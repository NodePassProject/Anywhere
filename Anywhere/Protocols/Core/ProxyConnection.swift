//
//  ProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "Proxy")

// MARK: - ProxyConnectionProtocol

/// Defines the interface for all proxy connection types.
protocol ProxyConnectionProtocol: AnyObject {
    var isConnected: Bool { get }
    var responseHeaderReceived: Bool { get set }

    func send(data: Data, completion: @escaping (Error?) -> Void)
    func send(data: Data)
    func receive(completion: @escaping (Data?, Error?) -> Void)
    func startReceiving(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void)
    func cancel()
}

// MARK: - ProxyConnection

/// TLS version constants matching TLS protocol version numbers.
enum TLSVersion: UInt16 {
    case tls12 = 0x0303
    case tls13 = 0x0304
}

/// Abstract base class providing common proxy connection functionality.
///
/// Subclasses must override ``isConnected``, ``sendRaw(data:completion:)``,
/// ``sendRaw(data:)``, ``receiveRaw(completion:)``, and ``cancel()``.
class ProxyConnection: ProxyConnectionProtocol {
    var responseHeaderReceived = false
    let lock = UnfairLock()

    /// The negotiated TLS version of the outer transport, if applicable.
    /// Returns `nil` for non-TLS transports (raw TCP).
    /// Subclasses should override to report their actual TLS version.
    var outerTLSVersion: TLSVersion? { nil }

    // MARK: Traffic Statistics

    private var _bytesSent: Int64 = 0
    private var _bytesReceived: Int64 = 0
    private let statsLock = UnfairLock()

    var bytesSent: Int64 { statsLock.withLock { _bytesSent } }
    var bytesReceived: Int64 { statsLock.withLock { _bytesReceived } }

    var isConnected: Bool {
        fatalError("Subclass must override isConnected")
    }

    // MARK: Send

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        statsLock.withLock { _bytesSent &+= Int64(data.count) }
        sendRaw(data: data, completion: completion)
    }

    func send(data: Data) {
        statsLock.withLock { _bytesSent &+= Int64(data.count) }
        sendRaw(data: data)
    }

    /// Sends raw data over the underlying transport. Must be overridden by subclasses.
    func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        fatalError("Subclass must override sendRaw")
    }

    /// Sends raw data over the underlying transport without tracking completion.
    func sendRaw(data: Data) {
        fatalError("Subclass must override sendRaw")
    }

    // MARK: Receive

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        receiveRaw { [weak self] data, error in
            if let self, let data, !data.isEmpty {
                self.statsLock.withLock { self._bytesReceived &+= Int64(data.count) }
            }
            completion(data, error)
        }
    }

    /// Receives raw data from the underlying transport. Must be overridden by subclasses.
    func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        fatalError("Subclass must override receiveRaw")
    }

    /// Receives raw data without transport decryption (for Vision direct copy mode).
    ///
    /// The default implementation delegates to ``receiveRaw(completion:)``.
    /// Subclasses can override for special handling.
    func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        receiveRaw(completion: completion)
    }

    /// Sends raw data without transport encryption (for Vision direct copy mode).
    ///
    /// The default implementation delegates to ``sendRaw(data:completion:)``.
    /// Subclasses can override for special handling.
    func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        sendRaw(data: data, completion: completion)
    }

    func sendDirectRaw(data: Data) {
        sendRaw(data: data)
    }

    // MARK: Receive Loop

    /// Starts a continuous receive loop, delivering data through `handler`.
    ///
    /// - Parameters:
    ///   - handler: Called with each chunk of received data.
    ///   - errorHandler: Called when an error occurs or the connection closes (`nil` error = clean close).
    func startReceiving(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void) {
        receiveLoop(handler: handler, errorHandler: errorHandler)
    }

    private func receiveLoop(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void) {
        receive { [weak self] data, error in
            guard let self else { return }

            if let error {
                errorHandler(error)
                return
            }

            if let data, !data.isEmpty {
                // Start next receive before processing to enable pipelining
                self.receiveLoop(handler: handler, errorHandler: errorHandler)
                handler(data)
            } else {
                errorHandler(nil)
            }
        }
    }

    // MARK: Cancel

    func cancel() {
        fatalError("Subclass must override cancel")
    }

    // MARK: Response Header

    /// Processes the VLESS response header on first receive.
    ///
    /// Strips the 2-byte response header and returns the remaining payload.
    /// If the header consumes all available data, issues another receive.
    ///
    /// - Parameters:
    ///   - data: The raw received data that may contain the response header.
    ///   - completion: Called with the payload data (header stripped) or an error.
    func processResponseHeader(data: Data, completion: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        let needsHeaderProcessing = !responseHeaderReceived
        if needsHeaderProcessing {
            responseHeaderReceived = true
        }
        lock.unlock()

        if needsHeaderProcessing {
            do {
                let headerLength = try VLESSProtocol.decodeResponseHeader(data: data)
                if headerLength > 0 && data.count > headerLength {
                    let remaining = Data(data.suffix(from: headerLength))
                    completion(remaining, nil)
                    return
                } else if headerLength > 0 {
                    receive(completion: completion)
                    return
                }
            } catch {
                completion(nil, error)
                return
            }
        }

        completion(data, nil)
    }
}

// MARK: - UDPProxyConnection

/// Generic UDP proxy connection wrapper that adds length-prefixed framing to any TCP proxy connection.
///
/// Replaces transport-specific UDP subclasses by composing UDP framing with any ``ProxyConnection``.
class UDPProxyConnection: ProxyConnection, UDPFramingCapable {
    private let inner: ProxyConnection
    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

    init(inner: ProxyConnection) {
        self.inner = inner
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendRaw(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        inner.sendRaw(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveRaw(completion: completion)
    }

    override func send(data: Data, completion: @escaping (Error?) -> Void) {
        super.send(data: frameUDPPacket(data), completion: completion)
    }

    override func send(data: Data) {
        super.send(data: frameUDPPacket(data))
    }

    override func receive(completion: @escaping (Data?, Error?) -> Void) {
        udpLock.lock()
        if let packet = extractUDPPacket() {
            udpLock.unlock()
            completion(packet, nil)
            return
        }
        udpLock.unlock()
        receiveMore(completion: completion)
    }

    private func receiveMore(completion: @escaping (Data?, Error?) -> Void) {
        inner.receive { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data else {
                completion(nil, nil)
                return
            }

            self.udpLock.lock()
            self.udpBuffer.append(data)

            if let packet = self.extractUDPPacket() {
                self.udpLock.unlock()
                completion(packet, nil)
            } else {
                self.udpLock.unlock()
                self.receiveMore(completion: completion)
            }
        }
    }

    override func cancel() {
        udpLock.lock()
        clearUDPBuffer()
        udpLock.unlock()
        inner.cancel()
    }

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveDirectRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendDirectRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        inner.sendDirectRaw(data: data)
    }
}
