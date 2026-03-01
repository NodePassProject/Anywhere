//
//  VLESSConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "VLESS")

// MARK: - VLESSConnectionProtocol

/// Defines the interface for all VLESS connection types.
protocol VLESSConnectionProtocol: AnyObject {
    var isConnected: Bool { get }
    var responseHeaderReceived: Bool { get set }

    func send(data: Data, completion: @escaping (Error?) -> Void)
    func send(data: Data)
    func receive(completion: @escaping (Data?, Error?) -> Void)
    func startReceiving(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void)
    func cancel()
}

// MARK: - VLESSConnection

/// TLS version constants matching TLS protocol version numbers.
enum TLSVersion: UInt16 {
    case tls12 = 0x0303
    case tls13 = 0x0304
}

/// Abstract base class providing common VLESS connection functionality.
///
/// Subclasses must override ``isConnected``, ``sendRaw(data:completion:)``,
/// ``sendRaw(data:)``, ``receiveRaw(completion:)``, and ``cancel()``.
class VLESSConnection: VLESSConnectionProtocol {
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
                    completion(Data(data.suffix(from: headerLength)), nil)
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

// MARK: - VLESSDirectConnection

/// VLESS connection over a direct ``BSDSocket`` transport.
class VLESSDirectConnection: VLESSConnection {
    let connection: BSDSocket

    /// Creates a new direct VLESS connection.
    ///
    /// - Parameter connection: The underlying BSD socket.
    init(connection: BSDSocket) {
        self.connection = connection
    }

    override var isConnected: Bool {
        if case .ready = connection.state { return true }
        return false
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        connection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        connection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        connection.receive(maximumLength: 65536) { [weak self] data, isComplete, error in
            guard let self else {
                completion(nil, nil)
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                if isComplete {
                    completion(nil, nil)
                } else {
                    self.receive(completion: completion)
                }
                return
            }

            self.processResponseHeader(data: data, completion: completion)
        }
    }

    override func cancel() {
        connection.forceCancel()
    }
}

// MARK: - VLESSDirectUDPConnection

/// VLESS UDP connection over a direct ``BSDSocket`` with length-prefixed packets.
class VLESSDirectUDPConnection: VLESSDirectConnection, UDPFramingCapable {
    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

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
        super.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
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
        super.cancel()
    }
}

// MARK: - VLESSHTTPUpgradeConnection

/// VLESS connection over an ``HTTPUpgradeConnection`` transport (raw TCP after HTTP upgrade).
class VLESSHTTPUpgradeConnection: VLESSConnection {
    private let huConnection: HTTPUpgradeConnection

    init(huConnection: HTTPUpgradeConnection) {
        self.huConnection = huConnection
    }

    override var isConnected: Bool {
        huConnection.isConnected
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        huConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        huConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        huConnection.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }

            self.processResponseHeader(data: data, completion: completion)
        }
    }

    override func cancel() {
        huConnection.cancel()
    }
}

// MARK: - VLESSHTTPUpgradeUDPConnection

/// VLESS UDP connection over an ``HTTPUpgradeConnection`` with length-prefixed packets.
class VLESSHTTPUpgradeUDPConnection: VLESSHTTPUpgradeConnection, UDPFramingCapable {
    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

    override func send(data: Data, completion: @escaping (Error?) -> Void) {
        sendRaw(data: frameUDPPacket(data), completion: completion)
    }

    override func send(data: Data) {
        sendRaw(data: frameUDPPacket(data))
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
        super.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
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
        super.cancel()
    }
}

// MARK: - VLESSXHTTPConnection

/// VLESS connection over an ``XHTTPConnection`` transport.
class VLESSXHTTPConnection: VLESSConnection {
    private let xhttpConnection: XHTTPConnection

    init(xhttpConnection: XHTTPConnection) {
        self.xhttpConnection = xhttpConnection
    }

    override var isConnected: Bool {
        xhttpConnection.isConnected
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        xhttpConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        xhttpConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        xhttpConnection.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }

            self.processResponseHeader(data: data, completion: completion)
        }
    }

    override func cancel() {
        xhttpConnection.cancel()
    }
}

// MARK: - VLESSXHTTPUDPConnection

/// VLESS UDP connection over an ``XHTTPConnection`` with length-prefixed packets.
class VLESSXHTTPUDPConnection: VLESSXHTTPConnection, UDPFramingCapable {
    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

    override func send(data: Data, completion: @escaping (Error?) -> Void) {
        sendRaw(data: frameUDPPacket(data), completion: completion)
    }

    override func send(data: Data) {
        sendRaw(data: frameUDPPacket(data))
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
        super.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
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
        super.cancel()
    }
}

// MARK: - VLESSTLSConnection

/// VLESS connection over a standard TLS ``TLSRecordConnection`` transport.
class VLESSTLSConnection: VLESSConnection {
    private let tlsConnection: TLSRecordConnection

    /// Creates a new TLS-backed VLESS connection.
    ///
    /// - Parameter tlsConnection: The underlying TLS record connection.
    init(tlsConnection: TLSRecordConnection) {
        self.tlsConnection = tlsConnection
    }

    /// Standard TLS always negotiates TLS 1.3 (we only support 1.3).
    override var outerTLSVersion: TLSVersion? { .tls13 }

    override var isConnected: Bool {
        if case .ready = tlsConnection.connection?.state { return true }
        return false
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        tlsConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        tlsConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        tlsConnection.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
                if case RealityError.decryptionFailed = error {
                    completion(data, error)
                    return
                }
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }

            self.processResponseHeader(data: data, completion: completion)
        }
    }

    override func cancel() {
        tlsConnection.cancel()
    }

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        tlsConnection.receiveRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        tlsConnection.sendRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        tlsConnection.sendRaw(data: data)
    }
}

// MARK: - VLESSTLSUDPConnection

/// VLESS UDP connection over a standard TLS transport with length-prefixed packets.
class VLESSTLSUDPConnection: VLESSTLSConnection, UDPFramingCapable {
    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

    override func send(data: Data, completion: @escaping (Error?) -> Void) {
        sendRaw(data: frameUDPPacket(data), completion: completion)
    }

    override func send(data: Data) {
        sendRaw(data: frameUDPPacket(data))
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
        super.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
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
        super.cancel()
    }
}

// MARK: - VLESSWebSocketConnection

/// VLESS connection over a ``WebSocketConnection`` transport.
class VLESSWebSocketConnection: VLESSConnection {
    private let wsConnection: WebSocketConnection

    init(wsConnection: WebSocketConnection) {
        self.wsConnection = wsConnection
    }

    override var isConnected: Bool {
        wsConnection.isConnected
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        wsConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        wsConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        wsConnection.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }

            self.processResponseHeader(data: data, completion: completion)
        }
    }

    override func cancel() {
        wsConnection.cancel()
    }
}

// MARK: - VLESSWebSocketUDPConnection

/// VLESS UDP connection over a ``WebSocketConnection`` with length-prefixed packets.
class VLESSWebSocketUDPConnection: VLESSWebSocketConnection, UDPFramingCapable {
    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

    override func send(data: Data, completion: @escaping (Error?) -> Void) {
        sendRaw(data: frameUDPPacket(data), completion: completion)
    }

    override func send(data: Data) {
        sendRaw(data: frameUDPPacket(data))
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
        super.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
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
        super.cancel()
    }
}

// MARK: - VLESSRealityConnection

/// VLESS connection over a ``TLSRecordConnection`` transport.
class VLESSRealityConnection: VLESSConnection {
    private let realityConnection: TLSRecordConnection

    /// Creates a new Reality-backed VLESS connection.
    ///
    /// - Parameter realityConnection: The underlying TLS record connection.
    init(realityConnection: TLSRecordConnection) {
        self.realityConnection = realityConnection
    }

    /// Reality always negotiates TLS 1.3.
    override var outerTLSVersion: TLSVersion? { .tls13 }

    override var isConnected: Bool {
        if case .ready = realityConnection.connection?.state { return true }
        return false
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        realityConnection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        realityConnection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        realityConnection.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
                return
            }

            if let error {
                // Pass through decryption failures with raw data for Vision direct copy mode
                if case RealityError.decryptionFailed = error {
                    completion(data, error)
                    return
                }
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil)
                return
            }

            self.processResponseHeader(data: data, completion: completion)
        }
    }

    override func cancel() {
        realityConnection.cancel()
    }

    override func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        realityConnection.receiveRaw(completion: completion)
    }

    override func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        realityConnection.sendRaw(data: data, completion: completion)
    }

    override func sendDirectRaw(data: Data) {
        realityConnection.sendRaw(data: data)
    }
}

// MARK: - VLESSRealityUDPConnection

/// VLESS UDP connection over a ``TLSRecordConnection`` with length-prefixed packets.
class VLESSRealityUDPConnection: VLESSRealityConnection, UDPFramingCapable {
    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

    override func send(data: Data, completion: @escaping (Error?) -> Void) {
        sendRaw(data: frameUDPPacket(data), completion: completion)
    }

    override func send(data: Data) {
        sendRaw(data: frameUDPPacket(data))
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
        super.receive { [weak self] data, error in
            guard let self else {
                completion(nil, VLESSError.connectionFailed("Connection deallocated"))
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
        super.cancel()
    }
}
