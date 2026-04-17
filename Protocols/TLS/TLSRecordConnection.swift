//
//  TLSRecordConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/17/26.
//

import Foundation

private let logger = AnywhereLogger(category: "TLS")

// MARK: - TLSRecord

/// Common surface implemented by both `TLSRecordConnection` (wolfSSL-backed,
/// used everywhere except Reality) and `RealityRecordConnection` (Swift
/// manual-keys path, used by Reality). Callers that can receive either
/// implementation — XHTTP, WebSocket, HTTPUpgrade, Vision-aware
/// sub-transports — accept `any TLSRecord`.
protocol TLSRecord: AnyObject {
    var connection: (any RawTransport)? { get set }
    var tlsVersion: UInt16 { get }

    func prependToReceiveBuffer(_ data: Data)

    func send(data: Data, completion: @escaping (Error?) -> Void)
    func send(data: Data)
    func receive(completion: @escaping (Data?, Error?) -> Void)

    func sendRaw(data: Data, completion: @escaping (Error?) -> Void)
    func sendRaw(data: Data)
    func receiveRaw(completion: @escaping (Data?, Error?) -> Void)

    func cancel()
}

// MARK: - TLSRecordConnection

class TLSRecordConnection: TLSRecord {

    // MARK: Properties

    /// Underlying TCP or tunneled transport. Exposed for callers that reach
    /// around TLS to the socket (e.g. TLSProxyConnection's raw mode forward).
    var connection: (any RawTransport)? {
        get { session.connection }
        set { session.connection = newValue }
    }

    /// Always `0x0304` in the wolfSSL-backed path. Retained as a property
    /// for backwards compatibility with Reality / Vision callers that
    /// branch on TLS version.
    let tlsVersion: UInt16 = 0x0304

    // MARK: Internals

    private let session: TLSSession

    // No explicit locks — `session.queue` is a serial DispatchQueue, so
    // every wolfSSL call + buffer mutation goes through it in strict
    // order. Using `os_unfair_lock` here would crash because the lock
    // would be acquired on the caller's thread and released on the
    // completion thread, which violates os_unfair_lock's same-thread rule.

    // MARK: Lifecycle

    init(session: TLSSession) {
        self.session = session
    }

    deinit {
        // Session deinit runs wolfSSL_free + wolfSSL_CTX_free.
    }

    // MARK: - Push-back buffer

    func prependToReceiveBuffer(_ data: Data) {
        session.queue.sync {
            session.prependedRaw.append(data)
        }
    }

    // MARK: - Encrypted send

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        writeAll(data: data, completion: completion)
    }

    func send(data: Data) {
        writeAll(data: data) { _ in }
    }

    private func writeAll(data: Data, completion: @escaping (Error?) -> Void) {
        let session = self.session
        session.queue.async { [weak self] in
            guard let self else { return }
            guard !session.cancelled else {
                completion(TLSError.connectionFailed("Connection cancelled"))
                return
            }

            let written: Int32 = data.withUnsafeBytes { raw in
                let p = raw.bindMemory(to: UInt8.self).baseAddress!
                return wolfSSL_write(session.ssl, p, Int32(data.count))
            }

            if written == Int32(data.count) {
                // Full plaintext accepted; flush whatever wolfSSL staged.
                TLSHandler.flushTx(session: session, completion: completion)
                return
            }

            if written > 0 {
                // Partial write — continue with the remainder after the
                // current staged bytes are on the wire.
                let remaining = data.subdata(in: Int(written)..<data.count)
                TLSHandler.flushTx(session: session) { [weak self] err in
                    if let err { completion(err); return }
                    self?.writeAll(data: remaining, completion: completion)
                }
                return
            }

            let err = wolfSSL_get_error(session.ssl, written)
            if err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ {
                // Drain tx, pull more rx if needed, then retry.
                TLSHandler.flushTx(session: session) { [weak self] flushErr in
                    guard let self else { return }
                    if let flushErr { completion(flushErr); return }
                    if err == WOLFSSL_ERROR_WANT_READ {
                        TLSHandler.pullFromNetwork(session: session) { [weak self] pullErr in
                            guard let self else { return }
                            if let pullErr { completion(pullErr); return }
                            self.writeAll(data: data, completion: completion)
                        }
                    } else {
                        self.writeAll(data: data, completion: completion)
                    }
                }
                return
            }

            completion(TLSError.handshakeFailed("wolfSSL_write rv=\(written) err=\(err)"))
        }
    }

    // MARK: - Encrypted receive

    /// Reads decrypted application data. Returns whatever wolfSSL has in
    /// its internal record buffer plus one underlying network read if the
    /// buffer is empty.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        readSome(completion: completion)
    }

    private func readSome(completion: @escaping (Data?, Error?) -> Void) {
        let session = self.session
        session.queue.async { [weak self] in
            guard let self else { return }
            guard !session.cancelled else {
                completion(nil, TLSError.connectionFailed("Connection cancelled"))
                return
            }

            // Drain any plaintext wolfSSL has already decrypted into
            // appBuffer (e.g. from a previous partial read).
            if !session.appBuffer.isEmpty {
                let out = session.appBuffer
                session.appBuffer.removeAll(keepingCapacity: true)
                completion(out, nil)
                return
            }

            var scratch = [UInt8](repeating: 0, count: 16384)
            let n: Int32 = scratch.withUnsafeMutableBufferPointer { buf in
                wolfSSL_read(session.ssl, buf.baseAddress, Int32(buf.count))
            }

            if n > 0 {
                completion(Data(scratch.prefix(Int(n))), nil)
                return
            }

            if n == 0 {
                completion(nil, nil)  // clean shutdown
                return
            }

            let err = wolfSSL_get_error(session.ssl, n)
            if err == WOLFSSL_ERROR_WANT_READ {
                TLSHandler.flushTx(session: session) { [weak self] flushErr in
                    guard let self else { return }
                    if let flushErr { completion(nil, flushErr); return }
                    TLSHandler.pullFromNetwork(session: session) { [weak self] pullErr in
                        guard let self else { return }
                        if let pullErr { completion(nil, pullErr); return }
                        self.readSome(completion: completion)
                    }
                }
                return
            }

            if err == WOLFSSL_ERROR_WANT_WRITE {
                TLSHandler.flushTx(session: session) { [weak self] flushErr in
                    guard let self else { return }
                    if let flushErr { completion(nil, flushErr); return }
                    self.readSome(completion: completion)
                }
                return
            }

            completion(nil, TLSError.handshakeFailed("wolfSSL_read rv=\(n) err=\(err)"))
        }
    }

    // MARK: - Raw (unencrypted) send / receive

    /// Sends bytes straight to the underlying transport, bypassing wolfSSL.
    /// Used by Vision direct-copy after the peer-signalled transition.
    func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        guard let transport = session.connection else {
            completion(TLSError.connectionFailed("Connection cancelled"))
            return
        }
        transport.send(data: data, completion: completion)
    }

    func sendRaw(data: Data) {
        session.connection?.send(data: data)
    }

    /// Reads bytes straight from the underlying transport, bypassing wolfSSL.
    /// Drains `prependedRaw` first so push-back data arrives ahead of live
    /// socket bytes. Also drains any undelivered plaintext from
    /// `appBuffer` so Vision's transition doesn't lose decrypted bytes
    /// that arrived before the direct-copy switch.
    func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        let session = self.session
        session.queue.async { [weak self] in
            if !session.prependedRaw.isEmpty {
                let out = session.prependedRaw
                session.prependedRaw.removeAll(keepingCapacity: true)
                completion(out, nil)
                return
            }
            if !session.appBuffer.isEmpty {
                let out = session.appBuffer
                session.appBuffer.removeAll(keepingCapacity: true)
                completion(out, nil)
                return
            }
            guard let transport = session.connection else {
                completion(nil, TLSError.connectionFailed("Connection cancelled"))
                return
            }
            transport.receive(maximumLength: 65536) { [weak self] data, isComplete, error in
                if let error { completion(nil, error); return }
                guard let data, !data.isEmpty else {
                    if isComplete { completion(nil, nil) }
                    else { self?.receiveRaw(completion: completion) }
                    return
                }
                completion(data, nil)
            }
        }
    }

    // MARK: - Cancel

    func cancel() {
        session.queue.async { [session] in
            if !session.cancelled {
                session.cancelled = true
                // Best-effort close_notify; ignore errors.
                _ = wolfSSL_shutdown(session.ssl)
                // Drain whatever wolfSSL staged during shutdown.
                if !session.txBuffer.isEmpty, let connection = session.connection {
                    let data = session.txBuffer
                    session.txBuffer.removeAll()
                    connection.send(data: data)
                }
            }
            session.connection?.forceCancel()
            session.connection = nil
            session.rxBuffer.removeAll(keepingCapacity: false)
            session.txBuffer.removeAll(keepingCapacity: false)
            session.appBuffer.removeAll(keepingCapacity: false)
            session.prependedRaw.removeAll(keepingCapacity: false)
        }
    }
}
