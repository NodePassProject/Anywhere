//
//  RawTransport.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/17/26.
//

import Foundation

// MARK: - RawTransport

/// Protocol abstracting the raw I/O layer used by TLS/Reality handshakes and
/// proxy chaining.
///
/// Both ``RawTCPSocket`` (real TCP) and ``TunneledTransport`` (tunneled TCP via a
/// proxy chain) conform.
protocol RawTransport: AnyObject {
    /// Whether the transport is connected and ready for I/O.
    var isTransportReady: Bool { get }

    /// Sends data through the transport.
    func send(data: Data, completion: @escaping (Error?) -> Void)

    /// Sends data without tracking completion.
    func send(data: Data)

    /// Receives up to `maximumLength` bytes from the transport.
    func receive(completion: @escaping (Data?, Bool, Error?) -> Void)

    /// Closes the transport and cancels all pending operations.
    func forceCancel()
}

// MARK: - SocketError

/// Errors that can occur during socket/transport operations.
enum SocketError: Error, LocalizedError {
    case resolutionFailed(String)
    case socketCreationFailed(String)
    case connectionFailed(String)
    case notConnected
    case sendFailed(String)
    case receiveFailed(String)

    var errorDescription: String? {
        switch self {
        case .resolutionFailed(let msg): return "DNS resolution failed: \(msg)"
        case .socketCreationFailed(let msg): return "Socket creation failed: \(msg)"
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .notConnected: return "Not connected"
        case .sendFailed(let msg): return "Send failed: \(msg)"
        case .receiveFailed(let msg): return "Receive failed: \(msg)"
        }
    }
}
