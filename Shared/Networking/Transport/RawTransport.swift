//
//  RawTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 6/30/26.
//

import Foundation

// MARK: - RawTransport

/// A bidirectional byte-stream transport.
protocol RawTransport: AnyObject {
    var isTransportReady: Bool { get }

    func send(data: Data, completion: @escaping (Error?) -> Void)

    func send(data: Data)

    /// Finishes the send direction (TCP FIN / protocol end-of-stream), ordered
    /// after every send already issued; the receive side stays open. Called at
    /// most once, and no sends may be issued after it.
    nonisolated func closeWrite(completion: @escaping (Error?) -> Void)

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void)

    func forceCancel()
}

extension RawTransport {
    /// Transports with no way to express end-of-stream short of a full close
    /// complete immediately; the peer simply never sees the half-close.
    nonisolated func closeWrite(completion: @escaping (Error?) -> Void) { completion(nil) }
}

// MARK: - TransportError

enum TransportError: Error, LocalizedError {
    case resolutionFailed(String)
    case connectionFailed(String)
    case notConnected
    case receiveFailed(String)
    /// POSIX failure preserving the raw `errno` so callers can classify by code.
    case posixError(Operation, errno: Int32)

    enum Operation {
        case connect, send, receive

        var failurePrefix: String {
            switch self {
            case .connect: return "Connection failed"
            case .send:    return "Send failed"
            case .receive: return "Receive failed"
            }
        }
    }

    var errorDescription: String? {
        switch self {
        case .resolutionFailed(let message): return "DNS resolution failed: \(message)"
        case .connectionFailed(let message): return "Connection failed: \(message)"
        case .notConnected: return "Not connected"
        case .receiveFailed(let message): return "Receive failed: \(message)"
        case .posixError(let op, let errno):
            return "\(op.failurePrefix): \(String(cString: strerror(errno)))"
        }
    }

    var posixErrno: Int32? {
        if case .posixError(_, let errno) = self { return errno }
        return nil
    }
}
