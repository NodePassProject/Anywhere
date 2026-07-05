//
//  DirectUDPProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation
import Synchronization

/// Adapts a push-based `NWUDPTransport` to a pull-based `ProxyConnection`; the receive loop is armed lazily on the first `receiveRaw`.
nonisolated final class DirectUDPProxyConnection: ProxyConnection {

    private let transport: NWUDPTransport

    private struct ReceiveState {
        var recvBuffer: [Data] = []
        var pendingReceive: ((Data?, Error?) -> Void)?
        var receiveError: Error?
        var startedReceiving = false
        var closed = false
    }

    private let recvState = Mutex(ReceiveState())

    /// Bounds memory under a burst the consumer hasn't drained yet.
    private static let maxBufferedDatagrams = 1024

    init(transport: NWUDPTransport) {
        self.transport = transport
        super.init()
    }

    override var isConnected: Bool { transport.isReady }
    override var deliversDatagrams: Bool { true }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        transport.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        transport.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        enum Action {
            case deliver(Data)
            case fail(Error)
            case eof
            case parked(stale: ((Data?, Error?) -> Void)?)
        }
        let (shouldStartReceiving, action): (Bool, Action) = recvState.withLock { state in
            var shouldStartReceiving = false
            if !state.startedReceiving {
                state.startedReceiving = true
                shouldStartReceiving = true
            }

            if !state.recvBuffer.isEmpty {
                return (shouldStartReceiving, .deliver(state.recvBuffer.removeFirst()))
            }

            if let error = state.receiveError {
                state.receiveError = nil
                return (shouldStartReceiving, .fail(error))
            }

            if state.closed {
                return (shouldStartReceiving, .eof)
            }

            // Single-pending discipline: fail any stale overlapping receive instead of letting it hang.
            let stale = state.pendingReceive
            state.pendingReceive = completion
            return (shouldStartReceiving, .parked(stale: stale))
        }

        if shouldStartReceiving {
            transport.startReceiving(handler: { [weak self] data in
                self?.deliverIncoming(data)
            }, errorHandler: { [weak self] error in
                self?.deliverError(error)
            })
        }

        switch action {
        case .deliver(let next):
            completion(next, nil)
        case .fail(let error):
            completion(nil, error)
        case .eof:
            completion(nil, nil)
        case .parked(let stale):
            stale?(nil, ProxyError.protocolError("overlapping receiveRaw on Direct UDP"))
        }
    }

    override func cancel() {
        let parked = recvState.withLock { state -> ((Data?, Error?) -> Void)? in
            state.closed = true
            let parked = state.pendingReceive
            state.pendingReceive = nil
            state.recvBuffer.removeAll()
            return parked
        }

        transport.cancel()
        parked?(nil, nil)
    }

    // MARK: - Private

    private func deliverIncoming(_ data: Data) {
        let callback = recvState.withLock { state -> ((Data?, Error?) -> Void)? in
            if state.closed {
                return nil
            }
            if let callback = state.pendingReceive {
                state.pendingReceive = nil
                return callback
            }
            // Drop-oldest when the consumer isn't keeping up — UDP is lossy.
            if state.recvBuffer.count >= Self.maxBufferedDatagrams {
                state.recvBuffer.removeFirst()
            }
            state.recvBuffer.append(data)
            return nil
        }
        callback?(data, nil)
    }

    private func deliverError(_ error: Error) {
        let callback = recvState.withLock { state -> ((Data?, Error?) -> Void)? in
            if state.closed {
                return nil
            }
            let callback = state.pendingReceive
            state.pendingReceive = nil
            if callback == nil {
                state.receiveError = error
            }
            return callback
        }
        callback?(nil, error)
    }
}
