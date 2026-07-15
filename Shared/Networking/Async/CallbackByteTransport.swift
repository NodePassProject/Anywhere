//
//  CallbackByteTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation

// MARK: - CallbackByteTransport

/// Presents an ``AsyncByteTransport`` through the completion-handler
/// ``RawTransport`` surface, for callback-based consumers.
///
/// A callback consumer can fire-and-forget `send(A); send(B)`, which would race if
/// each were bridged to its own `Task`, so sends are drained in submission order by an
/// ``AsyncSendPump`` (`finishSend` ordered after them). Receives are single-flight per
/// the `RawTransport` contract, so each bridges to one `await transport.receive()`.
nonisolated final class CallbackByteTransport: RawTransport, @unchecked Sendable {

    private let transport: any AsyncByteTransport
    private let sendPump: AsyncSendPump

    init(_ transport: any AsyncByteTransport) {
        self.transport = transport
        // Capture `transport` (not `self`) so the pump doesn't retain the adapter.
        self.sendPump = AsyncSendPump(
            send: { try await transport.send($0) },
            finish: { try await transport.finishSend() }
        )
    }

    deinit {
        sendPump.finish()
    }

    // MARK: - RawTransport

    var isTransportReady: Bool { transport.isReady }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        sendPump.enqueueSend(data, completion: completion)
    }

    func send(data: Data) {
        sendPump.enqueueSend(data, completion: nil)
    }

    func closeWrite(completion: @escaping (Error?) -> Void) {
        sendPump.enqueueFinish(completion: completion)
    }

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
        let transport = self.transport
        Task {
            do {
                switch try await transport.receive() {
                case .bytes(let data): completion(data, false, nil)
                case .end: completion(nil, true, nil)
                }
            } catch {
                completion(nil, true, error)
            }
        }
    }

    func forceCancel() {
        sendPump.finish()
        transport.cancel()
    }
}
