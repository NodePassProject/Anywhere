//
//  CallbackDatagramTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 7/14/26.
//

import Foundation
import Synchronization

// MARK: - CallbackDatagramTransport

/// Presents an ``AsyncDatagramTransport`` through the push-based
/// ``RawDatagramTransport`` surface, for callback-based consumers. A single receive
/// loop turns the pull `receive()` into handler callbacks.
///
/// There is no send pump: UDP datagrams are independent, so per-send `Task`s need
/// no ordering.
nonisolated final class CallbackDatagramTransport: RawDatagramTransport, @unchecked Sendable {

    private let transport: any AsyncDatagramTransport
    private let receiveTask = Mutex<Task<Void, Never>?>(nil)

    init(_ transport: any AsyncDatagramTransport) {
        self.transport = transport
    }

    deinit {
        receiveTask.withLock { $0?.cancel() }
    }

    // MARK: - RawDatagramTransport

    var isTransportReady: Bool { transport.isReady }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        let transport = self.transport
        Task {
            do {
                try await transport.send(data)
                completion(nil)
            } catch {
                completion(error)
            }
        }
    }

    func send(data: Data) {
        let transport = self.transport
        Task { try? await transport.send(data) }
    }

    func startReceiving(queue: DispatchQueue?, handler: @escaping (Data) -> Void, errorHandler: ((Error) -> Void)?) {
        let transport = self.transport
        let task = Task {
            do {
                while true {
                    let datagram = try await transport.receive()
                    if Task.isCancelled { return }
                    if let queue {
                        queue.async { handler(datagram) }
                    } else {
                        handler(datagram)
                    }
                }
            } catch {
                if Task.isCancelled { return }
                if let queue {
                    queue.async { errorHandler?(error) }
                } else {
                    errorHandler?(error)
                }
            }
        }
        receiveTask.withLock { existing in
            existing?.cancel()
            existing = task
        }
    }

    func cancel() {
        receiveTask.withLock { $0?.cancel() }
        transport.cancel()
    }
}
