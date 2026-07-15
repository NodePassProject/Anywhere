//
//  AsyncProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

// MARK: - AsyncProxyConnection

/// A ``ProxyConnection`` whose **async** raw methods are the primary contract.
///
/// The base ``ProxyConnection`` is callback-primary: its async surface bridges *down*
/// to `sendRaw(data:completion:)` / `receiveRaw(completion:)`, so a subclass that
/// implements only the async methods (like the async-native transports) leaves the
/// callback methods hitting the base `fatalError` — and crashes the moment a
/// callback consumer touches it.
///
/// This class **inverts** that: subclasses override the async raw methods
/// (``sendRaw(_:)``, ``receiveRaw()``, and optionally ``closeWrite()``), and the
/// callback surface is provided here by bridging *up* to them — ordered sends through
/// an ``AsyncSendPump``, receives through a per-call `Task` (receives are single-flight
/// by contract). A subclass therefore works for both async and callback consumers with
/// zero bridge code of its own.
///
/// Recursion safety: every callback override forwards to a *concrete* async method
/// (a subclass override, or the no-op ``closeWrite()`` default here) — never back to a
/// callback method — so no method can call itself in a cycle. The async raw methods are
/// abstract here (`fatalError`) to make "you must override the async methods" an
/// explicit contract, mirroring the base class's callback-side `fatalError`.
nonisolated class AsyncProxyConnection: ProxyConnection, @unchecked Sendable {

    /// Serializes callback-issued sends; nil until phase-2 init has `self`.
    private var sendPump: AsyncSendPump!

    override init() {
        super.init()
        // Weak self: the pump task must not retain the connection, else `deinit`
        // (which stops the pump) could never run. On dealloc mid-send the job is
        // dropped — abortive teardown, consistent with `cancel()`.
        sendPump = AsyncSendPump(
            send: { [weak self] data in
                guard let self else { throw CancellationError() }
                try await self.sendRaw(data)
            },
            finish: { [weak self] in
                guard let self else { throw CancellationError() }
                try await self.closeWrite()
            }
        )
    }

    deinit {
        sendPump?.finish()
    }

    // MARK: Async contract (subclasses override)

    override func sendRaw(_ data: Data) async throws {
        fatalError("AsyncProxyConnection subclass must override sendRaw(_:)")
    }

    override func receiveRaw() async throws -> Data? {
        fatalError("AsyncProxyConnection subclass must override receiveRaw()")
    }

    /// Half-closes the send direction. Concrete no-op default so the callback bridge
    /// never recurses; async-native transports override to signal end-of-stream.
    override func closeWrite() async throws {
        // Protocols that can't express half-close short of a full close do nothing.
    }

    // MARK: Callback surface (bridges up to the async contract)

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        sendPump.enqueueSend(data, completion: completion)
    }

    override func sendRaw(data: Data) {
        sendPump.enqueueSend(data, completion: nil)
    }

    override func closeWrite(completion: @escaping (Error?) -> Void) {
        sendPump.enqueueFinish(completion: completion)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        Task { [weak self] in
            guard let self else {
                completion(nil, nil)  // EOF on dealloc, matching the receive-loop contract
                return
            }
            do {
                completion(try await self.receiveRaw(), nil)
            } catch {
                completion(nil, error)
            }
        }
    }

    // MARK: Cancel

    override func cancel() {
        sendPump.finish()
        performCancel()
    }

    /// Abortive teardown of the underlying transport. Subclasses override; the pump is
    /// already stopped by ``cancel()`` before this runs.
    func performCancel() {}
}
