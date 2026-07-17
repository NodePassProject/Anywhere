//
//  LWIPConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "LWIPConcurrencyBridge")

nonisolated protocol LWIPBridgeHost: AnyObject {

    /// lwIP has an IP packet to write back to the TUN. `packet` aliases lwIP's own memory
    /// with a `.none` deallocator; it stays valid until `release(releaseCtx)` runs, which
    /// must happen on the bridge queue (`pbuf_free`/`mem_free` are unlocked under NO_SYS=1).
    func lwipDidOutput(_ packet: Data, isIPv6: Bool,
                       releaseCtx: UnsafeMutableRawPointer?,
                       release: @escaping @convention(c) (UnsafeMutableRawPointer?) -> Void)

    /// Verdict for an incoming SYN before lwIP allocates a pcb — one of the
    /// `LWIP_BRIDGE_SYN_*` values. `dstIP` is raw address bytes valid for this call only.
    func lwipSynVerdict(dstIP: UnsafeRawPointer, dstPort: UInt16, isIPv6: Bool) -> Int32

    /// The connection to adopt for a just-accepted pcb, or `nil` to abort it (RST).
    /// `dstIP` is raw address bytes valid for this call only; the returned connection is
    /// handed a retained reference lwIP stores as the pcb's `tcp_arg`.
    func lwipAccept(pcb: UnsafeMutableRawPointer, dstIP: UnsafeRawPointer,
                    dstPort: UInt16, isIPv6: Bool) -> TCPConnection?
}

nonisolated final class LWIPConcurrencyBridge: @unchecked Sendable {

    /// The serial executor every lwIP operation and callback runs on. Exposed so
    /// ``TunnelStack`` can vend `lwipQueue` from it and drive C timers on the same domain.
    let executor: BridgeExecutor

    init(label: String) {
        self.executor = BridgeExecutor(label: label)
    }

    /// The lwIP serial queue. Everything touching lwIP hops here; it is the bridge's
    /// executor's queue, so work scheduled on it shares the actor isolation domain.
    var queue: DispatchQueue { executor.queue }

    /// Fire-and-forget hop onto the lwIP queue with a `Sendable`-checked closure — the sanctioned
    /// way for the bridge's clients to enter its isolation domain, so callers never reach for
    /// `queue.async` (and the raw queue's unguarded `.sync`/`.suspend`) directly.
    func enqueue(_ work: @escaping @convention(block) @Sendable () -> Void) {
        queue.async(execute: work)
    }

    // MARK: - Async hop

    /// Runs `body` on the lwIP queue and resumes the caller with its result — the async
    /// seam between the relay drivers (pure async/await) and lwIP's queue-confined state.
    ///
    /// Not `@Sendable`/`throws`: `body` reaches a connection's lwipQueue-confined state
    /// exactly as the former `TCPConnection.onLwip` did, and lwIP calls don't throw.
    func run<T>(_ body: @escaping () -> T) async -> T {
        await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { continuation.resume(returning: body()) }
        }
    }

    /// Parked hop: runs `body` on the lwIP queue, handing it the `continuation` to resolve later —
    /// `body` resumes it inline or stashes it (e.g. across a script transform hop) and resumes it
    /// when that completes. Resumed exactly once. The continuation scaffolding lives here so the
    /// lwIP-queue-confined callers (MITM legs/streams) never open one themselves.
    func runParked<T>(_ body: @escaping (CheckedContinuation<T, Never>) -> Void) async -> T {
        await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { body(continuation) }
        }
    }

    /// Throwing counterpart of ``runParked``: `body` may resume the continuation by throwing.
    func runParkedThrowing<T>(_ body: @escaping (CheckedContinuation<T, Error>) -> Void) async throws -> T {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
            queue.async { body(continuation) }
        }
    }

    /// Runs `body` synchronously on the lwIP queue from an off-queue caller (e.g. the provider's
    /// `stop()` thread), completing before returning. Delegates to the executor's guarded
    /// primitive, which precondition-checks it isn't already on the queue (that would deadlock).
    func runSyncOffQueue<T>(_ body: () -> T) -> T {
        executor.runSyncOffQueue(body)
    }

    /// A repeating tick on the lwIP queue for driving `lwip_bridge_check_timeouts`; the raw
    /// `DispatchSourceTimer` lives in the bridge layer. `handler` and the returned timer's
    /// suspend/resume/cancel are all queue-confined.
    func makeTick(intervalMs: Int, leewayMs: Int,
                  handler: @escaping @Sendable () -> Void) -> BridgeTimer {
        executor.makeRepeatingTimer(intervalMs: intervalMs, leewayMs: leewayMs, handler: handler)
    }

    // MARK: - Lifecycle (start / end point)

    /// Publishes `host` as the bridge's host context and installs the C callbacks that route
    /// lwIP events to it. Must run on ``queue`` before ``initEngine()``. The host is stored
    /// unretained (it owns this bridge and outlives it), matching lwIP's global-context model.
    func installCallbacks(host: any LWIPBridgeHost) {
        lwip_bridge_set_host_ctx(BridgeContext.passUnretained(host as AnyObject))

        // Output: lwIP → tunnel packet flow. `Data(bytesNoCopy:)` with a `.none`
        // deallocator lets the host's writePackets read lwIP's memory directly; the host
        // owns the release and must run it on ``queue``.
        lwip_bridge_set_output_fn { data, len, isIPv6, releaseCtx, release in
            guard let host = LWIPConcurrencyBridge.host(), let data, let release else { return }
            let packet = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
                              count: Int(len), deallocator: .none)
            host.lwipDidOutput(packet, isIPv6: isIPv6 != 0, releaseCtx: releaseCtx, release: release)
        }

        // TCP SYN filter: decide drop/reset/pass before lwIP allocates a pcb.
        lwip_bridge_set_tcp_syn_filter_fn { _, _, dstIP, dstPort, isIPv6 in
            guard let host = LWIPConcurrencyBridge.host(), let dstIP else {
                return Int32(LWIP_BRIDGE_SYN_PASS)
            }
            return host.lwipSynVerdict(dstIP: dstIP, dstPort: dstPort, isIPv6: isIPv6 != 0)
        }

        // TCP accept: build a connection per incoming pcb (or abort). A non-nil result is
        // handed to lwIP as a retained `tcp_arg`; the terminal `tcp_err` or Swift teardown
        // balances it (see ``TCPConnection`` / ``discard(_:)``).
        // The recovered connection is an `actor` whose executor is *this* bridge's queue, so
        // these callbacks — which lwIP fires synchronously on that queue — enter its isolated
        // state through `assumeIsolated` (validated against the queue, no hop).
        lwip_bridge_set_tcp_accept_fn { _, _, dstIP, dstPort, isIPv6, pcb in
            guard let host = LWIPConcurrencyBridge.host(), let pcb, let dstIP else { return nil }
            guard let connection = host.lwipAccept(pcb: pcb, dstIP: dstIP,
                                                   dstPort: dstPort, isIPv6: isIPv6 != 0) else {
                return nil
            }
            connection.assumeIsolated { $0.start() }
            return BridgeContext.passRetained(connection)
        }

        // Recv: data (or a remote FIN when empty) on an established connection.
        lwip_bridge_set_tcp_recv_fn { connection, data, len in
            guard let connection else {
                logger.debug("[LWIPBridge] tcp_recv: connection is nil")
                return
            }
            BridgeContext.unretained(connection, as: TCPConnection.self).assumeIsolated { conn in
                if let data, len > 0 {
                    conn.handleReceivedData(bytes: data, count: Int(len))
                } else {
                    conn.handleRemoteClose()
                }
            }
        }

        // Sent: send-buffer space freed (bytes acknowledged).
        lwip_bridge_set_tcp_sent_fn { connection, len in
            guard let connection else { return }
            BridgeContext.unretained(connection, as: TCPConnection.self).assumeIsolated { $0.handleSent(len: len) }
        }

        // Err: the pcb is already freed by lwIP — consume the retained reference it held.
        lwip_bridge_set_tcp_err_fn { connection, err in
            guard let connection else {
                logger.debug("[LWIPBridge] tcp_err: connection is nil, err=\(err)")
                return
            }
            BridgeContext.consume(connection, as: TCPConnection.self).assumeIsolated { $0.handleError(err: err) }
        }
    }

    /// Brings the lwIP netif, listeners, and timers up. Call after ``installCallbacks(host:)``,
    /// on ``queue``.
    func initEngine() {
        lwip_bridge_init()
    }

    /// Tears the lwIP stack down (netif, listeners, all pcbs). Runs on ``queue``.
    func shutdownEngine() {
        lwip_bridge_shutdown()
    }

    /// Clears the host context so no late callback resolves a torn-down host. Runs on ``queue``.
    func clearHost() {
        lwip_bridge_set_host_ctx(nil)
    }

    /// Gracefully closes every active TCP connection (FIN, letting lwIP downgrade in-flight
    /// legs to RST) without touching the netif or listeners — the network-recovery path.
    /// Runs on ``queue``.
    func closeAllActiveTCP() {
        lwip_bridge_for_each_tcp { arg in
            guard let arg else { return }
            BridgeContext.unretained(arg, as: TCPConnection.self).assumeIsolated { $0.close() }
        }
    }

    /// Active TCP pcbs (established/connecting/closing); LISTEN and TIME_WAIT excluded.
    /// Runs on ``queue``.
    func activeTCPCount() -> Int {
        Int(lwip_bridge_active_tcp_count())
    }

    // MARK: - Data plane

    /// Feeds a TCP/ICMP packet batch into lwIP. The batch bracket coalesces per-segment
    /// ACKs and flushes one ACK per active pcb on end (ANYWHERE_PATCHES Patch 3). The
    /// caller re-arms the timeout tick after, since a fresh segment may queue a timeout.
    /// Runs on ``queue``.
    func input(_ packets: [Data]) {
        lwip_bridge_input_batch_begin()
        for packet in packets {
            packet.withUnsafeBytes { buffer in
                guard let baseAddress = buffer.baseAddress else { return }
                lwip_bridge_input(baseAddress, Int32(buffer.count))
            }
        }
        lwip_bridge_input_batch_end()
    }

    /// Services lwIP's timeout list (TCP retransmit, persist, TIME_WAIT). Returns `true`
    /// once nothing remains pending, so the caller can suspend the periodic tick until
    /// fresh input re-arms it. Runs on ``queue``.
    func serviceTimeouts() -> Bool {
        lwip_bridge_check_timeouts() != 0
    }

    // MARK: - Per-connection TCP operations
    //
    // The `pcb` is lwIP's per-connection handle, owned by a ``TCPConnection`` and only
    // valid on ``queue``. These wrap the raw `lwip_bridge_tcp_*` entry points so the
    // connection's relay logic never names a C symbol. All run on ``queue``.

    /// Half-closes the send direction (sends a FIN), leaving the receive side open.
    func tcpShutdownTx(_ pcb: UnsafeMutableRawPointer) {
        lwip_bridge_tcp_shutdown_tx(pcb)
    }

    /// Acks `len` received bytes back to lwIP, reopening the receive window.
    func tcpRecved(_ pcb: UnsafeMutableRawPointer, _ len: UInt16) {
        lwip_bridge_tcp_recved(pcb, len)
    }

    /// Flushes queued segments (fires the output callback synchronously).
    func tcpOutput(_ pcb: UnsafeMutableRawPointer) {
        lwip_bridge_tcp_output(pcb)
    }

    /// Bytes lwIP's send buffer can currently accept.
    func tcpSendBuffer(_ pcb: UnsafeMutableRawPointer) -> Int {
        Int(lwip_bridge_tcp_sndbuf(pcb))
    }

    /// Enqueues up to `len` bytes for sending; returns lwIP's `err_t` (0 = ok, -1 = ERR_MEM).
    func tcpWrite(_ pcb: UnsafeMutableRawPointer, _ data: UnsafeRawPointer, _ len: UInt16) -> Int32 {
        lwip_bridge_tcp_write(pcb, data, len)
    }

    /// Number of segments queued but not yet acked — the send-queue depth.
    func tcpSendQueueLength(_ pcb: UnsafeMutableRawPointer) -> Int {
        Int(lwip_bridge_tcp_snd_queuelen(pcb))
    }

    /// Closes the connection (FIN); downgrades to RST if un-recved bytes remain.
    func tcpClose(_ pcb: UnsafeMutableRawPointer) {
        lwip_bridge_tcp_close(pcb)
    }

    /// Aborts the connection (RST) and frees the pcb.
    func tcpAbort(_ pcb: UnsafeMutableRawPointer) {
        lwip_bridge_tcp_abort(pcb)
    }

    /// One-shot best-effort write of `data` (e.g. a pre-establishment reject alert), flushing
    /// output after. Bounded by the send buffer; a short write or `ERR_MEM` just stops early.
    func tcpWriteImmediate(_ pcb: UnsafeMutableRawPointer, _ data: Data) {
        guard !data.isEmpty else { return }
        var written = 0
        data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            while written < data.count {
                let sndbuf = tcpSendBuffer(pcb)
                guard sndbuf > 0 else { break }
                let chunk = min(min(sndbuf, data.count - written), TunnelConstants.tcpMaxWriteSize)
                guard tcpWrite(pcb, base + written, UInt16(chunk)) == 0 else { break }
                written += chunk
            }
        }
        if written > 0 { tcpOutput(pcb) }
    }

    // MARK: - Per-PCB token teardown
    //
    // A new pcb stores a *retained* `TCPConnection` as its `tcp_arg` (vended in the accept
    // trampoline above). The recv/sent callbacks recover it unretained; the terminal
    // `tcp_err` consumes it. ``discard(_:)`` balances it when Swift drives teardown itself
    // (`tcp_close`/`tcp_abort`) and no `tcp_err` will fire.

    /// Balances an accepted connection's retained reference when Swift drives teardown
    /// (`tcp_close`/`tcp_abort`) and no terminal `tcp_err` will fire to consume it.
    /// Runs on ``queue``.
    func discard(_ connection: TCPConnection) {
        BridgeContext.release(connection)
    }

    // MARK: - Host recovery

    /// Recovers the host behind the bridge's global context. All callbacks run on ``queue``,
    /// where the context is set/cleared, so the read is queue-confined.
    private static func host() -> (any LWIPBridgeHost)? {
        guard let ctx = lwip_bridge_host_ctx() else { return nil }
        return BridgeContext.unretained(ctx, as: AnyObject.self) as? LWIPBridgeHost
    }
}
