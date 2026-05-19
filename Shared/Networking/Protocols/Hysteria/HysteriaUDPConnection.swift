//
//  HysteriaUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation

private let logger = AnywhereLogger(category: "Hysteria-UDP")

nonisolated final class HysteriaUDPConnection: ProxyConnection {

    enum State { case idle, ready, closed }

    private let session: HysteriaSession
    private let destination: String
    private var state: State = .idle
    private var sessionID: UInt32 = 0

    /// Per-datagram FIFO. Bounded at `maxQueuedPackets` with drop-oldest
    /// semantics — matches the reference Go client's 1024-slot `ReceiveCh`
    /// and preserves UDP's lossy contract.
    /// All `packetQueue` / `pendingReceive` / `closureError` mutation runs
    /// on `session.queue` (producer, consumer, and teardown all funnel
    /// through it); consumer delivery hops through the queue once so the
    /// completion never fires from inside ngtcp2's `recv_datagram` stack.
    private var packetQueue: [Data] = []
    private static let maxQueuedPackets = 1024

    private var pendingReceive: ((Data?, Error?) -> Void)?

    /// Closure error stashed when the session tears down between receive
    /// calls (no `pendingReceive` set at the moment `handleSessionError`
    /// fires). Surfaced on the next `receiveRaw` so the consumer learns the
    /// connection is gone and closes its flow — without this, the upstream
    /// `LWIPUDPFlow` would sit on a dead connection until the 300 s idle
    /// timer reaped it.
    private var closureError: Error?

    /// Per-PacketID reassembly slots. Multiple fragmented packets can be in
    /// flight concurrently and arrive interleaved (the QUIC DATAGRAM frame
    /// gives no ordering guarantee), so each PacketID owns an independent
    /// slot — matches sing-quic's `udpDefragger` (hysteria2/packet.go).
    /// Slots evict on completion, on TTL expiry (`defragSlotTTLNanos`), or
    /// when the concurrent-slot cap (`maxDefragSlots`) forces oldest-out.
    private struct DefragSlot {
        var fragments: [Data?]
        var received: Int
        let fragmentCount: Int
        let createdAt: DispatchTime
    }
    private var defragSlots: [UInt16: DefragSlot] = [:]
    private static let defragSlotTTLNanos: UInt64 = 10 * 1_000_000_000
    private static let maxDefragSlots = 8

    /// Monotonic per-connection PacketID counter. Wraps from 0xFFFF back to
    /// 1, skipping 0 (reserved as "unfragmented" by some Hysteria servers).
    /// A monotonic counter avoids defrag-slot corruption from ID collisions
    /// inside the 16-bit space — `assembleFragment` reuses a slot when the
    /// fragment count matches, so two upper-layer packets that draw the
    /// same random ID would merge into one corrupt payload. Matches
    /// sing-quic's `packetId.Add(1) % math.MaxUint16` (hysteria2/packet.go).
    /// Only mutated on `session.queue` (the only call site is `sendRaw`).
    private var nextPacketID: UInt16 = 1

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
        super.init()
    }

    override var isConnected: Bool {
        session.isOnQueue ? (state == .ready) : session.queue.sync { state == .ready }
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - Open

    func open(completion: @escaping (Error?) -> Void) {
        session.registerUDPSession(self) { [weak self] result in
            guard let self else { completion(HysteriaError.streamClosed); return }
            switch result {
            case .failure(let error):
                completion(error)
            case .success(let sid):
                self.sessionID = sid
                self.state = .ready
                completion(nil)
            }
        }
    }

    // MARK: - Incoming datagrams (from session)

    func handleIncomingDatagram(_ msg: HysteriaProtocol.UDPMessage) {
        // On session queue.
        let assembled: Data?
        if msg.fragCount <= 1 {
            assembled = msg.data
        } else {
            assembled = assembleFragment(msg)
        }
        // Drop empty payloads. The default `ProxyConnection.receiveLoop`
        // treats empty `Data` as EOF (it differs from `nil` only in
        // type), so passing a zero-byte datagram through would close the
        // flow on the consumer side. Skipping silently matches UDP's
        // lossy contract and also defends against an attacker sending an
        // all-empty fragment chain to terminate the session.
        guard let payload = assembled, !payload.isEmpty else { return }

        if let cb = pendingReceive {
            pendingReceive = nil
            // Hop through `session.queue` so the completion never fires from
            // the same call stack as ngtcp2's `recv_datagram` callback.
            session.queue.async { cb(payload, nil) }
            return
        }
        if packetQueue.count >= Self.maxQueuedPackets {
            packetQueue.removeFirst()
        }
        packetQueue.append(payload)
    }

    private func assembleFragment(_ msg: HysteriaProtocol.UDPMessage) -> Data? {
        // Drop fragments with invalid indices.
        guard msg.fragID < msg.fragCount, msg.fragCount > 0 else { return nil }

        let now = DispatchTime.now()
        let nowNs = now.uptimeNanoseconds

        if !defragSlots.isEmpty {
            defragSlots = defragSlots.filter { _, slot in
                nowNs &- slot.createdAt.uptimeNanoseconds <= Self.defragSlotTTLNanos
            }
        }

        var slot: DefragSlot
        if let existing = defragSlots[msg.packetID], existing.fragmentCount == Int(msg.fragCount) {
            slot = existing
        } else {
            if defragSlots[msg.packetID] == nil, defragSlots.count >= Self.maxDefragSlots,
               let oldestKey = defragSlots.min(by: { $0.value.createdAt < $1.value.createdAt })?.key {
                defragSlots.removeValue(forKey: oldestKey)
            }
            slot = DefragSlot(
                fragments: Array(repeating: nil, count: Int(msg.fragCount)),
                received: 0,
                fragmentCount: Int(msg.fragCount),
                createdAt: now
            )
        }

        if slot.fragments[Int(msg.fragID)] == nil {
            slot.fragments[Int(msg.fragID)] = msg.data
            slot.received += 1
        }

        if slot.received < slot.fragmentCount {
            defragSlots[msg.packetID] = slot
            return nil
        }

        defragSlots.removeValue(forKey: msg.packetID)
        var full = Data()
        for part in slot.fragments {
            guard let part else { return nil }
            full.append(part)
        }
        return full
    }

    // MARK: - ProxyConnection overrides

    /// Called by LWIPUDPFlow with one raw UDP payload per call (see the
    /// `.hysteria` branch of `LWIPUDPFlow.connectViaProxyClient`). Wraps the
    /// payload in a Hysteria UDP datagram, fragmenting when the QUIC
    /// DATAGRAM MTU would be exceeded.
    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(HysteriaError.streamClosed); return }
            guard self.state == .ready else {
                completion(self.state == .closed ? HysteriaError.streamClosed : HysteriaError.notReady)
                return
            }
            self.attemptSend(data: data, retriesLeft: 1, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    /// Fragments `data` against the current path MTU and submits the
    /// fragments to the QUIC layer. On a `datagramTooLarge` outcome
    /// (PMTU shrank between fragmentation and `writeToUDP`), retries once
    /// at the now-reported smaller bound — re-fragmentation uses a fresh
    /// `packetID`, so the receiver's defrag slot for the orphaned attempt
    /// times out independently and doesn't mix with the retry.
    /// Must be called on `session.queue`.
    private func attemptSend(
        data: Data,
        retriesLeft: Int,
        completion: @escaping (Error?) -> Void
    ) {
        // `maxDatagramPayloadSize` returns 0 when the peer didn't advertise
        // DATAGRAM support (shouldn't happen because `registerUDPSession`
        // already gates on `udpSupported`) or when the path MTU has
        // collapsed below the Hysteria UDP header floor. Either case
        // makes every subsequent fragmentation attempt fail with a
        // misleading "too large to fragment" error; surface a dedicated
        // error so the consumer's log shows the real reason once instead
        // of one "too large" line per send.
        let maxSize = self.session.maxDatagramPayloadSize
        let headerSize = HysteriaProtocol.udpHeaderSize(address: self.destination)
        guard maxSize > headerSize else {
            completion(HysteriaError.connectionFailed(
                "Datagram path unusable (peer max \(maxSize) ≤ header \(headerSize))"
            ))
            return
        }
        let packetID = self.newPacketID()
        let fragments = HysteriaProtocol.fragmentUDP(
            sessionID: self.sessionID,
            packetID: packetID,
            address: self.destination,
            data: data,
            maxDatagramSize: maxSize
        )
        guard !fragments.isEmpty else {
            completion(HysteriaError.connectionFailed("UDP payload too large to fragment"))
            return
        }
        let encoded = fragments.map { HysteriaProtocol.encodeUDPMessage($0) }
        self.session.writeDatagrams(encoded) { [weak self] error in
            // `writeDatagrams` always fires this completion on
            // `session.queue` (== `quic.queue`), so we're safe to mutate
            // state and recurse into `attemptSend` directly.
            // `datagramTooLarge` means PMTU shrank under us between
            // fragmentation and send — re-attempt once with a fresh
            // `maxDatagramPayloadSize` read.
            if let qErr = error as? QUICConnection.QUICError,
               case .datagramTooLarge = qErr,
               retriesLeft > 0,
               let self = self {
                guard self.state == .ready else {
                    completion(self.state == .closed
                        ? HysteriaError.streamClosed
                        : HysteriaError.notReady)
                    return
                }
                self.attemptSend(
                    data: data,
                    retriesLeft: retriesLeft - 1,
                    completion: completion
                )
                return
            }
            completion(error)
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        // Always hop to session.queue so reads of `packetQueue` /
        // `pendingReceive` / `closureError` happen on the owning queue.
        session.queue.async { [weak self] in
            guard let self else {
                completion(nil, HysteriaError.streamClosed)
                return
            }
            // Drain buffered packets first, even after the session has
            // errored or closed — those packets were received before the
            // failure and represent good data. `handleSessionError`
            // intentionally leaves `packetQueue` populated; surfacing the
            // stashed `closureError` ahead of the queue would silently
            // discard them and trip the consumer's errorHandler with
            // outstanding data in the buffer.
            if !self.packetQueue.isEmpty {
                let packet = self.packetQueue.removeFirst()
                completion(packet, nil)
                return
            }
            // Buffer empty: now surface any stashed error from a session
            // teardown that happened between calls.
            if let err = self.closureError {
                self.closureError = nil
                completion(nil, err)
                return
            }
            // No buffered data, no stashed error, already closed → EOF.
            if self.state == .closed {
                completion(nil, nil)
                return
            }
            self.pendingReceive = completion
        }
    }

    override func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.session.releaseUDPSession(self.sessionID)
            let cb = self.pendingReceive
            self.pendingReceive = nil
            self.packetQueue.removeAll()
            self.defragSlots.removeAll()
            cb?(nil, HysteriaError.streamClosed)
        }
    }

    func handleSessionError(_ error: Error) {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            let cb = self.pendingReceive
            self.pendingReceive = nil
            // If no consumer was waiting, the receive loop is between calls
            // (handler running, next receiveRaw not yet scheduled). Stash
            // the error so the next call surfaces it instead of finding a
            // silent queue-empty state and re-arming.
            if cb == nil {
                self.closureError = error
            }
            cb?(nil, error)
        }
    }

    // MARK: - Helpers

    /// Returns the next PacketID in monotonic order, skipping 0. Must be
    /// called on `session.queue`.
    private func newPacketID() -> UInt16 {
        let pid = nextPacketID
        nextPacketID = nextPacketID == UInt16.max ? 1 : nextPacketID + 1
        return pid
    }
}
