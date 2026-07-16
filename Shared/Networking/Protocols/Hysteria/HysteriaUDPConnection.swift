//
//  HysteriaUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HysteriaUDPConnection")

nonisolated final class HysteriaUDPConnection: ProxyConnection {

    enum State { case idle, ready, closed }

    private let session: HysteriaSession
    private let destination: String

    /// Confined to `session.queue`. The setter mirrors readiness into
    /// `_isReady` so `isConnected` avoids a sync hop onto `session.queue`.
    private var _state: State = .idle
    private var state: State {
        get { _state }
        set {
            _state = newValue
            _isReady.store(newValue == .ready, ordering: .relaxed)
        }
    }
    private let _isReady = Atomic<Bool>(false)

    /// Assigned once on `session.queue` during open, then read from the async send path.
    private let _sessionID = Atomic<UInt32>(0)
    private var sessionID: UInt32 {
        get { _sessionID.load(ordering: .relaxed) }
        set { _sessionID.store(newValue, ordering: .relaxed) }
    }

    /// Reassembled inbound datagrams / EOF / error, pushed from the session's datagram
    /// demux (on `session.queue`, inside ngtcp2's recv_datagram) and pulled by `receiveRaw`.
    /// The async replacement for the parked `pendingReceive`; datagrams aren't flow-controlled,
    /// so steady-state depth stays near zero because `UDPFlow` drains it in a tight loop.
    private let inbox = AsyncByteChannel()

    /// Serializes framed datagram writes (and thus PacketID allocation) across the wire `await`.
    private let sendMutex = AsyncMutex()

    /// Per-PacketID reassembly slot; fragments arrive interleaved, so each
    /// PacketID owns one. Evicted on completion, TTL expiry, or cap overflow.
    private struct DefragSlot {
        var fragments: [Data?]
        var received: Int
        let fragmentCount: Int
        let createdAt: DispatchTime
    }
    private var defragSlots: [UInt16: DefragSlot] = [:]
    private static let defragSlotTTLNanos: UInt64 = 10 * 1_000_000_000
    /// Concurrent reassembly cap; 32 bounds worst-case memory to ~11 MB
    /// while keeping LRU eviction rare.
    private static let maxDefragSlots = 32

    /// Monotonic PacketID, wrapping 0xFFFF → 1 and skipping 0 ("unfragmented"
    /// to some servers); colliding IDs would merge two packets into one
    /// corrupt defrag slot. Mutated only under `sendMutex`.
    private var nextPacketID: UInt16 = 1

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
        super.init()
    }

    /// Atomic readiness mirror; callable from any queue.
    override var isConnected: Bool {
        _isReady.load(ordering: .relaxed)
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }
    override var deliversDatagrams: Bool { true }

    // MARK: - Open

    func open() async throws {
        let sid = try await session.registerUDPSession(self)
        // Assign the id and flip to ready on the session queue (where the old completion ran),
        // so the queue-confined `_state` write doesn't race the datagram demux reads.
        await session.run { [self] in
            sessionID = sid
            state = .ready
        }
    }

    // MARK: - Incoming datagrams (from session)

    func handleIncomingDatagram(_ message: HysteriaProtocol.UDPMessage) {
        // On session queue. `cancel()` defers `releaseUDPSession`; datagrams
        // in that window must not repopulate a dead connection.
        if state == .closed { return }
        let assembled: Data?
        if message.fragCount <= 1 {
            assembled = message.data
        } else {
            assembled = assembleFragment(message)
        }
        // Drop empty payloads: an empty datagram would look like EOF to the reader.
        guard let payload = assembled, !payload.isEmpty else { return }
        inbox.yield(payload)
    }

    private func assembleFragment(_ message: HysteriaProtocol.UDPMessage) -> Data? {
        guard message.fragID < message.fragCount, message.fragCount > 0 else { return nil }

        let now = DispatchTime.now()
        let nowNs = now.uptimeNanoseconds

        // Lazy TTL eviction: a full-dict scan per fragment is noticeable at the cap.
        let existing = defragSlots[message.packetID]
        let existingIsExpired = existing.map {
            nowNs &- $0.createdAt.uptimeNanoseconds > Self.defragSlotTTLNanos
        } ?? false

        var slot: DefragSlot
        if let existing, !existingIsExpired,
           existing.fragmentCount == Int(message.fragCount) {
            slot = existing
        } else {
            // New slot at cap: evict expired slots first, else the oldest.
            if existing == nil || existingIsExpired,
               defragSlots.count >= Self.maxDefragSlots {
                let victim: UInt16? = defragSlots
                    .lazy
                    .map { (key: $0.key, slot: $0.value) }
                    .min { lhs, rhs in
                        // Prefer expired slots over live ones, then oldest.
                        let lhsExpired = nowNs &- lhs.slot.createdAt.uptimeNanoseconds > Self.defragSlotTTLNanos
                        let rhsExpired = nowNs &- rhs.slot.createdAt.uptimeNanoseconds > Self.defragSlotTTLNanos
                        if lhsExpired != rhsExpired { return lhsExpired }
                        return lhs.slot.createdAt < rhs.slot.createdAt
                    }?.key
                if let victim {
                    defragSlots.removeValue(forKey: victim)
                }
            }
            slot = DefragSlot(
                fragments: Array(repeating: nil, count: Int(message.fragCount)),
                received: 0,
                fragmentCount: Int(message.fragCount),
                createdAt: now
            )
        }

        if slot.fragments[Int(message.fragID)] == nil {
            slot.fragments[Int(message.fragID)] = message.data
            slot.received += 1
        }

        if slot.received < slot.fragmentCount {
            defragSlots[message.packetID] = slot
            return nil
        }

        defragSlots.removeValue(forKey: message.packetID)
        var full = Data()
        for part in slot.fragments {
            guard let part else { return nil }
            full.append(part)
        }
        return full
    }

    // MARK: - ProxyConnection overrides

    /// Wraps `data` in a Hysteria UDP datagram, fragmenting at the QUIC DATAGRAM MTU.
    override func sendRaw(_ data: Data) async throws {
        // The wire format requires ≥1 data byte after the address; the
        // server silently discards zero-byte payloads.
        guard !data.isEmpty else { return }
        guard _isReady.load(ordering: .relaxed) else {
            throw HysteriaError.streamClosed
        }
        // Serialize so PacketID allocation and datagram order match on-wire order.
        try await sendMutex.withLock {
            try await self.attemptSend(data: data, maxSizeOverride: nil, retriesLeft: 1)
        }
    }

    /// Fragments `data` and submits to QUIC; on `datagramTooLarge` (PMTU shrank
    /// mid-send) retries once with the bound from the error. Runs under `sendMutex`.
    private func attemptSend(data: Data, maxSizeOverride: Int?, retriesLeft: Int) async throws {
        // maxSize 0 (DATAGRAM unsupported / MTU collapsed) is permanent for
        // this fixed destination — surface a terminal error.
        let maxSize: Int
        if let maxSizeOverride {
            maxSize = maxSizeOverride
        } else {
            maxSize = await session.currentMaxDatagramPayloadSize()
        }
        let headerSize = HysteriaProtocol.udpHeaderSize(address: destination)
        guard maxSize > headerSize else {
            throw HysteriaError.destinationTooLargeForDatagram(maxFrame: maxSize, headerSize: headerSize)
        }
        let packetID = newPacketID()
        let fragments = HysteriaProtocol.fragmentUDP(
            sessionID: sessionID,
            packetID: packetID,
            address: destination,
            data: data,
            maxDatagramSize: maxSize
        )
        guard !fragments.isEmpty else {
            throw HysteriaError.connectionFailed("UDP payload too large to fragment")
        }
        let encoded = fragments.map { $0.encoded }
        do {
            try await session.writeDatagrams(encoded)
        } catch {
            if let qErr = error as? QUICConnection.QUICError,
               case .datagramTooLarge(let maxBound) = qErr,
               retriesLeft > 0 {
                guard _isReady.load(ordering: .relaxed) else {
                    throw HysteriaError.streamClosed
                }
                try await attemptSend(data: data, maxSizeOverride: maxBound, retriesLeft: retriesLeft - 1)
                return
            }
            throw error
        }
    }

    override func receiveRaw() async throws -> Data? {
        try await inbox.next()
    }

    override func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.session.releaseUDPSession(self.sessionID)
            self.defragSlots.removeAll()
            self.inbox.cancel()
        }
    }

    func handleSessionError(_ error: Error) {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.inbox.fail(error)
        }
    }

    // MARK: - Helpers

    /// Next PacketID; called only under `sendMutex`, so no queue confinement is needed.
    private func newPacketID() -> UInt16 {
        let pid = nextPacketID
        nextPacketID = nextPacketID == UInt16.max ? 1 : nextPacketID + 1
        return pid
    }
}
