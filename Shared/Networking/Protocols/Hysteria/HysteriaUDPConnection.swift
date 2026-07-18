//
//  HysteriaUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HysteriaUDPConnection")

actor HysteriaUDPConnection {

    private let session: HysteriaSession
    private let destination: String

    /// Readiness mirror for the nonisolated `isConnected`/send-guard.
    private nonisolated let _isReady = Atomic<Bool>(false)
    /// Assigned once in `open()`, read from the send path.
    private nonisolated let _sessionID = Atomic<UInt32>(0)

    /// Inbound datagram messages from the demux. Producer (`rawInbox`) is `Sendable` and driven on
    /// the ngtcp2 queue; `receiveRaw()` pulls `rawIterator` and reassembles, so both the iterator and
    /// the defrag slots are plain actor-isolated state.
    private nonisolated let rawInbox: AsyncThrowingStream<HysteriaProtocol.UDPMessage, Error>.Continuation
    nonisolated(unsafe) private var rawIterator: AsyncThrowingStream<HysteriaProtocol.UDPMessage, Error>.AsyncIterator

    /// Per-PacketID reassembly slot; fragments arrive interleaved, so each PacketID owns one.
    /// Evicted on completion, TTL expiry, or cap overflow.
    private struct DefragSlot {
        var fragments: [Data?]
        var received: Int
        let fragmentCount: Int
        let createdAt: DispatchTime
    }
    private var defragSlots: [UInt16: DefragSlot] = [:]
    private nonisolated static let defragSlotTTLNanos: UInt64 = 10 * 1_000_000_000
    /// Concurrent reassembly cap; 32 bounds worst-case memory to ~11 MB while keeping eviction rare.
    private nonisolated static let maxDefragSlots = 32

    /// Monotonic PacketID, wrapping 0xFFFF → 1 and skipping 0 ("unfragmented" to some servers);
    /// colliding IDs would merge two packets into one corrupt defrag slot. Allocated in `newPacketID`,
    /// whose actor-isolated synchronous execution gives each concurrent send a distinct id.
    private var nextPacketID: UInt16 = 1

    /// Guards `teardown()` so the session is released exactly once.
    private var closed = false

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
        let (stream, continuation) = AsyncThrowingStream.makeStream(of: HysteriaProtocol.UDPMessage.self)
        self.rawInbox = continuation
        self.rawIterator = stream.makeAsyncIterator()
    }

    nonisolated var isConnected: Bool { _isReady.load(ordering: .relaxed) }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }
    nonisolated var deliversDatagrams: Bool { true }

    private var sessionID: UInt32 {
        get { _sessionID.load(ordering: .relaxed) }
        set { _sessionID.store(newValue, ordering: .relaxed) }
    }

    // MARK: - Open

    func open() async throws {
        let sid = try await session.registerUDPSession(self)
        sessionID = sid
        _isReady.store(true, ordering: .relaxed)
    }

    // MARK: - Demux feed (nonisolated; driven on the ngtcp2 queue)

    nonisolated func feedDatagram(_ message: HysteriaProtocol.UDPMessage) {
        rawInbox.yield(message)
    }

    nonisolated func handleSessionError(_ error: Error) {
        _isReady.store(false, ordering: .relaxed)
        rawInbox.finish(throwing: error)
    }

    // MARK: - ProxyConnection overrides

    func receiveRaw() async throws -> Data? {
        while true {
            guard let message = try await nextMessage() else { return nil }
            let assembled: Data?
            if message.fragCount <= 1 {
                assembled = message.data
            } else {
                assembled = assembleFragment(message)
            }
            // Drop empty payloads: an empty datagram would look like EOF to the reader.
            guard let payload = assembled, !payload.isEmpty else { continue }
            return payload
        }
    }
    
    private func nextMessage() async throws -> HysteriaProtocol.UDPMessage? {
        try await rawIterator.next(isolation: #isolation)
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

    /// Wraps `data` in a Hysteria UDP datagram, fragmenting at the QUIC DATAGRAM MTU.
    func sendRaw(_ data: Data) async throws {
        // The wire format requires ≥1 data byte after the address; the server discards zero-byte payloads.
        guard !data.isEmpty else { return }
        guard _isReady.load(ordering: .relaxed) else {
            throw HysteriaError.streamClosed
        }
        // No send lock: actor isolation makes PacketID allocation atomic (distinct ids per
        // concurrent send), and QUIC writes each fragment batch atomically. UDP tolerates
        // whole-datagram reordering, so nothing further needs serializing.
        try await attemptSend(data: data, maxSizeOverride: nil, retriesLeft: 1)
    }

    /// Fragments `data` and submits to QUIC; on `datagramTooLarge` (PMTU shrank mid-send)
    /// retries once with the bound from the error.
    private func attemptSend(data: Data, maxSizeOverride: Int?, retriesLeft: Int) async throws {
        // maxSize 0 (DATAGRAM unsupported / MTU collapsed) is permanent for this fixed
        // destination — surface a terminal error.
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

    nonisolated func cancel() {
        _isReady.store(false, ordering: .relaxed)
        rawInbox.finish()
        Task { await self.teardown() }
    }

    private func teardown() {
        guard !closed else { return }
        closed = true
        session.releaseUDPSession(_sessionID.load(ordering: .relaxed))
        defragSlots.removeAll()
    }

    // MARK: - Helpers

    /// Next PacketID. Actor-isolated, so concurrent sends never collide.
    private func newPacketID() -> UInt16 {
        let pid = nextPacketID
        nextPacketID = nextPacketID == UInt16.max ? 1 : nextPacketID + 1
        return pid
    }
}

extension HysteriaUDPConnection: ProxyConnection {}
