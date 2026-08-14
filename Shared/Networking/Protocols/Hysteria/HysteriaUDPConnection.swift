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

    private enum Phase: PhaseTransitionable {
        case idle
        case opening
        case open(sid: UInt32)
        case closed

        var isClosed: Bool {
            if case .closed = self { true } else { false }
        }

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .opening),
                 (.opening, .open):
                return true
            case (_, .closed):
                return !old.isClosed
            default:
                return false
            }
        }
    }
    private nonisolated let phase = Mutex<Phase>(.idle)
    
    private let rawInbox = AsyncInbox<HysteriaProtocol.UDPMessage>()
    
    private struct DefragSlot {
        var fragments: [Data?]
        var received: Int
        let fragmentCount: Int
        let createdAt: DispatchTime
    }
    private var defragSlots: [UInt16: DefragSlot] = [:]
    private nonisolated static let defragSlotTTLNanos: UInt64 = 10 * 1_000_000_000
    private nonisolated static let maxDefragSlots = 32
    
    private var nextPacketID: UInt16 = 1

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
    }

    nonisolated var isConnected: Bool {
        phase.withLock { if case .open = $0 { true } else { false } }
    }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }
    nonisolated var deliversDatagrams: Bool { true }

    private nonisolated var currentSID: UInt32? {
        phase.withLock { if case .open(let sid) = $0 { sid } else { nil } }
    }

    private nonisolated func closeLifecycle() -> UInt32? {
        phase.withLock { state in
            let sid: UInt32?
            switch state {
            case .closed: return nil
            case .open(let s): sid = s
            case .idle, .opening: sid = nil
            }
            Phase.transition(&state, to: .closed)
            return sid
        }
    }

    // MARK: - Open

    func open() async throws {
        let begin = phase.withLock { Phase.transition(&$0, to: .opening) }
        guard begin else { throw AnywhereError.proxy(.hysteria, .streamClosed) }

        let sid: UInt32
        do {
            sid = try await session.registerUDPSession(self)
        } catch {
            _ = closeLifecycle()
            throw error
        }
        let adopted = phase.withLock { Phase.transition(&$0, to: .open(sid: sid)) }
        guard adopted else {
            session.releaseUDPSession(sid)
            throw AnywhereError.proxy(.hysteria, .streamClosed)
        }
    }

    // MARK: - Demux feed

    nonisolated func feedDatagram(_ message: HysteriaProtocol.UDPMessage) {
        rawInbox.yield(message)
    }

    nonisolated func handleSessionError(_ error: Error) {
        rawInbox.finish(throwing: error)
        _ = closeLifecycle()
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
            guard let payload = assembled, !payload.isEmpty else { continue }
            return payload
        }
    }

    private func nextMessage() async throws -> HysteriaProtocol.UDPMessage? {
        try await rawInbox.next()
    }

    private func assembleFragment(_ message: HysteriaProtocol.UDPMessage) -> Data? {
        guard message.fragID < message.fragCount, message.fragCount > 0 else { return nil }

        let now = DispatchTime.now()
        let nowNs = now.uptimeNanoseconds
        
        let existing = defragSlots[message.packetID]
        let existingIsExpired = existing.map {
            nowNs &- $0.createdAt.uptimeNanoseconds > Self.defragSlotTTLNanos
        } ?? false

        var slot: DefragSlot
        if let existing, !existingIsExpired,
           existing.fragmentCount == Int(message.fragCount) {
            slot = existing
        } else {
            if existing == nil || existingIsExpired,
               defragSlots.count >= Self.maxDefragSlots {
                let victim: UInt16? = defragSlots
                    .lazy
                    .map { (key: $0.key, slot: $0.value) }
                    .min { lhs, rhs in
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
    
    func sendRaw(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        try await attemptSend(data: data, maxSizeOverride: nil, retriesLeft: 1)
    }
    
    private func attemptSend(data: Data, maxSizeOverride: Int?, retriesLeft: Int) async throws {
        guard let sessionID = currentSID else {
            throw AnywhereError.proxy(.hysteria, .streamClosed)
        }
        let maxSize: Int
        if let maxSizeOverride {
            maxSize = maxSizeOverride
        } else {
            maxSize = await session.currentMaxDatagramPayloadSize()
        }
        let headerSize = HysteriaProtocol.udpHeaderSize(address: destination)
        guard maxSize > headerSize else {
            throw AnywhereError.proxy(.hysteria, .datagramTooLarge(maxFrame: maxSize, headerSize: headerSize))
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
            throw AnywhereError.proxy(.hysteria, .connectionClosed(detail: "UDP payload too large to fragment"))
        }
        let encoded = fragments.map { $0.encoded }
        do {
            try await session.writeDatagrams(encoded)
        } catch {
            if case AnywhereError.quic(.datagramTooLarge(let maxBound)) = error,
               retriesLeft > 0 {
                guard isConnected else {
                    throw AnywhereError.proxy(.hysteria, .streamClosed)
                }
                try await attemptSend(data: data, maxSizeOverride: maxBound, retriesLeft: retriesLeft - 1)
                return
            }
            throw error
        }
    }

    nonisolated func cancel() {
        rawInbox.finish()
        if let sid = closeLifecycle() {
            session.releaseUDPSession(sid)
        }
        Task { await self.clearDefragSlots() }
    }

    private func clearDefragSlots() {
        defragSlots.removeAll()
    }

    // MARK: - Helpers
    
    private func newPacketID() -> UInt16 {
        let pid = nextPacketID
        nextPacketID = nextPacketID == UInt16.max ? 1 : nextPacketID + 1
        return pid
    }
}

extension HysteriaUDPConnection: ProxyConnection {}
