//
//  FakeIPPool.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "FakeIPPool")

nonisolated final class FakeIPPool: Sendable {
    struct Entry {
        let domain: String
        var shouldReject = false
        var verdict: DomainRouter.Match?
        var verdictVersion: UInt64 = 0
    }

    private class LRUNode {
        let offset: Int
        var prev: LRUNode?
        var next: LRUNode?
        init(offset: Int) { self.offset = offset }
    }
    
    private struct State {
        var domainToOffset: [String: Int] = [:]
        var offsetToEntry: [Int: Entry] = [:]

        var lruHead: LRUNode?  // most recently used
        var lruTail: LRUNode?  // least recently used
        var offsetToNode: [Int: LRUNode] = [:]

        var nextOffset = 1

        // MARK: LRU Doubly-Linked List (O(1) operations)

        mutating func touchLRU(_ offset: Int) {
            guard let node = offsetToNode[offset] else { return }
            removeNode(node)
            insertAtHead(node)
        }

        mutating func appendLRU(_ offset: Int) {
            let node = LRUNode(offset: offset)
            offsetToNode[offset] = node
            insertAtHead(node)
        }

        mutating func evictLRU() -> Int {
            guard let tail = lruTail else {
                // Unreachable (pool is full ⇒ LRU nonempty); fall back rather than crash.
                logger.debug("[FakeIPPool] evictLRU called on empty list, falling back to offset 1")
                return 1
            }
            let offset = tail.offset
            removeNode(tail)
            offsetToNode.removeValue(forKey: offset)
            if let entry = offsetToEntry.removeValue(forKey: offset) {
                domainToOffset.removeValue(forKey: entry.domain)
            }
            return offset
        }

        mutating func removeNode(_ node: LRUNode) {
            node.prev?.next = node.next
            node.next?.prev = node.prev
            if node === lruHead { lruHead = node.next }
            if node === lruTail { lruTail = node.prev }
            node.prev = nil
            node.next = nil
        }

        mutating func insertAtHead(_ node: LRUNode) {
            node.next = lruHead
            node.prev = nil
            lruHead?.prev = node
            lruHead = node
            if lruTail == nil { lruTail = node }
        }
    }

    private let state = Mutex(State())

    // MARK: - Static Helpers
    
    static func isFakeIP(_ ip: String) -> Bool {
        ip.hasPrefix("198.18.") || ip.hasPrefix("198.19.") || ip.hasPrefix("2001:db8::")
    }

    static func ipv4Bytes(offset: Int) -> (UInt8, UInt8, UInt8, UInt8) {
        let ip32 = TunnelConstants.fakeIPPoolBaseIPv4 + UInt32(offset)
        return (
            UInt8((ip32 >> 24) & 0xFF),
            UInt8((ip32 >> 16) & 0xFF),
            UInt8((ip32 >> 8) & 0xFF),
            UInt8(ip32 & 0xFF)
        )
    }

    static func ipv6Bytes(offset: Int) -> [UInt8] {
        return [
            0x20, 0x01,
            0x0D, 0xB8,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            UInt8((offset >> 24) & 0xFF),
            UInt8((offset >> 16) & 0xFF),
            UInt8((offset >> 8) & 0xFF),
            UInt8(offset & 0xFF),
        ]
    }

    // MARK: - Pool Operations

    func allocate(domain: String, verdict: DomainRouter.Match?, verdictVersion: UInt64) -> Int {
        state.withLock { state in
            if let offset = state.domainToOffset[domain] {
                state.touchLRU(offset)
                state.offsetToEntry[offset]?.verdict = verdict
                state.offsetToEntry[offset]?.verdictVersion = verdictVersion
                return offset
            }

            let offset: Int
            if state.nextOffset <= TunnelConstants.fakeIPPoolSize {
                offset = state.nextOffset
                state.nextOffset += 1
            } else {
                offset = state.evictLRU()
            }

            state.domainToOffset[domain] = offset
            state.offsetToEntry[offset] = Entry(domain: domain, verdict: verdict, verdictVersion: verdictVersion)
            state.appendLRU(offset)

            return offset
        }
    }
    
    func cacheVerdict(domain: String, match: DomainRouter.Match?, version: UInt64) {
        state.withLock { state in
            guard let offset = state.domainToOffset[domain] else { return }
            state.offsetToEntry[offset]?.verdict = match
            state.offsetToEntry[offset]?.verdictVersion = version
        }
    }

    func lookup(ip: String) -> Entry? {
        state.withLock { state in
            guard let offset = ipToOffset(ip) else { return nil }
            guard let entry = state.offsetToEntry[offset] else { return nil }
            state.touchLRU(offset)
            return entry
        }
    }

    func reset() {
        state.withLock { $0 = State() }
    }

    var count: Int { state.withLock { $0.domainToOffset.count } }

    // MARK: - Reject Marks
    
    func markRejected(domain: String) {
        let marked = state.withLock { state -> Bool in
            guard let offset = state.domainToOffset[domain],
                  state.offsetToEntry[offset]?.shouldReject == false else { return false }
            state.offsetToEntry[offset]?.shouldReject = true
            return true
        }
        if marked {
            logger.debug("[FakeIPPool] Reject-marked \(domain)")
        }
    }
    
    func clearRejectMarks() {
        state.withLock { state in
            for (offset, entry) in state.offsetToEntry where entry.shouldReject {
                state.offsetToEntry[offset]?.shouldReject = false
            }
        }
    }
    
    func isRejectMarked(rawIP: UnsafeRawPointer, isIPv6: Bool) -> Bool {
        guard let offset = Self.offset(isIPv6: isIPv6, byteAt: {
            rawIP.load(fromByteOffset: $0, as: UInt8.self)
        }) else { return false }
        return isRejectMarked(offset: offset)
    }
    
    func isRejectMarked(ipBytes: SIMD16<UInt8>, isIPv6: Bool) -> Bool {
        guard let offset = Self.offset(isIPv6: isIPv6, byteAt: { ipBytes[$0] }) else {
            return false
        }
        return isRejectMarked(offset: offset)
    }

    private func isRejectMarked(offset: Int) -> Bool {
        state.withLock { $0.offsetToEntry[offset]?.shouldReject ?? false }
    }
    
    private static func offset(isIPv6: Bool, byteAt: (Int) -> UInt8) -> Int? {
        if isIPv6 {
            guard byteAt(0) == 0x20, byteAt(1) == 0x01,
                  byteAt(2) == 0x0D, byteAt(3) == 0xB8 else { return nil }
            for i in 4...11 {
                guard byteAt(i) == 0 else { return nil }
            }
            let offset = (Int(byteAt(12)) << 24) | (Int(byteAt(13)) << 16)
                       | (Int(byteAt(14)) << 8) | Int(byteAt(15))
            guard offset >= 1, offset <= TunnelConstants.fakeIPPoolSize else { return nil }
            return offset
        }
        let ip32 = (UInt32(byteAt(0)) << 24) | (UInt32(byteAt(1)) << 16)
                 | (UInt32(byteAt(2)) << 8) | UInt32(byteAt(3))
        guard ip32 > TunnelConstants.fakeIPPoolBaseIPv4 else { return nil }
        let offset = Int(ip32 - TunnelConstants.fakeIPPoolBaseIPv4)
        guard offset <= TunnelConstants.fakeIPPoolSize else { return nil }
        return offset
    }

    // MARK: - IP ↔ Offset Conversion

    private func ipToOffset(_ ip: String) -> Int? {
        if ip.contains(":") {
            return ipv6ToOffset(ip)
        }
        return ipv4ToOffset(ip)
    }

    private func ipv4ToOffset(_ ip: String) -> Int? {
        var octets: (UInt32, UInt32, UInt32, UInt32) = (0, 0, 0, 0)
        var current: UInt32 = 0
        var octetIndex = 0
        for c in ip.utf8 {
            if c == UInt8(ascii: ".") {
                guard octetIndex < 3 else { return nil }
                switch octetIndex {
                case 0: octets.0 = current
                case 1: octets.1 = current
                case 2: octets.2 = current
                default: return nil
                }
                current = 0
                octetIndex += 1
            } else if c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9") {
                current = current * 10 + UInt32(c - UInt8(ascii: "0"))
                guard current <= 255 else { return nil }
            } else {
                return nil
            }
        }
        guard octetIndex == 3 else { return nil }
        octets.3 = current
        guard octets.3 <= 255 else { return nil }
        let ip32 = (octets.0 << 24) | (octets.1 << 16) | (octets.2 << 8) | octets.3
        let offset = Int(ip32 - TunnelConstants.fakeIPPoolBaseIPv4)
        guard offset >= 1, offset <= TunnelConstants.fakeIPPoolSize else { return nil }
        return offset
    }

    private func ipv6ToOffset(_ ip: String) -> Int? {
        var address = in6_addr()
        guard inet_pton(AF_INET6, ip, &address) == 1 else { return nil }

        return withUnsafeBytes(of: &address) { raw -> Int? in
            let bytes = raw.bindMemory(to: UInt8.self)
            guard bytes.count == 16 else { return nil }

            guard bytes[0] == 0x20, bytes[1] == 0x01,
                  bytes[2] == 0x0D, bytes[3] == 0xB8 else { return nil }
            for i in 4...11 {
                guard bytes[i] == 0 else { return nil }
            }

            let offset = (Int(bytes[12]) << 24) | (Int(bytes[13]) << 16)
                       | (Int(bytes[14]) << 8) | Int(bytes[15])
            guard offset >= 1, offset <= TunnelConstants.fakeIPPoolSize else { return nil }
            return offset
        }
    }
}
