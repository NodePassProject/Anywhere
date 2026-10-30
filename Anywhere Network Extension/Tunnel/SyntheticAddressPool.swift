//
//  SyntheticAddressPool.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated final class SyntheticAddressPool: Sendable {
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
    
    static func isSyntheticAddress(_ ip: String) -> Bool {
        ip.hasPrefix("198.18.") || ip.hasPrefix("198.19.")
    }

    static func ipv4Bytes(offset: Int) -> (UInt8, UInt8, UInt8, UInt8) {
        let ip32 = TunnelConstants.syntheticAddressPoolBaseIPv4 + UInt32(offset)
        return (
            UInt8((ip32 >> 24) & 0xFF),
            UInt8((ip32 >> 16) & 0xFF),
            UInt8((ip32 >> 8) & 0xFF),
            UInt8(ip32 & 0xFF)
        )
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
            if state.nextOffset <= TunnelConstants.syntheticAddressPoolSize {
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

    func cachedVerdict(domain: String) -> (match: DomainRouter.Match?, version: UInt64)? {
        state.withLock { state in
            guard let offset = state.domainToOffset[domain],
                  let entry = state.offsetToEntry[offset] else { return nil }
            return (entry.verdict, entry.verdictVersion)
        }
    }

    func lookup(ip: String) -> Entry? {
        state.withLock { state in
            guard let offset = ipv4ToOffset(ip) else { return nil }
            guard let entry = state.offsetToEntry[offset] else { return nil }
            state.touchLRU(offset)
            return entry
        }
    }

    func reset() {
        state.withLock { state in
            var node = state.lruHead
            while let current = node {
                node = current.next
                current.prev = nil
                current.next = nil
            }
            state = State()
        }
    }

    var count: Int { state.withLock { $0.domainToOffset.count } }

    // MARK: - Reject Marks
    
    func markRejected(domain: String) {
        state.withLock { state in
            guard let offset = state.domainToOffset[domain] else { return }
            state.offsetToEntry[offset]?.shouldReject = true
        }
    }
    
    func clearRejectMarks() {
        state.withLock { state in
            for (offset, entry) in state.offsetToEntry where entry.shouldReject {
                state.offsetToEntry[offset]?.shouldReject = false
            }
        }
    }
    
    func isRejectMarked(ipv4 ip32: UInt32) -> Bool {
        guard let offset = Self.offset(ipv4: ip32) else { return false }
        return state.withLock { $0.offsetToEntry[offset]?.shouldReject ?? false }
    }

    // MARK: - IP ↔ Offset Conversion

    private static func offset(ipv4 ip32: UInt32) -> Int? {
        guard ip32 > TunnelConstants.syntheticAddressPoolBaseIPv4 else { return nil }
        let offset = Int(ip32 - TunnelConstants.syntheticAddressPoolBaseIPv4)
        guard offset <= TunnelConstants.syntheticAddressPoolSize else { return nil }
        return offset
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
        return Self.offset(ipv4: ip32)
    }
}
