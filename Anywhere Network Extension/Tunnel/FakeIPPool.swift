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
    }

    // IPv4: 198.18.0.0/15, offsets 1...fakeIPPoolSize (LRU-capped).
    // IPv6: 2001:db8::/96 (RFC 3849), offset in low 32 bits. Prefix must stay inside
    // the tunnel's routes or fakes black-hole; rules out ULA.

    private class LRUNode {
        let offset: Int
        var prev: LRUNode?
        var next: LRUNode?
        init(offset: Int) { self.offset = offset }
    }

    /// All mutable state, guarded as one unit so the LRU invariant holds.
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

    /// Is this IP in the fake IPv4 or IPv6 range? A string-prefix check suffices:
    /// lwIP's canonical ntoa always renders fakes with the `2001:db8::` prefix.
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

    func allocate(domain: String) -> Int {
        state.withLock { state in
            if let offset = state.domainToOffset[domain] {
                state.touchLRU(offset)
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
            state.offsetToEntry[offset] = Entry(domain: domain)
            state.appendLRU(offset)

            return offset
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
