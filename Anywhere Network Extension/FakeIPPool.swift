//
//  FakeIPPool.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "FakeIPPool")

class FakeIPPool {

    struct Entry {
        let domain: String
    }

    // IPv4: 198.18.0.0/15 → offsets 1..131071 available; we cap LRU at a
    // much smaller size so a long-running tunnel can't balloon the three
    // dictionaries that back the pool (~200 B per entry × 3 maps).
    private static let baseIPv4: UInt32 = 0xC612_0000  // 198.18.0.0
    private static let poolSize = 16_384               // usable offsets

    // IPv6: fc00:: + offset (same offset range as IPv4)
    // fc00::1 through fc00::1:ffff

    /// Protects all mutable state (maps, LRU list, nextOffset).
    private let lock = UnfairLock()

    // Bidirectional maps
    private var domainToOffset: [String: Int] = [:]
    private var offsetToEntry: [Int: Entry] = [:]

    // LRU doubly-linked list — O(1) touch/evict (matches Xray-core cache.Lru)
    private class LRUNode {
        let offset: Int
        var prev: LRUNode?
        var next: LRUNode?
        init(offset: Int) { self.offset = offset }
    }
    private var lruHead: LRUNode?  // most recently used
    private var lruTail: LRUNode?  // least recently used
    private var offsetToNode: [Int: LRUNode] = [:]

    private var nextOffset = 1

    // MARK: - Static Helpers

    /// Fast check: is this IP in the fake IPv4 (198.18.0.0/15) or IPv6 (fc00::/18) range?
    static func isFakeIP(_ ip: String) -> Bool {
        ip.hasPrefix("198.18.") || ip.hasPrefix("198.19.") || ip.hasPrefix("fc00::")
    }

    /// Convert an offset to 4-byte IPv4 address.
    static func ipv4Bytes(offset: Int) -> (UInt8, UInt8, UInt8, UInt8) {
        let ip32 = baseIPv4 + UInt32(offset)
        return (
            UInt8((ip32 >> 24) & 0xFF),
            UInt8((ip32 >> 16) & 0xFF),
            UInt8((ip32 >> 8) & 0xFF),
            UInt8(ip32 & 0xFF)
        )
    }

    /// Convert an offset to 16-byte IPv6 address (fc00:: + offset).
    static func ipv6Bytes(offset: Int) -> [UInt8] {
        // fc00:0000:0000:0000:0000:0000:XXXX:XXXX
        return [
            0xFC, 0x00,  // fc00
            0x00, 0x00,  // :0000
            0x00, 0x00,  // :0000
            0x00, 0x00,  // :0000
            0x00, 0x00,  // :0000
            0x00, 0x00,  // :0000
            UInt8((offset >> 24) & 0xFF),
            UInt8((offset >> 16) & 0xFF),
            UInt8((offset >> 8) & 0xFF),
            UInt8(offset & 0xFF),
        ]
    }

    // MARK: - Pool Operations

    /// Allocate (or reuse) an offset for the given domain.
    /// Use `ipv4Bytes(offset:)` or `ipv6Bytes(offset:)` to get the actual address bytes.
    func allocate(domain: String) -> Int {
        lock.withLock {
            // Already allocated? Touch LRU and return existing offset
            if let offset = domainToOffset[domain] {
                touchLRU(offset)
                return offset
            }

            // Need a new offset
            let offset: Int
            if nextOffset <= Self.poolSize {
                offset = nextOffset
                nextOffset += 1
            } else {
                // Pool full — evict LRU
                offset = evictLRU()
            }

            domainToOffset[domain] = offset
            offsetToEntry[offset] = Entry(domain: domain)
            appendLRU(offset)

            return offset
        }
    }

    /// Look up an entry by its fake IP string (IPv4 or IPv6).
    func lookup(ip: String) -> Entry? {
        lock.withLock {
            guard let offset = ipToOffset(ip) else { return nil }
            guard let entry = offsetToEntry[offset] else { return nil }
            touchLRU(offset)
            return entry
        }
    }

    /// Clear all mappings (called on full stop).
    func reset() {
        lock.withLock {
            domainToOffset.removeAll()
            offsetToEntry.removeAll()
            offsetToNode.removeAll()
            lruHead = nil
            lruTail = nil
            nextOffset = 1
        }
    }

    /// Returns the number of active entries.
    var count: Int { lock.withLock { domainToOffset.count } }

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
        let offset = Int(ip32 - Self.baseIPv4)
        guard offset >= 1, offset <= Self.poolSize else { return nil }
        return offset
    }

    private func ipv6ToOffset(_ ip: String) -> Int? {
        var addr = in6_addr()
        guard inet_pton(AF_INET6, ip, &addr) == 1 else { return nil }

        return withUnsafeBytes(of: &addr) { raw -> Int? in
            let bytes = raw.bindMemory(to: UInt8.self)
            guard bytes.count == 16 else { return nil }

            // Verify fc00:: prefix (bytes 0-1 = 0xFC00, bytes 2-11 = 0)
            guard bytes[0] == 0xFC, bytes[1] == 0x00 else { return nil }
            for i in 2...11 {
                guard bytes[i] == 0 else { return nil }
            }

            // Extract offset from bytes 12-15
            let offset = (Int(bytes[12]) << 24) | (Int(bytes[13]) << 16)
                       | (Int(bytes[14]) << 8) | Int(bytes[15])
            guard offset >= 1, offset <= Self.poolSize else { return nil }
            return offset
        }
    }

    // MARK: - LRU Doubly-Linked List (O(1) operations)

    private func touchLRU(_ offset: Int) {
        guard let node = offsetToNode[offset] else { return }
        removeNode(node)
        insertAtHead(node)
    }

    private func appendLRU(_ offset: Int) {
        let node = LRUNode(offset: offset)
        offsetToNode[offset] = node
        insertAtHead(node)
    }

    private func evictLRU() -> Int {
        guard let tail = lruTail else {
            // Should never happen — pool is full so LRU list cannot be empty.
            // Fall back to offset 1 rather than crashing.
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

    private func removeNode(_ node: LRUNode) {
        node.prev?.next = node.next
        node.next?.prev = node.prev
        if node === lruHead { lruHead = node.next }
        if node === lruTail { lruTail = node.prev }
        node.prev = nil
        node.next = nil
    }

    private func insertAtHead(_ node: LRUNode) {
        node.next = lruHead
        node.prev = nil
        lruHead?.prev = node
        lruHead = node
        if lruTail == nil { lruTail = node }
    }
}
