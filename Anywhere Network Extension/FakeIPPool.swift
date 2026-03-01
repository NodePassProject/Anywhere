//
//  FakeIPPool.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "FakeIPPool")

class FakeIPPool {

    struct Entry {
        let domain: String
        let configuration: VLESSConfiguration?  // nil = DIRECT bypass
        let isDirect: Bool
    }

    // IPv4: 198.18.0.0/15 → offsets 1..131071
    private static let baseIPv4: UInt32 = 0xC612_0000  // 198.18.0.0
    private static let poolSize = 131_071              // usable offsets

    // IPv6: fc00:: + offset (same offset range as IPv4)
    // fc00::1 through fc00::1:ffff

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
    func allocate(domain: String, configuration: VLESSConfiguration?, isDirect: Bool)
        -> (offset: Int, entry: Entry)
    {
        let entry = Entry(domain: domain, configuration: configuration, isDirect: isDirect)

        // Already allocated? Touch LRU and update entry (configuration may have changed)
        if let offset = domainToOffset[domain] {
            offsetToEntry[offset] = entry
            touchLRU(offset)
            return (offset, entry)
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
        offsetToEntry[offset] = entry
        appendLRU(offset)

        let ip = Self.ipv4Bytes(offset: offset)
        logger.debug("[FakeIP] \(domain, privacy: .public) → \(ip.0).\(ip.1).\(ip.2).\(ip.3)")
        return (offset, entry)
    }

    /// Look up an entry by its fake IP string (IPv4 or IPv6).
    func lookup(ip: String) -> Entry? {
        guard let offset = ipToOffset(ip) else { return nil }
        guard let entry = offsetToEntry[offset] else { return nil }
        touchLRU(offset)
        return entry
    }

    /// Clear all mappings (called on full stop).
    func reset() {
        domainToOffset.removeAll()
        offsetToEntry.removeAll()
        offsetToNode.removeAll()
        lruHead = nil
        lruTail = nil
        nextOffset = 1
    }

    /// Updates existing entries' configurations from the current routing rules.
    /// Called on stack restart instead of `reset()` so that apps holding cached fake IPs
    /// (from before the restart) still resolve to valid domain→proxy mappings.
    /// Entries whose domains no longer match any rule are removed.
    func rebuild(using router: DomainRouter) {
        var domainsToRemove: [String] = []

        for (domain, offset) in domainToOffset {
            guard let action = router.matchDomain(domain) else {
                domainsToRemove.append(domain)
                continue
            }

            let isDirect: Bool
            let configuration: VLESSConfiguration?
            switch action {
            case .direct:
                isDirect = true
                configuration = nil
            case .proxy:
                isDirect = false
                configuration = router.resolveConfiguration(action: action)
                if configuration == nil {
                    domainsToRemove.append(domain)
                    continue
                }
            }

            offsetToEntry[offset] = Entry(domain: domain, configuration: configuration, isDirect: isDirect)
        }

        for domain in domainsToRemove {
            if let offset = domainToOffset.removeValue(forKey: domain) {
                offsetToEntry.removeValue(forKey: offset)
                if let node = offsetToNode.removeValue(forKey: offset) {
                    removeNode(node)
                }
            }
        }

        if !domainsToRemove.isEmpty {
            logger.info("[FakeIP] Rebuild: removed \(domainsToRemove.count) stale entries, \(self.domainToOffset.count) active")
        }
    }

    // MARK: - IP ↔ Offset Conversion

    private func ipToOffset(_ ip: String) -> Int? {
        if ip.contains(":") {
            return ipv6ToOffset(ip)
        }
        return ipv4ToOffset(ip)
    }

    private func ipv4ToOffset(_ ip: String) -> Int? {
        let parts = ip.split(separator: ".")
        guard parts.count == 4,
              let a = UInt32(parts[0]), let b = UInt32(parts[1]),
              let c = UInt32(parts[2]), let d = UInt32(parts[3]) else { return nil }
        let ip32 = (a << 24) | (b << 16) | (c << 8) | d
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
        guard let tail = lruTail else { fatalError("evictLRU called on empty list") }
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
