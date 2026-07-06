//
//  TieredRouteMatcher.swift
//  Anywhere
//
//  Created by NodePassProject on 7/6/26.
//

import Foundation

// MARK: - Tiered route matching core
//
// The matching engine behind routing decisions, shared between the Network
// Extension's DomainRouter (hot path — lookups on the lwIP and UDP queues)
// and the host app's RouteAttributor (which replays decisions to label them
// with rule sets). One implementation, two payloads: the extension stores
// bare `RouteTarget`s, the app attaches rule-set identity. Matchers intern
// payloads to `Int16` IDs so nodes stay small either way.
//
// Semantics: within a tier, suffix beats keyword and the deepest suffix /
// longest keyword wins, later insertion breaking ties; CIDR is longest-prefix
// with more-specific prefixes winning and duplicates overwriting. Tier
// priority is query order — matchDomain/matchIP walk tiers by index, first
// hit wins.

nonisolated enum MatcherID {
    static let none: Int16 = -1
}

/// Interning payloads (a ~32 B `RouteTarget`, or the app's larger attributed
/// form) down to `Int16` IDs keeps matcher nodes small.
nonisolated struct PayloadTable<Payload: Hashable> {
    private var payloads: [Payload] = []
    private var ids: [Payload: Int16] = [:]

    mutating func intern(_ payload: Payload) -> Int16 {
        if let id = ids[payload] { return id }
        let id = Int16(payloads.count)
        payloads.append(payload)
        ids[payload] = id
        return id
    }

    func resolve(_ id: Int16) -> Payload? {
        let index = Int(id)
        guard index >= 0, index < payloads.count else { return nil }
        return payloads[index]
    }
}

// MARK: - Keyword automaton

/// Aho–Corasick automaton for `domainKeyword`: longest substring match in one
/// O(D) walk. `finalize()` flattens the build tree into BFS-ordered flat columns
/// plus CSR edges; inserting after it traps.
///
/// `@unchecked Sendable`: immutable once finalized (the build tree is dropped
/// and `insert` traps); finalize before crossing isolation domains.
nonisolated final class KeywordAutomaton: @unchecked Sendable {

    // MARK: Build state (dropped on finalize)

    private final class BuildNode {
        var children: [UInt8: BuildNode] = [:]
        var failure: BuildNode?
        /// Nearest accepting ancestor via failure links; lets lookup skip the full failure chain.
        var dictSuffix: BuildNode?
        var actionID: Int16 = MatcherID.none
        var patternLength: UInt16 = 0
        var insertionOrder: Int32 = 0
        /// Assigned during BFS layout; -1 until then.
        var nodeID: Int32 = -1
    }

    private var buildRoot: BuildNode? = BuildNode()
    private var insertionCounter: Int32 = 0
    private var finalized = false

    // MARK: Frozen state (populated by finalize)

    /// Per-node columns. Indexed by `0..<failure.count`; root is index 0.
    /// `dictSuffix[i] == -1` means "no accepting ancestor".
    private var failure: ContiguousArray<Int32> = []
    private var dictSuffix: ContiguousArray<Int32> = []
    private var actionID: ContiguousArray<Int16> = []
    private var patternLength: ContiguousArray<UInt16> = []
    private var insertionOrder: ContiguousArray<Int32> = []

    /// CSR edges: node `i`'s edges live at `[edgeStart[i], edgeStart[i + 1])`, sorted by byte.
    private var edgeStart: ContiguousArray<Int32> = []
    private var edgeByte: ContiguousArray<UInt8> = []
    private var edgeTarget: ContiguousArray<Int32> = []

    // MARK: Build API

    func insert(_ pattern: String, actionID: Int16) {
        guard !pattern.isEmpty else { return }
        let bytes = Array(pattern.utf8)
        // RFC 1035 caps domains at 253 octets; anything past UInt16.max is garbage — drop silently.
        guard bytes.count <= Int(UInt16.max) else { return }

        var node = buildRoot!
        for b in bytes {
            if let child = node.children[b] {
                node = child
            } else {
                let child = BuildNode()
                node.children[b] = child
                node = child
            }
        }
        insertionCounter += 1
        node.actionID = actionID
        node.patternLength = UInt16(bytes.count)
        node.insertionOrder = insertionCounter
    }

    // MARK: Finalize

    /// Builds failure/dictSuffix links and freezes the flat columns.
    /// Idempotent; subsequent inserts trap.
    func finalize() {
        guard !finalized else { return }
        guard let root = buildRoot else {
            finalized = true
            return
        }

        // Failure links point at strictly shallower depth, so BFS order lays out a
        // child's failure target first; sorted-byte children keep CSR rows sorted.
        var queue: [BuildNode] = []
        queue.reserveCapacity(64)
        root.nodeID = 0
        queue.append(root)

        var nFailure: [Int32] = [0]                       // root's failure is itself
        var nDictSuffix: [Int32] = [-1]
        var nActionID: [Int16] = [root.actionID]
        var nPatternLength: [UInt16] = [root.patternLength]
        var nInsertionOrder: [Int32] = [root.insertionOrder]
        var edgeStarts: [Int32] = [0]
        var edgeBytes: [UInt8] = []
        var edgeTargets: [Int32] = []

        var head = 0
        while head < queue.count {
            let node = queue[head]; head += 1

            let sortedChildren = node.children.sorted { $0.key < $1.key }
            for (byte, childNode) in sortedChildren {
                // Standard AC failure: nearest ancestor-of-failure with a
                // `byte` child (≠ childNode), else root. node.failure is nil only for root.
                var f = node.failure
                while let current = f, current.children[byte] == nil, current !== root {
                    f = current.failure
                }
                if let current = f, let next = current.children[byte], next !== childNode {
                    childNode.failure = next
                } else {
                    childNode.failure = root
                }
                childNode.dictSuffix = (childNode.failure?.actionID ?? MatcherID.none) != MatcherID.none
                    ? childNode.failure
                    : childNode.failure?.dictSuffix

                let childID = Int32(nFailure.count)
                childNode.nodeID = childID
                queue.append(childNode)

                nFailure.append(childNode.failure!.nodeID)
                nDictSuffix.append(childNode.dictSuffix?.nodeID ?? -1)
                nActionID.append(childNode.actionID)
                nPatternLength.append(childNode.patternLength)
                nInsertionOrder.append(childNode.insertionOrder)

                edgeBytes.append(byte)
                edgeTargets.append(childID)
            }
            edgeStarts.append(Int32(edgeBytes.count))
        }

        failure = ContiguousArray(nFailure)
        dictSuffix = ContiguousArray(nDictSuffix)
        actionID = ContiguousArray(nActionID)
        patternLength = ContiguousArray(nPatternLength)
        insertionOrder = ContiguousArray(nInsertionOrder)
        edgeStart = ContiguousArray(edgeStarts)
        edgeByte = ContiguousArray(edgeBytes)
        edgeTarget = ContiguousArray(edgeTargets)

        buildRoot = nil
        finalized = true
    }

    // MARK: Read API

    /// Best-matching action ID, or `MatcherID.none` when no pattern matches.
    func lookup(_ domain: UnsafeBufferPointer<UInt8>) -> Int16 {
        // Empty edge table means nothing was inserted; skip the walk for keyword-free tiers.
        guard finalized, !edgeByte.isEmpty else { return MatcherID.none }

        var bestID: Int16 = MatcherID.none
        var bestLength: UInt16 = 0
        var bestOrder: Int32 = -1
        var nodeID: Int32 = 0

        for byte in domain {
            var nextID = childTarget(nodeID: nodeID, byte: byte)
            while nextID < 0 && nodeID != 0 {
                nodeID = failure[Int(nodeID)]
                nextID = childTarget(nodeID: nodeID, byte: byte)
            }
            if nextID >= 0 { nodeID = nextID }

            // Enumerate accepting nodes via the dictSuffix chain.
            var hit: Int32 = nodeID
            while hit >= 0 {
                let aid = actionID[Int(hit)]
                if aid != MatcherID.none {
                    let plen = patternLength[Int(hit)]
                    let pord = insertionOrder[Int(hit)]
                    if plen > bestLength || (plen == bestLength && pord > bestOrder) {
                        bestID = aid
                        bestLength = plen
                        bestOrder = pord
                    }
                }
                hit = dictSuffix[Int(hit)]
            }
        }
        return bestID
    }

    /// Edge target for `byte` from `nodeID`, or -1; rows are sorted so the scan exits early.
    private func childTarget(nodeID: Int32, byte: UInt8) -> Int32 {
        let start = Int(edgeStart[Int(nodeID)])
        let end = Int(edgeStart[Int(nodeID) + 1])
        var i = start
        while i < end {
            let candidateByte = edgeByte[i]
            if candidateByte == byte { return edgeTarget[i] }
            if candidateByte > byte { return -1 }
            i += 1
        }
        return -1
    }
}

// MARK: - Per-tier matchers

nonisolated struct TierMatchers<Payload: Hashable> {
    /// Per-tier interner; matchers store `Int16` IDs resolved back at the tier boundary.
    var payloadTable = PayloadTable<Payload>()

    var suffixTrie = FlatLabelTrie<Int16>()
    var keywordAutomaton = KeywordAutomaton()
    var ipv4Trie = CIDRv4Trie()
    var ipv6Trie = CIDRv6Trie()
    var domainRuleCount = 0
    var ipRuleCount = 0

    /// Suffix rules are buffered as `(byte range into the caller's base buffer,
    /// interned payload)`. This skips the scratch node tree and its per-node dictionary.
    var suffixRecords: [FlatLabelTrie<Int16>.BulkEntry] = []

    var isEmpty: Bool { domainRuleCount == 0 && ipRuleCount == 0 }

    /// `offset`/`length` index into the caller's base buffer, which stays
    /// valid until `finalize` copies the matched label bytes out.
    mutating func collectSuffix(offset: Int, length: Int, payload: Payload) {
        suffixRecords.append(.init(offset: Int32(offset), length: Int32(length),
                                   payload: payloadTable.intern(payload), order: Int32(suffixRecords.count)))
        domainRuleCount += 1
    }

    mutating func insertKeyword(_ pattern: String, payload: Payload) {
        guard !pattern.isEmpty else { return }
        keywordAutomaton.insert(pattern, actionID: payloadTable.intern(payload))
        domainRuleCount += 1
    }

    mutating func reserveIPv4(additionalPrefixes: Int) { ipv4Trie.reserveForAdditionalPrefixes(additionalPrefixes) }
    mutating func reserveIPv6(additionalPrefixes: Int) { ipv6Trie.reserveForAdditionalPrefixes(additionalPrefixes) }

    mutating func insertIPv4(network: UInt32, prefixLen: Int, payload: Payload) {
        ipv4Trie.insert(network: network, prefixLen: prefixLen, actionID: payloadTable.intern(payload))
        ipRuleCount += 1
    }

    mutating func insertIPv6(network: [UInt8], prefixLen: Int, payload: Payload) {
        ipv6Trie.insert(network: network, prefixLen: prefixLen, actionID: payloadTable.intern(payload))
        ipRuleCount += 1
    }

    mutating func finalize(base: UnsafeBufferPointer<UInt8>) {
        keywordAutomaton.finalize()
        suffixTrie.buildBulk(base: base, entries: &suffixRecords)
        suffixRecords = []
    }

    /// Suffix wins over keyword.
    func lookupDomain(_ domain: UnsafeBufferPointer<UInt8>) -> Payload? {
        if let id = suffixTrie.lookup(domain) {
            return payloadTable.resolve(id)
        }
        let keywordActionID = keywordAutomaton.lookup(domain)
        return keywordActionID == MatcherID.none ? nil : payloadTable.resolve(keywordActionID)
    }

    func lookupIPv4(_ ip: UInt32) -> Payload? {
        let id = ipv4Trie.lookup(ip)
        return id == MatcherID.none ? nil : payloadTable.resolve(id)
    }

    func lookupIPv6(hi: UInt64, lo: UInt64) -> Payload? {
        let id = ipv6Trie.lookup(hi: hi, lo: lo)
        return id == MatcherID.none ? nil : payloadTable.resolve(id)
    }
}

// MARK: - Tiered matcher

nonisolated struct TieredRouteMatcher<Payload: Hashable> {
    var tiers: [TierMatchers<Payload>]

    init(tierCount: Int) {
        tiers = (0..<tierCount).map { _ in TierMatchers() }
    }

    var hasRules: Bool {
        for i in tiers.indices where !tiers[i].isEmpty { return true }
        return false
    }

    mutating func finalize(base: UnsafeBufferPointer<UInt8>) {
        for i in tiers.indices { tiers[i].finalize(base: base) }
    }

    /// Matches a domain by walking tiers in priority order. First hit wins.
    /// Folds the query itself; callers that fold outside a lock use
    /// ``matchDomain(bytes:)`` directly.
    func matchDomain(_ domain: String) -> Payload? {
        guard !domain.isEmpty else { return nil }
        var lowered = RouteMatching.asciiLowercasedIfNeeded(domain)
        return lowered.withUTF8 { matchDomain(bytes: $0) }
    }

    /// Iterates by index so the per-tier `TierMatchers` value isn't copied on each lookup.
    func matchDomain(bytes: UnsafeBufferPointer<UInt8>) -> Payload? {
        for i in tiers.indices {
            if let payload = tiers[i].lookupDomain(bytes) { return payload }
        }
        return nil
    }

    /// Matches an IP address against per-tier CIDR tries in priority order.
    func matchIP(_ ip: String) -> Payload? {
        guard !ip.isEmpty else { return nil }

        if ip.contains(":") {
            var address = in6_addr()
            guard inet_pton(AF_INET6, ip, &address) == 1 else { return nil }
            // Pack to a 128-bit pair once; reuse across tiers.
            let (hi, lo) = withUnsafeBytes(of: &address) { raw -> (UInt64, UInt64) in
                CIDRv6Trie.pack16(raw.bindMemory(to: UInt8.self))
            }
            for i in tiers.indices {
                if let payload = tiers[i].lookupIPv6(hi: hi, lo: lo) { return payload }
            }
            return nil
        } else {
            guard let ipv4Address = RouteMatching.parseIPv4(ip) else { return nil }
            for i in tiers.indices {
                if let payload = tiers[i].lookupIPv4(ipv4Address) { return payload }
            }
            return nil
        }
    }
}

// MARK: - Folding & CIDR parsing

nonisolated enum RouteMatching {

    /// Returns the input unchanged (no allocation) when already lowercase ASCII;
    /// otherwise falls back to `lowercased()` to match load-time folding.
    static func asciiLowercasedIfNeeded(_ input: String) -> String {
        for b in input.utf8 where (b >= 0x41 && b <= 0x5A) || b >= 0x80 {
            return input.lowercased()
        }
        return input
    }

    /// Parses "A.B.C.D/prefix" into (network, prefixLen) with host bits zeroed.
    static func parseIPv4CIDR(_ cidr: String) -> (network: UInt32, prefixLen: Int)? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefixLen = Int(parts[1]),
              prefixLen >= 0, prefixLen <= 32,
              let ip = parseIPv4(String(parts[0])) else { return nil }
        let mask: UInt32 = prefixLen == 0 ? 0 : ~UInt32(0) << (32 - prefixLen)
        return (network: ip & mask, prefixLen: prefixLen)
    }

    /// Parses a dotted-quad IPv4 string to host-order UInt32.
    static func parseIPv4(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".", maxSplits: 4, omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard let byte = UInt8(part) else { return nil }
            result = result << 8 | UInt32(byte)
        }
        return result
    }

    static func parseIPv6CIDR(_ cidr: String) -> (network: [UInt8], prefixLen: Int)? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefixLen = Int(parts[1]),
              prefixLen >= 0, prefixLen <= 128 else { return nil }

        var address = in6_addr()
        guard inet_pton(AF_INET6, String(parts[0]), &address) == 1 else { return nil }

        var network = withUnsafeBytes(of: &address) { Array($0.bindMemory(to: UInt8.self)) }
        // Zero host bits
        for i in 0..<16 {
            let bitPos = i * 8
            if bitPos >= prefixLen {
                network[i] = 0
            } else if bitPos + 8 > prefixLen {
                let keep = prefixLen - bitPos
                network[i] &= ~UInt8(0) << (8 - keep)
            }
        }
        return (network: network, prefixLen: prefixLen)
    }
}

// MARK: - CIDR Patricia tries
//
// Path-compressed binary tries for longest-prefix match, nodes in one contiguous
// arena; v4 and v6 are separate types so the v4 hot loop avoids 128-bit shifts.

nonisolated struct CIDRv4Trie {
    /// 4 + 4 + 4 + 2 + 1 + 1 padding = 16 bytes, 4-byte aligned.
    private struct Node {
        var bits: UInt32 = 0        // MSB-aligned edge bits; bits past `bitLen` are zero
        var left: Int32 = -1        // index into `nodes`, or -1 for none
        var right: Int32 = -1
        var actionID: Int16 = MatcherID.none
        var bitLen: UInt8 = 0       // 0…32
    }

    private var nodes: [Node] = [Node()]

    /// Reserves headroom for `prefixes` more insertions so a bulk load skips the doubling reallocations.
    /// A path-compressed binary trie holds at most 2N-1 nodes for N disjoint prefixes, so 2× is safe.
    mutating func reserveForAdditionalPrefixes(_ prefixes: Int) {
        guard prefixes > 0 else { return }
        nodes.reserveCapacity(nodes.count + 2 * prefixes)
    }

    // MARK: - Insert

    /// More-specific prefixes win at lookup; duplicate prefixes overwrite.
    mutating func insert(network: UInt32, prefixLen: Int, actionID: Int16) {
        let length = UInt8(prefixLen)
        let bits = Self.maskTop(network, length)
        insertCore(bits: bits, bitLen: length, actionID: actionID)
    }

    // MARK: - Lookup

    /// Deepest action along the path, or `MatcherID.none`. Reads each child once
    /// into a local to avoid bounds-checked subscripts on the hot path.
    func lookup(_ ip: UInt32) -> Int16 {
        nodes.withUnsafeBufferPointer { buffer in
            var bits = ip
            var remaining: UInt8 = 32
            var nodeID = 0
            var deepest = buffer[0].actionID

            while remaining > 0 {
                let firstBit = bits >> 31
                let childID = (firstBit == 0) ? buffer[nodeID].left : buffer[nodeID].right
                if childID < 0 { return deepest }

                let child = buffer[Int(childID)]
                let commonPrefixLen = Self.lcp(bits, child.bits, cap: min(remaining, child.bitLen))
                if commonPrefixLen < child.bitLen { return deepest }

                bits = Self.shiftLeft(bits, child.bitLen)
                remaining -= child.bitLen
                nodeID = Int(childID)
                if child.actionID != MatcherID.none { deepest = child.actionID }
            }

            return deepest
        }
    }

    // MARK: - Patricia core

    private mutating func insertCore(bits: UInt32, bitLen: UInt8, actionID: Int16) {
        var workingBits = bits
        var remaining = bitLen
        var nodeID: Int32 = 0

        while remaining > 0 {
            let firstBit = UInt8(workingBits >> 31)
            let childID = (firstBit == 0) ? nodes[Int(nodeID)].left : nodes[Int(nodeID)].right

            if childID < 0 {
                let leafID = makeLeaf(bits: workingBits, bitLen: remaining, actionID: actionID)
                if firstBit == 0 { nodes[Int(nodeID)].left = leafID }
                else { nodes[Int(nodeID)].right = leafID }
                return
            }

            let childBits = nodes[Int(childID)].bits
            let childBitLen = nodes[Int(childID)].bitLen
            let lcp = Self.lcp(workingBits, childBits, cap: min(remaining, childBitLen))

            if lcp == childBitLen {
                workingBits = Self.shiftLeft(workingBits, lcp)
                remaining -= lcp
                nodeID = childID
                continue
            }

            // Partial match: split `child`'s edge at position `lcp`.
            let midBits = Self.maskTop(childBits, lcp)
            let existingNewBits = Self.shiftLeft(childBits, lcp)

            var mid = Node()
            mid.bits = midBits
            mid.bitLen = lcp
            let midID = Int32(nodes.count)
            nodes.append(mid)

            // Rewrite the existing child to carry only the tail of its edge.
            nodes[Int(childID)].bits = existingNewBits
            nodes[Int(childID)].bitLen = childBitLen - lcp

            if UInt8(existingNewBits >> 31) == 0 { nodes[Int(midID)].left = childID }
            else { nodes[Int(midID)].right = childID }

            let newBits = Self.shiftLeft(workingBits, lcp)
            let newRemaining = remaining - lcp
            if newRemaining == 0 {
                nodes[Int(midID)].actionID = actionID
            } else {
                let leafID = makeLeaf(bits: newBits, bitLen: newRemaining, actionID: actionID)
                if UInt8(newBits >> 31) == 0 { nodes[Int(midID)].left = leafID }
                else { nodes[Int(midID)].right = leafID }
            }

            if firstBit == 0 { nodes[Int(nodeID)].left = midID }
            else { nodes[Int(nodeID)].right = midID }
            return
        }

        // Key fully consumed; payload attaches to the current node.
        nodes[Int(nodeID)].actionID = actionID
    }

    private mutating func makeLeaf(bits: UInt32, bitLen: UInt8, actionID: Int16) -> Int32 {
        var leaf = Node()
        leaf.bits = bits
        leaf.bitLen = bitLen
        leaf.actionID = actionID
        let id = Int32(nodes.count)
        nodes.append(leaf)
        return id
    }

    // MARK: - 32-bit bit ops

    /// Shift left, capped at 32 bits (returns 0 when `n >= 32`).
    private static func shiftLeft(_ bits: UInt32, _ n: UInt8) -> UInt32 {
        if n == 0 { return bits }
        if n >= 32 { return 0 }
        return bits << n
    }

    /// Keep only the top `n` bits; zero the rest.
    private static func maskTop(_ bits: UInt32, _ n: UInt8) -> UInt32 {
        if n == 0 { return 0 }
        if n >= 32 { return bits }
        return bits & (~UInt32(0) << (32 - n))
    }

    /// Longest common prefix of two MSB-aligned 32-bit edges, capped at `cap`.
    private static func lcp(_ a: UInt32, _ b: UInt32, cap: UInt8) -> UInt8 {
        if cap == 0 { return 0 }
        let d = a ^ b
        if d == 0 { return cap }
        return min(cap, UInt8(d.leadingZeroBitCount))
    }
}

nonisolated struct CIDRv6Trie {
    /// 8 + 8 + 4 + 4 + 2 + 1 + 5 padding = 32 bytes, 8-byte aligned. Edge bits are
    /// MSB-first across (bitsHi, bitsLo); bits past `bitLen` stay zero by invariant.
    private struct Node {
        var bitsHi: UInt64 = 0
        var bitsLo: UInt64 = 0
        var left: Int32 = -1
        var right: Int32 = -1
        var actionID: Int16 = MatcherID.none
        var bitLen: UInt8 = 0       // 0…128
    }

    private var nodes: [Node] = [Node()]

    /// Reserves headroom for `prefixes` more insertions ahead of a bulk load; see the v4 counterpart.
    mutating func reserveForAdditionalPrefixes(_ prefixes: Int) {
        guard prefixes > 0 else { return }
        nodes.reserveCapacity(nodes.count + 2 * prefixes)
    }

    // MARK: - Insert

    mutating func insert(network: [UInt8], prefixLen: Int, actionID: Int16) {
        let (hi, lo) = network.withUnsafeBufferPointer { Self.pack16($0) }
        let length = UInt8(prefixLen)
        let (mHi, mLo) = Self.maskTop(hi, lo, length)
        insertCore(bitsHi: mHi, bitsLo: mLo, bitLen: length, actionID: actionID)
    }

    // MARK: - Lookup

    /// Deepest action along the path for a packed 128-bit address, or `MatcherID.none`.
    func lookup(hi hi0: UInt64, lo lo0: UInt64) -> Int16 {
        nodes.withUnsafeBufferPointer { buffer in
            var hi = hi0
            var lo = lo0
            var remaining: UInt8 = 128
            var nodeID = 0
            var deepest = buffer[0].actionID

            while remaining > 0 {
                let firstBit = hi >> 63
                let childID = (firstBit == 0) ? buffer[nodeID].left : buffer[nodeID].right
                if childID < 0 { return deepest }

                let child = buffer[Int(childID)]
                let lcp = Self.lcp(
                    aHi: hi, aLo: lo, aLen: remaining,
                    bHi: child.bitsHi, bLo: child.bitsLo, bLen: child.bitLen
                )
                if lcp < child.bitLen { return deepest }

                (hi, lo) = Self.shiftLeft(hi, lo, child.bitLen)
                remaining -= child.bitLen
                nodeID = Int(childID)
                if child.actionID != MatcherID.none { deepest = child.actionID }
            }

            return deepest
        }
    }

    // MARK: - Patricia core

    private mutating func insertCore(bitsHi: UInt64, bitsLo: UInt64, bitLen: UInt8, actionID: Int16) {
        var hi = bitsHi
        var lo = bitsLo
        var remaining = bitLen
        var nodeID: Int32 = 0

        while remaining > 0 {
            let firstBit = UInt8(hi >> 63)
            let childID = (firstBit == 0) ? nodes[Int(nodeID)].left : nodes[Int(nodeID)].right

            if childID < 0 {
                let leafID = makeLeaf(bitsHi: hi, bitsLo: lo, bitLen: remaining, actionID: actionID)
                if firstBit == 0 { nodes[Int(nodeID)].left = leafID }
                else { nodes[Int(nodeID)].right = leafID }
                return
            }

            let childBitsHi = nodes[Int(childID)].bitsHi
            let childBitsLo = nodes[Int(childID)].bitsLo
            let childBitLen = nodes[Int(childID)].bitLen
            let lcp = Self.lcp(
                aHi: hi, aLo: lo, aLen: remaining,
                bHi: childBitsHi, bLo: childBitsLo, bLen: childBitLen
            )

            if lcp == childBitLen {
                (hi, lo) = Self.shiftLeft(hi, lo, lcp)
                remaining -= lcp
                nodeID = childID
                continue
            }

            let (midHi, midLo) = Self.maskTop(childBitsHi, childBitsLo, lcp)
            let (existingNewHi, existingNewLo) = Self.shiftLeft(childBitsHi, childBitsLo, lcp)

            var mid = Node()
            mid.bitsHi = midHi
            mid.bitsLo = midLo
            mid.bitLen = lcp
            let midID = Int32(nodes.count)
            nodes.append(mid)

            nodes[Int(childID)].bitsHi = existingNewHi
            nodes[Int(childID)].bitsLo = existingNewLo
            nodes[Int(childID)].bitLen = childBitLen - lcp

            if UInt8(existingNewHi >> 63) == 0 { nodes[Int(midID)].left = childID }
            else { nodes[Int(midID)].right = childID }

            let (newHi, newLo) = Self.shiftLeft(hi, lo, lcp)
            let newRemaining = remaining - lcp
            if newRemaining == 0 {
                nodes[Int(midID)].actionID = actionID
            } else {
                let leafID = makeLeaf(bitsHi: newHi, bitsLo: newLo, bitLen: newRemaining, actionID: actionID)
                if UInt8(newHi >> 63) == 0 { nodes[Int(midID)].left = leafID }
                else { nodes[Int(midID)].right = leafID }
            }

            if firstBit == 0 { nodes[Int(nodeID)].left = midID }
            else { nodes[Int(nodeID)].right = midID }
            return
        }

        nodes[Int(nodeID)].actionID = actionID
    }

    private mutating func makeLeaf(bitsHi: UInt64, bitsLo: UInt64, bitLen: UInt8, actionID: Int16) -> Int32 {
        var leaf = Node()
        leaf.bitsHi = bitsHi
        leaf.bitsLo = bitsLo
        leaf.bitLen = bitLen
        leaf.actionID = actionID
        let id = Int32(nodes.count)
        nodes.append(leaf)
        return id
    }

    // MARK: - 128-bit bit ops

    private static func shiftLeft(_ hi: UInt64, _ lo: UInt64, _ amount: UInt8) -> (UInt64, UInt64) {
        let n = Int(amount)
        if n == 0 { return (hi, lo) }
        if n >= 128 { return (0, 0) }
        if n >= 64 { return (lo << (n - 64), 0) }
        return ((hi << n) | (lo >> (64 - n)), lo << n)
    }

    private static func maskTop(_ hi: UInt64, _ lo: UInt64, _ n: UInt8) -> (UInt64, UInt64) {
        let count = Int(n)
        if count == 0 { return (0, 0) }
        if count >= 128 { return (hi, lo) }
        if count <= 64 {
            let mask: UInt64 = (count == 64) ? ~0 : ~UInt64(0) << (64 - count)
            return (hi & mask, 0)
        }
        let mask = ~UInt64(0) << (128 - count)
        return (hi, lo & mask)
    }

    private static func lcp(aHi: UInt64, aLo: UInt64, aLen: UInt8,
                            bHi: UInt64, bLo: UInt64, bLen: UInt8) -> UInt8 {
        let cap = min(aLen, bLen)
        if cap == 0 { return 0 }
        let dHi = aHi ^ bHi
        if dHi != 0 { return min(cap, UInt8(dHi.leadingZeroBitCount)) }
        let dLo = aLo ^ bLo
        if dLo != 0 { return min(cap, 64 + UInt8(dLo.leadingZeroBitCount)) }
        return cap
    }

    /// Packs up to 16 big-endian bytes into a (hi, lo) 128-bit pair.
    static func pack16(_ buf: UnsafeBufferPointer<UInt8>) -> (UInt64, UInt64) {
        var hi: UInt64 = 0
        var lo: UInt64 = 0
        let count = min(16, buf.count)
        for i in 0..<count {
            let byte = UInt64(buf[i])
            if i < 8 {
                hi |= byte << ((7 - i) * 8)
            } else {
                lo |= byte << ((7 - (i - 8)) * 8)
            }
        }
        return (hi, lo)
    }
}
