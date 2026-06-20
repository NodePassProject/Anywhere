//
//  DomainRouter.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "DomainRouter")

class DomainRouter {

    // MARK: - Tier model
    //
    // Cross-source priority is tier query order (User > ADBlock > Built-in > Country
    // Bypass); within a tier, suffix beats keyword and deepest/longest match wins.

    // MARK: - Action interning (see fileprivate `ActionTable` below)

    // MARK: - Keyword automaton

    /// Aho–Corasick automaton for `domainKeyword`: longest substring match in one
    /// O(D) walk. `finalize()` flattens the build tree into BFS-ordered flat columns
    /// plus CSR edges; inserting after it traps.
    private final class KeywordAutomaton {

        // MARK: Build state (dropped on finalize)

        private final class BuildNode {
            var children: [UInt8: BuildNode] = [:]
            var failure: BuildNode?
            /// Nearest accepting ancestor via failure links; lets lookup skip the full failure chain.
            var dictSuffix: BuildNode?
            var actionID: Int16 = ActionTable.noneID
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
                    childNode.dictSuffix = (childNode.failure?.actionID ?? ActionTable.noneID) != ActionTable.noneID
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

        /// Best-matching action ID, or `ActionTable.noneID` when no pattern matches.
        func lookup(_ domain: UnsafeBufferPointer<UInt8>) -> Int16 {
            // Empty edge table means nothing was inserted; skip the walk for keyword-free tiers.
            guard finalized, !edgeByte.isEmpty else { return ActionTable.noneID }

            var bestID: Int16 = ActionTable.noneID
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
                    if aid != ActionTable.noneID {
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

    // MARK: - Tier state

    private struct TierMatchers {
        /// Per-tier interner; matchers store `Int16` IDs resolved back at the tier boundary.
        var actionTable = ActionTable()

        var suffixTrie = FlatLabelTrie<Int16>()
        var keywordAutomaton = KeywordAutomaton()
        var ipv4Trie = CIDRv4Trie()
        var ipv6Trie = CIDRv6Trie()
        var domainRuleCount = 0
        var ipRuleCount = 0

        /// Suffix rules are buffered as `(byte range into the payload, interned action)`.
        /// This skips the scratch node tree and its per-node dictionary.
        var suffixRecords: [FlatLabelTrie<Int16>.BulkEntry] = []

        var isEmpty: Bool { domainRuleCount == 0 && ipRuleCount == 0 }

        /// `offset`/`length` index into the mapped routing payload, which stays
        /// valid until `finalize` copies the matched label bytes out.
        mutating func collectSuffix(offset: Int, length: Int, action: RouteTarget) {
            suffixRecords.append(.init(offset: Int32(offset), length: Int32(length),
                                       payload: actionTable.intern(action), order: Int32(suffixRecords.count)))
            domainRuleCount += 1
        }

        mutating func insertKeyword(_ pattern: String, action: RouteTarget) {
            guard !pattern.isEmpty else { return }
            keywordAutomaton.insert(pattern, actionID: actionTable.intern(action))
            domainRuleCount += 1
        }

        mutating func insertIPv4(network: UInt32, prefixLen: Int, action: RouteTarget) {
            ipv4Trie.insert(network: network, prefixLen: prefixLen, actionID: actionTable.intern(action))
            ipRuleCount += 1
        }

        mutating func insertIPv6(network: [UInt8], prefixLen: Int, action: RouteTarget) {
            ipv6Trie.insert(network: network, prefixLen: prefixLen, actionID: actionTable.intern(action))
            ipRuleCount += 1
        }
        
        mutating func finalize(base: UnsafeBufferPointer<UInt8>) {
            keywordAutomaton.finalize()
            suffixTrie.buildBulk(base: base, entries: &suffixRecords)
            suffixRecords = []
        }

        /// Suffix wins over keyword.
        func lookupDomain(_ domain: UnsafeBufferPointer<UInt8>) -> RouteTarget? {
            if let id = suffixTrie.lookup(domain) {
                return actionTable.resolve(id)
            }
            let keywordActionID = keywordAutomaton.lookup(domain)
            return keywordActionID == ActionTable.noneID ? nil : actionTable.resolve(keywordActionID)
        }

        func lookupIPv4(_ ip: UInt32) -> RouteTarget? {
            let id = ipv4Trie.lookup(ip)
            return id == ActionTable.noneID ? nil : actionTable.resolve(id)
        }

        func lookupIPv6(hi: UInt64, lo: UInt64) -> RouteTarget? {
            let id = ipv6Trie.lookup(hi: hi, lo: lo)
            return id == ActionTable.noneID ? nil : actionTable.resolve(id)
        }
    }

    // Tiers in priority order — first hit wins.
    private enum Tier: Int, CaseIterable {
        case user = 0
        case adBlock = 1
        case builtIn = 2
        case bypass = 3
    }

    private var tiers: [TierMatchers] = Tier.allCases.map { _ in TierMatchers() }

    private var configurationMap: [UUID: ProxyConfiguration] = [:]

    /// Guards `tiers` + `configurationMap` (lookups run on both the lwIP and UDP queues);
    /// reloads hold the lock across the whole compile so a lookup never sees a half-built tier.
    private let routingLock = UnfairLock()

    // MARK: - Loading

    /// Clears all rules and configurations (e.g. when switching to global mode).
    func reset() {
        routingLock.withLock { resetUnlocked() }
    }

    /// Caller must hold ``routingLock``.
    private func resetUnlocked() {
        tiers = Tier.allCases.map { _ in TierMatchers() }
        configurationMap.removeAll()
    }

    /// Compiles rules from the App Group routing file into per-tier matchers under `routingLock`.
    func loadRoutingConfiguration() {
        routingLock.withLock { loadRoutingConfigurationLocked() }
    }

    private func loadRoutingConfigurationLocked() {
        resetUnlocked()

        guard let data = AWCore.getRoutingData() else {
            logger.debug("[DomainRouter] No routing data available")
            return
        }
        
        do {
            try data.withUnsafeBytes { raw in
                let base = raw.bindMemory(to: UInt8.self)
                var reader = RoutingBinaryReader(bytes: base, data: data, owner: self)
                try reader.run()
                for i in tiers.indices { tiers[i].finalize(base: base) }
            }
        } catch {
            resetUnlocked()
            logger.error("[DomainRouter] Routing payload parse failed: \(error)")
            return
        }

        logger.debug("[DomainRouter] Loaded tiers — user: \(self.tiers[Tier.user.rawValue].domainRuleCount)+\(self.tiers[Tier.user.rawValue].ipRuleCount), adBlock: \(self.tiers[Tier.adBlock.rawValue].domainRuleCount)+\(self.tiers[Tier.adBlock.rawValue].ipRuleCount), builtIn: \(self.tiers[Tier.builtIn.rawValue].domainRuleCount)+\(self.tiers[Tier.builtIn.rawValue].ipRuleCount), bypass: \(self.tiers[Tier.bypass.rawValue].domainRuleCount)+\(self.tiers[Tier.bypass.rawValue].ipRuleCount); \(self.configurationMap.count) configurations")
    }

    // MARK: - Streaming ingestion
    
    fileprivate func ingestConfigurations(_ slice: Data) {
        guard let configurations = try? JSONDecoder().decode([String: ProxyConfiguration].self, from: slice) else { return }
        for (key, configuration) in configurations {
            guard let configurationId = UUID(uuidString: key) else { continue }
            configurationMap[configurationId] = configuration
        }
    }
    
    fileprivate func ingestRule(tierIndex: Int, action: RouteTarget, type: RoutingRuleType,
                                valueStart: Int, length: Int, base: UnsafeBufferPointer<UInt8>) {
        switch type {
        case .domainSuffix:
            tiers[tierIndex].collectSuffix(offset: valueStart, length: length, action: action)
        case .domainKeyword:
            tiers[tierIndex].insertKeyword(String(decoding: base[valueStart..<valueStart + length], as: UTF8.self), action: action)
        case .ipCIDR:
            if let parsed = Self.parseIPv4CIDR(String(decoding: base[valueStart..<valueStart + length], as: UTF8.self)) {
                tiers[tierIndex].insertIPv4(network: parsed.network, prefixLen: parsed.prefixLen, action: action)
            }
        case .ipCIDR6:
            if let parsed = Self.parseIPv6CIDR(String(decoding: base[valueStart..<valueStart + length], as: UTF8.self)) {
                tiers[tierIndex].insertIPv6(network: parsed.network, prefixLen: parsed.prefixLen, action: action)
            }
        }
    }

    // MARK: - Payload reader

    private struct RoutingBinaryReader {
        enum ReadError: Error { case badMagic, truncated, malformed }

        let bytes: UnsafeBufferPointer<UInt8>
        let data: Data
        let owner: DomainRouter
        private var cursor = 0
        private var count: Int { bytes.count }

        mutating func run() throws {
            try expectMagic()

            let configLength = Int(try u32())
            let configStart = cursor
            try advance(configLength)
            if configLength > 0 {
                owner.ingestConfigurations(data.subdata(in: (data.startIndex + configStart)..<(data.startIndex + configStart + configLength)))
            }

            var remainingEntries = try u32()
            while remainingEntries > 0 {
                try readEntry()
                remainingEntries -= 1
            }
        }

        private mutating func readEntry() throws {
            guard let tier = RoutingBinaryFormat.Tier(rawValue: try u8()) else { throw ReadError.malformed }
            let action = try readAction()

            var remainingRules = try u32()
            while remainingRules > 0 {
                let typeByte = try u8()
                let length = Int(try u16())
                let valueStart = cursor
                try advance(length)
                if let type = RoutingRuleType(rawValue: Int(typeByte)) {
                    owner.ingestRule(tierIndex: Int(tier.rawValue), action: action, type: type,
                                     valueStart: valueStart, length: length, base: bytes)
                }
                remainingRules -= 1
            }
        }

        private mutating func readAction() throws -> RouteTarget {
            switch RoutingBinaryFormat.Action(rawValue: try u8()) {
            case .direct: return .direct
            case .reject: return .reject
            case .proxy: return .proxy(try readUUID())
            case nil: throw ReadError.malformed
            }
        }

        // MARK: Primitives

        private mutating func expectMagic() throws {
            let magic = RoutingBinaryFormat.magic
            guard cursor + magic.count <= count else { throw ReadError.truncated }
            for k in 0..<magic.count where bytes[cursor + k] != magic[k] { throw ReadError.badMagic }
            cursor += magic.count
        }

        private mutating func u8() throws -> UInt8 {
            guard cursor < count else { throw ReadError.truncated }
            defer { cursor += 1 }
            return bytes[cursor]
        }

        private mutating func u16() throws -> UInt16 {
            guard cursor + 2 <= count else { throw ReadError.truncated }
            defer { cursor += 2 }
            return UInt16(bytes[cursor]) | (UInt16(bytes[cursor + 1]) << 8)
        }

        private mutating func u32() throws -> UInt32 {
            guard cursor + 4 <= count else { throw ReadError.truncated }
            defer { cursor += 4 }
            return UInt32(bytes[cursor]) | (UInt32(bytes[cursor + 1]) << 8) | (UInt32(bytes[cursor + 2]) << 16) | (UInt32(bytes[cursor + 3]) << 24)
        }

        private mutating func advance(_ n: Int) throws {
            guard n >= 0, cursor + n <= count else { throw ReadError.truncated }
            cursor += n
        }

        private mutating func readUUID() throws -> UUID {
            guard cursor + 16 <= count else { throw ReadError.truncated }
            let u = UUID(uuid: (bytes[cursor], bytes[cursor + 1], bytes[cursor + 2], bytes[cursor + 3],
                                bytes[cursor + 4], bytes[cursor + 5], bytes[cursor + 6], bytes[cursor + 7],
                                bytes[cursor + 8], bytes[cursor + 9], bytes[cursor + 10], bytes[cursor + 11],
                                bytes[cursor + 12], bytes[cursor + 13], bytes[cursor + 14], bytes[cursor + 15]))
            cursor += 16
            return u
        }
    }

    // MARK: - Matching (public API)

    var hasRules: Bool {
        routingLock.withLock {
            for i in tiers.indices where !tiers[i].isEmpty { return true }
            return false
        }
    }

    /// Matches a domain by walking tiers in priority order. First hit wins.
    func matchDomain(_ domain: String) -> RouteTarget? {
        guard !domain.isEmpty else { return nil }
        // Lowercase once and share the UTF-8 bytes across tiers; timed outside
        // routingLock so the monitor lock stays a leaf.
        return PerformanceMonitor.measure(.routingDomain) {
            var lowered = Self.asciiLowercasedIfNeeded(domain)
            return routingLock.withLock {
                lowered.withUTF8 { matchDomainBytes($0) }
            }
        }
    }

    /// Iterates by index so the per-tier `TierMatchers` value isn't copied on each lookup.
    private func matchDomainBytes(_ bytes: UnsafeBufferPointer<UInt8>) -> RouteTarget? {
        for i in tiers.indices {
            if let action = tiers[i].lookupDomain(bytes) { return action }
        }
        return nil
    }

    /// Matches an IP address against per-tier CIDR tries in priority order.
    func matchIP(_ ip: String) -> RouteTarget? {
        guard !ip.isEmpty else { return nil }

        // Timed outside routingLock so the monitor lock stays a leaf.
        return PerformanceMonitor.measure(.routingIP) {
            routingLock.withLock { () -> RouteTarget? in
                if ip.contains(":") {
                    var address = in6_addr()
                    guard inet_pton(AF_INET6, ip, &address) == 1 else { return nil }
                    // Pack to a 128-bit pair once; reuse across tiers.
                    let (hi, lo) = withUnsafeBytes(of: &address) { raw -> (UInt64, UInt64) in
                        CIDRv6Trie.pack16(raw.bindMemory(to: UInt8.self))
                    }
                    for i in tiers.indices {
                        if let action = tiers[i].lookupIPv6(hi: hi, lo: lo) { return action }
                    }
                    return nil
                } else {
                    guard let ipv4Address = Self.parseIPv4(ip) else { return nil }
                    for i in tiers.indices {
                        if let action = tiers[i].lookupIPv4(ipv4Address) { return action }
                    }
                    return nil
                }
            }
        }
    }

    /// Returns nil for .direct/.reject or when the configuration UUID is unknown.
    func resolveConfiguration(action: RouteTarget) -> ProxyConfiguration? {
        switch action {
        case .direct, .reject:
            return nil
        case .proxy(let id):
            return routingLock.withLock { configurationMap[id] }
        }
    }

    // MARK: - Case folding

    /// Returns the input unchanged (no allocation) when already lowercase ASCII;
    /// otherwise falls back to `lowercased()` to match load-time folding.
    private static func asciiLowercasedIfNeeded(_ input: String) -> String {
        for b in input.utf8 where (b >= 0x41 && b <= 0x5A) || b >= 0x80 {
            return input.lowercased()
        }
        return input
    }

    // MARK: - CIDR Parsing

    /// Parses "A.B.C.D/prefix" into (network, prefixLen) with host bits zeroed.
    private static func parseIPv4CIDR(_ cidr: String) -> (network: UInt32, prefixLen: Int)? {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefixLen = Int(parts[1]),
              prefixLen >= 0, prefixLen <= 32,
              let ip = parseIPv4(String(parts[0])) else { return nil }
        let mask: UInt32 = prefixLen == 0 ? 0 : ~UInt32(0) << (32 - prefixLen)
        return (network: ip & mask, prefixLen: prefixLen)
    }

    /// Parses a dotted-quad IPv4 string to host-order UInt32.
    private static func parseIPv4(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".", maxSplits: 4, omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard let byte = UInt8(part) else { return nil }
            result = result << 8 | UInt32(byte)
        }
        return result
    }

    private static func parseIPv6CIDR(_ cidr: String) -> (network: [UInt8], prefixLen: Int)? {
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

// MARK: - Action interning
//
// Interning `RouteTarget` (~32 B with UUID payload) to an `Int16` ID keeps matcher
// nodes small. `fileprivate` rather than nested so the CIDR tries can use the sentinels.
fileprivate struct ActionTable {
    static let noneID: Int16 = -1
    static let directID: Int16 = 0
    static let rejectID: Int16 = 1
    private static let firstProxyID: Int16 = 2

    private var proxyUUIDs: [UUID] = []
    private var proxyIndex: [UUID: Int16] = [:]

    mutating func intern(_ action: RouteTarget) -> Int16 {
        switch action {
        case .direct: return Self.directID
        case .reject: return Self.rejectID
        case .proxy(let uuid):
            if let id = proxyIndex[uuid] { return id }
            let id = Self.firstProxyID + Int16(proxyUUIDs.count)
            proxyUUIDs.append(uuid)
            proxyIndex[uuid] = id
            return id
        }
    }

    func resolve(_ id: Int16) -> RouteTarget? {
        switch id {
        case Self.noneID: return nil
        case Self.directID: return .direct
        case Self.rejectID: return .reject
        default:
            let index = Int(id) - Int(Self.firstProxyID)
            guard index >= 0, index < proxyUUIDs.count else { return nil }
            return .proxy(proxyUUIDs[index])
        }
    }
}

// MARK: - CIDR Patricia tries
//
// Path-compressed binary tries for longest-prefix match, nodes in one contiguous
// arena; v4 and v6 are separate types so the v4 hot loop avoids 128-bit shifts.

struct CIDRv4Trie {
    /// 4 + 4 + 4 + 2 + 1 + 1 padding = 16 bytes, 4-byte aligned.
    private struct Node {
        var bits: UInt32 = 0        // MSB-aligned edge bits; bits past `bitLen` are zero
        var left: Int32 = -1        // index into `nodes`, or -1 for none
        var right: Int32 = -1
        var actionID: Int16 = ActionTable.noneID
        var bitLen: UInt8 = 0       // 0…32
    }

    private var nodes: [Node] = [Node()]

    // MARK: - Insert

    /// More-specific prefixes win at lookup; duplicate prefixes overwrite.
    mutating func insert(network: UInt32, prefixLen: Int, actionID: Int16) {
        let length = UInt8(prefixLen)
        let bits = Self.maskTop(network, length)
        insertCore(bits: bits, bitLen: length, actionID: actionID)
    }

    // MARK: - Lookup

    /// Deepest action along the path, or `ActionTable.noneID`. Reads each child once
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
                if child.actionID != ActionTable.noneID { deepest = child.actionID }
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

struct CIDRv6Trie {
    /// 8 + 8 + 4 + 4 + 2 + 1 + 5 padding = 32 bytes, 8-byte aligned. Edge bits are
    /// MSB-first across (bitsHi, bitsLo); bits past `bitLen` stay zero by invariant.
    private struct Node {
        var bitsHi: UInt64 = 0
        var bitsLo: UInt64 = 0
        var left: Int32 = -1
        var right: Int32 = -1
        var actionID: Int16 = ActionTable.noneID
        var bitLen: UInt8 = 0       // 0…128
    }

    private var nodes: [Node] = [Node()]

    // MARK: - Insert

    mutating func insert(network: [UInt8], prefixLen: Int, actionID: Int16) {
        let (hi, lo) = network.withUnsafeBufferPointer { Self.pack16($0) }
        let length = UInt8(prefixLen)
        let (mHi, mLo) = Self.maskTop(hi, lo, length)
        insertCore(bitsHi: mHi, bitsLo: mLo, bitLen: length, actionID: actionID)
    }

    // MARK: - Lookup

    /// Deepest action along the path for a packed 128-bit address, or `ActionTable.noneID`.
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
                if child.actionID != ActionTable.noneID { deepest = child.actionID }
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
