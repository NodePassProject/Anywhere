//
//  DomainRouter.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "DomainRouter")

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
                let u = queue[head]; head += 1

                let sortedChildren = u.children.sorted { $0.key < $1.key }
                for (byte, v) in sortedChildren {
                    // Standard AC failure: nearest ancestor-of-failure with a
                    // `byte` child (≠ v), else root. u.failure is nil only for root.
                    var f = u.failure
                    while let cur = f, cur.children[byte] == nil, cur !== root {
                        f = cur.failure
                    }
                    if let cur = f, let next = cur.children[byte], next !== v {
                        v.failure = next
                    } else {
                        v.failure = root
                    }
                    v.dictSuffix = (v.failure?.actionID ?? ActionTable.noneID) != ActionTable.noneID
                        ? v.failure
                        : v.failure?.dictSuffix

                    let childID = Int32(nFailure.count)
                    v.nodeID = childID
                    queue.append(v)

                    nFailure.append(v.failure!.nodeID)
                    nDictSuffix.append(v.dictSuffix?.nodeID ?? -1)
                    nActionID.append(v.actionID)
                    nPatternLength.append(v.patternLength)
                    nInsertionOrder.append(v.insertionOrder)

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
                let eb = edgeByte[i]
                if eb == byte { return edgeTarget[i] }
                if eb > byte { return -1 }
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

        var isEmpty: Bool { domainRuleCount == 0 && ipRuleCount == 0 }

        mutating func insertSuffix(_ suffix: String, action: RouteTarget) {
            suffixTrie.insert(suffix: suffix, payload: actionTable.intern(action))
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

        /// Call once per tier after all inserts; lookups before this return nil.
        mutating func finalize() {
            keywordAutomaton.finalize()
            suffixTrie.freeze()
        }

        /// Suffix wins over keyword.
        func lookupDomain(_ domain: UnsafeBufferPointer<UInt8>) -> RouteTarget? {
            if let id = suffixTrie.lookup(domain) {
                return actionTable.resolve(id)
            }
            let kid = keywordAutomaton.lookup(domain)
            return kid == ActionTable.noneID ? nil : actionTable.resolve(kid)
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

        guard let data = AWCore.getRoutingData(),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            logger.debug("[DomainRouter] No routing data available")
            return
        }

        // Configurations (tier-independent)
        if let configurations = json["configs"] as? [String: Any] {
            for (key, value) in configurations {
                guard let configurationId = UUID(uuidString: key),
                      let configurationDict = value as? [String: Any] else { continue }
                if let configuration = ProxyConfiguration.parse(from: configurationDict) {
                    configurationMap[configurationId] = configuration
                }
            }
        }

        // Rules targeting the current default proxy still load: dropping them is
        // unsound since a more-specific or lower-tier rule could match instead.
        if let entries = json["userRules"] as? [[String: Any]] {
            loadRuleEntries(entries, into: .user)
        }
        if let entries = json["adBlockRules"] as? [[String: Any]] {
            loadRuleEntries(entries, into: .adBlock)
        }
        if let entries = json["builtInRules"] as? [[String: Any]] {
            loadRuleEntries(entries, into: .builtIn)
        }
        if let entries = json["bypassRules"] as? [[String: Any]] {
            loadBypassEntries(entries, into: .bypass)
        }

        for i in tiers.indices { tiers[i].finalize() }

        logger.debug("[DomainRouter] Loaded tiers — user: \(self.tiers[Tier.user.rawValue].domainRuleCount)+\(self.tiers[Tier.user.rawValue].ipRuleCount), adBlock: \(self.tiers[Tier.adBlock.rawValue].domainRuleCount)+\(self.tiers[Tier.adBlock.rawValue].ipRuleCount), builtIn: \(self.tiers[Tier.builtIn.rawValue].domainRuleCount)+\(self.tiers[Tier.builtIn.rawValue].ipRuleCount), bypass: \(self.tiers[Tier.bypass.rawValue].domainRuleCount)+\(self.tiers[Tier.bypass.rawValue].ipRuleCount); \(self.configurationMap.count) configurations")
    }

    private func loadRuleEntries(_ entries: [[String: Any]], into tier: Tier) {
        for rule in entries {
            guard let actionStr = rule["action"] as? String else { continue }

            let action: RouteTarget
            if actionStr == "direct" {
                action = .direct
            } else if actionStr == "reject" {
                action = .reject
            } else if actionStr == "proxy",
                      let configurationIdStr = rule["configId"] as? String,
                      let configurationId = UUID(uuidString: configurationIdStr) {
                action = .proxy(configurationId)
            } else {
                continue
            }

            if let domainRules = rule["domainRules"] as? [[String: Any]] {
                for dr in domainRules {
                    guard let type = Self.parseRuleType(dr["type"]),
                          let value = dr["value"] as? String else { continue }
                    let lowered = value.lowercased()
                    switch type {
                    case .domainSuffix:
                        tiers[tier.rawValue].insertSuffix(lowered, action: action)
                    case .domainKeyword:
                        tiers[tier.rawValue].insertKeyword(lowered, action: action)
                    case .ipCIDR, .ipCIDR6:
                        break
                    }
                }
            }

            if let ipRules = rule["ipRules"] as? [[String: Any]] {
                for ir in ipRules {
                    guard let type = Self.parseRuleType(ir["type"]),
                          let value = ir["value"] as? String else { continue }
                    switch type {
                    case .ipCIDR:
                        if let parsed = Self.parseIPv4CIDR(value) {
                            tiers[tier.rawValue].insertIPv4(network: parsed.network, prefixLen: parsed.prefixLen, action: action)
                        }
                    case .ipCIDR6:
                        if let parsed = Self.parseIPv6CIDR(value) {
                            tiers[tier.rawValue].insertIPv6(network: parsed.network, prefixLen: parsed.prefixLen, action: action)
                        }
                    case .domainSuffix, .domainKeyword:
                        break
                    }
                }
            }
        }
    }

    /// Bypass rules use a flat {type, value} shape with an implicit `.direct` action.
    private func loadBypassEntries(_ entries: [[String: Any]], into tier: Tier) {
        for rule in entries {
            guard let type = Self.parseRuleType(rule["type"]),
                  let value = rule["value"] as? String else { continue }
            switch type {
            case .domainSuffix:
                tiers[tier.rawValue].insertSuffix(value.lowercased(), action: .direct)
            case .domainKeyword:
                tiers[tier.rawValue].insertKeyword(value.lowercased(), action: .direct)
            case .ipCIDR:
                if let parsed = Self.parseIPv4CIDR(value) {
                    tiers[tier.rawValue].insertIPv4(network: parsed.network, prefixLen: parsed.prefixLen, action: .direct)
                }
            case .ipCIDR6:
                if let parsed = Self.parseIPv6CIDR(value) {
                    tiers[tier.rawValue].insertIPv6(network: parsed.network, prefixLen: parsed.prefixLen, action: .direct)
                }
            }
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
                    var addr = in6_addr()
                    guard inet_pton(AF_INET6, ip, &addr) == 1 else { return nil }
                    // Pack to a 128-bit pair once; reuse across tiers.
                    let (hi, lo) = withUnsafeBytes(of: &addr) { raw -> (UInt64, UInt64) in
                        CIDRv6Trie.pack16(raw.bindMemory(to: UInt8.self))
                    }
                    for i in tiers.indices {
                        if let action = tiers[i].lookupIPv6(hi: hi, lo: lo) { return action }
                    }
                    return nil
                } else {
                    guard let ip32 = Self.parseIPv4(ip) else { return nil }
                    for i in tiers.indices {
                        if let action = tiers[i].lookupIPv4(ip32) { return action }
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
    private static func asciiLowercasedIfNeeded(_ s: String) -> String {
        for b in s.utf8 where (b >= 0x41 && b <= 0x5A) || b >= 0x80 {
            return s.lowercased()
        }
        return s
    }

    // MARK: - CIDR Parsing

    private static func parseRuleType(_ rawValue: Any?) -> RoutingRuleType? {
        guard let rawValue = rawValue as? Int else { return nil }
        return RoutingRuleType(rawValue: rawValue)
    }

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

        var addr = in6_addr()
        guard inet_pton(AF_INET6, String(parts[0]), &addr) == 1 else { return nil }

        var network = withUnsafeBytes(of: &addr) { Array($0.bindMemory(to: UInt8.self)) }
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
            let idx = Int(id) - Int(Self.firstProxyID)
            guard idx >= 0, idx < proxyUUIDs.count else { return nil }
            return .proxy(proxyUUIDs[idx])
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
        let len = UInt8(prefixLen)
        let bits = Self.maskTop(network, len)
        insertCore(bits: bits, bitLen: len, actionID: actionID)
    }

    // MARK: - Lookup

    /// Deepest action along the path, or `ActionTable.noneID`. Reads each child once
    /// into a local to avoid bounds-checked subscripts on the hot path.
    func lookup(_ ip: UInt32) -> Int16 {
        nodes.withUnsafeBufferPointer { buf in
            var bits = ip
            var remaining: UInt8 = 32
            var nodeID = 0
            var deepest = buf[0].actionID

            while remaining > 0 {
                let firstBit = bits >> 31
                let childID = (firstBit == 0) ? buf[nodeID].left : buf[nodeID].right
                if childID < 0 { return deepest }

                let child = buf[Int(childID)]
                let lcp = Self.lcp(bits, child.bits, cap: min(remaining, child.bitLen))
                if lcp < child.bitLen { return deepest }

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
        var b = bits
        var remaining = bitLen
        var nodeID: Int32 = 0

        while remaining > 0 {
            let firstBit = UInt8(b >> 31)
            let childID = (firstBit == 0) ? nodes[Int(nodeID)].left : nodes[Int(nodeID)].right

            if childID < 0 {
                let leafID = makeLeaf(bits: b, bitLen: remaining, actionID: actionID)
                if firstBit == 0 { nodes[Int(nodeID)].left = leafID }
                else { nodes[Int(nodeID)].right = leafID }
                return
            }

            let childBits = nodes[Int(childID)].bits
            let childBitLen = nodes[Int(childID)].bitLen
            let lcp = Self.lcp(b, childBits, cap: min(remaining, childBitLen))

            if lcp == childBitLen {
                // Existing edge fully matched; descend.
                b = Self.shiftLeft(b, lcp)
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

            let newBits = Self.shiftLeft(b, lcp)
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
        let len = UInt8(prefixLen)
        let (mHi, mLo) = Self.maskTop(hi, lo, len)
        insertCore(bitsHi: mHi, bitsLo: mLo, bitLen: len, actionID: actionID)
    }

    // MARK: - Lookup

    /// Deepest action along the path for a packed 128-bit address, or `ActionTable.noneID`.
    func lookup(hi hi0: UInt64, lo lo0: UInt64) -> Int16 {
        nodes.withUnsafeBufferPointer { buf in
            var hi = hi0
            var lo = lo0
            var remaining: UInt8 = 128
            var nodeID = 0
            var deepest = buf[0].actionID

            while remaining > 0 {
                let firstBit = hi >> 63
                let childID = (firstBit == 0) ? buf[nodeID].left : buf[nodeID].right
                if childID < 0 { return deepest }

                let child = buf[Int(childID)]
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
