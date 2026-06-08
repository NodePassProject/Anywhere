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
    // Each rule source owns its own set of matching structures, so cross-source
    // priority is enforced by the order tiers are queried, not by trie insert
    // order. Within a tier, suffix rules win over keyword rules; deepest suffix
    // and longest CIDR prefix still win, but that competition is now scoped to
    // a single source.
    //
    // Priority (highest first): User > ADBlock > Built-in > Country Bypass.

    // MARK: - Action interning (see fileprivate `ActionTable` below)

    // MARK: - Keyword automaton

    /// Aho–Corasick automaton for `domainKeyword` matching: finds the
    /// longest pattern occurring as a substring of the input in a single
    /// O(D) walk, independent of the number of patterns. Replaces the
    /// previous O(N·D) per-pattern `String.contains` loop.
    ///
    /// Memory model: a class-per-node tree is built during ``insert`` (so
    /// the wide branching factor at the root stays cheap to mutate), then
    /// at ``finalize()`` time the structure is BFS-laid-out across flat
    /// columns — failure / dictSuffix / actionID / patternLength /
    /// insertionOrder — plus CSR-style edges. The scratch tree is dropped
    /// after finalize; the frozen form has no per-node heap allocation
    /// and no per-node Dictionary, which is the dominant cost of the
    /// class-based form.
    ///
    /// Lifecycle:
    ///   1. Build: call ``insert(_:actionID:)`` for each rule.
    ///   2. Finalize: call ``finalize()`` once after all inserts.
    ///   3. Lookup: call ``lookup(_:)``. Read-only after finalize.
    ///
    /// Inserting after ``finalize()`` traps. Lookup before ``finalize()``
    /// returns `ActionTable.noneID`. Build-once-read-many by design.
    private final class KeywordAutomaton {

        // MARK: Build state (dropped on finalize)

        private final class BuildNode {
            var children: [UInt8: BuildNode] = [:]
            var failure: BuildNode?
            /// Nearest accepting ancestor reachable via failure links —
            /// lets ``lookup`` enumerate all patterns ending at a state
            /// without walking the full failure chain each step.
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

        /// CSR edges. Node `i`'s outgoing edges live at indices
        /// `[edgeStart[i], edgeStart[i + 1])`, sorted by byte. Length of
        /// `edgeStart` is `nodeCount + 1` once finalized.
        private var edgeStart: ContiguousArray<Int32> = []
        private var edgeByte: ContiguousArray<UInt8> = []
        private var edgeTarget: ContiguousArray<Int32> = []

        // MARK: Build API

        func insert(_ pattern: String, actionID: Int16) {
            guard !pattern.isEmpty else { return }
            let bytes = Array(pattern.utf8)
            // Domain patterns are bounded by 253 octets per RFC 1035; UInt16
            // is comfortable headroom. Anything bigger is almost certainly
            // garbage input — drop silently rather than truncate.
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

        /// Builds failure / dictSuffix links and flattens the trie into the
        /// frozen columns above. Idempotent; subsequent inserts trap.
        func finalize() {
            guard !finalized else { return }
            guard let root = buildRoot else {
                finalized = true
                return
            }

            // Single BFS pass: at each node we (a) compute failure for each
            // child using the standard AC formula — safe because failure
            // links always point at strictly shallower depth, which BFS has
            // already laid out — and (b) emit the child's row into the flat
            // columns. Children are visited in sorted-byte order so each
            // node's CSR edge row is sorted, enabling early-exit lookup.
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
                    // AC failure: walk u.failure ancestors until one has a child
                    // for `byte` (and isn't `v` itself), else fall back to root.
                    // u.failure is nil only for root; treat that as "stay at root".
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

                    // `v.failure` is set above and has a nodeID because BFS
                    // already visited it (depth strictly shallower than v).
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

        /// Returns the best-matching action ID, or `ActionTable.noneID` if
        /// no pattern in the automaton occurs as a substring of `domain`
        /// (the host's raw UTF-8 bytes).
        func lookup(_ domain: UnsafeBufferPointer<UInt8>) -> Int16 {
            // No patterns ⇒ no possible match. After `finalize()` the node
            // columns always carry the root row, so gate on the edge table
            // (empty iff nothing was inserted) to skip the O(D) walk for
            // tiers that have no keyword rules.
            guard finalized, !edgeByte.isEmpty else { return ActionTable.noneID }

            var bestID: Int16 = ActionTable.noneID
            var bestLength: UInt16 = 0
            var bestOrder: Int32 = -1
            var nodeID: Int32 = 0

            for byte in domain {
                // Walk failure links until either a child for `byte` exists
                // or we land at root with no match.
                var nextID = childTarget(nodeID: nodeID, byte: byte)
                while nextID < 0 && nodeID != 0 {
                    nodeID = failure[Int(nodeID)]
                    nextID = childTarget(nodeID: nodeID, byte: byte)
                }
                if nextID >= 0 { nodeID = nextID }

                // Enumerate accepting nodes reachable via the dictSuffix chain.
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

        /// Returns the target nodeID for an edge `byte` from `nodeID`, or
        /// -1 if no such edge exists. Rows are sorted by byte, so the scan
        /// exits early once `edgeByte > byte`.
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
        /// Per-tier interner. Every matcher in this tier stores `Int16`
        /// IDs into this table and resolves back at the tier boundary
        /// (see `lookupDomain` / `lookupIPv4` / `lookupIPv6`).
        var actionTable = ActionTable()

        /// Reverse-label trie for `domainSuffix` matching. Each edge is
        /// one dot-separated label; walking deeper matches a
        /// more-specific suffix.
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

        /// Builds the keyword automaton's failure links and freezes
        /// the suffix trie. Call once per tier after all inserts;
        /// lookups before this return nil.
        mutating func finalize() {
            keywordAutomaton.finalize()
            suffixTrie.freeze()
        }

        /// Domain Suffix wins over Domain Keyword: only fall back to the
        /// keyword automaton when the suffix trie does not match.
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

    // Proxy configurations for rule-assigned proxies
    private var configurationMap: [UUID: ProxyConfiguration] = [:]

    /// Guards ``tiers`` + ``configurationMap`` against the cross-queue split of
    /// the data plane: routing lookups now come from both ``lwipQueue`` (TCP
    /// accept) and ``udpQueue`` (UDP new-flow), while ``loadRoutingConfiguration``
    /// / ``reset`` rebuild the tables on ``lwipQueue`` at start/restart. Reads
    /// take the lock briefly; the (rare, restart-only) reload holds it across
    /// the compile so a concurrent lookup never observes a half-built tier. The
    /// reload reads UserDefaults/JSON only — it never calls back into a data-plane
    /// queue — so there is no lock-ordering cycle.
    private let routingLock = UnfairLock()

    // MARK: - Loading

    /// Clears all routing rules and configurations.
    /// Used when switching to global mode to ensure no stale rules affect routing.
    func reset() {
        routingLock.withLock { resetUnlocked() }
    }

    /// Clears the tables. Caller must hold ``routingLock`` (or run before the
    /// router is visible to any other queue).
    private func resetUnlocked() {
        tiers = Tier.allCases.map { _ in TierMatchers() }
        configurationMap.removeAll()
    }

    /// Reads routing configuration from App Group UserDefaults and compiles rules
    /// into per-tier matching structures. Holds ``routingLock`` across the whole
    /// compile so cross-queue lookups block until the new tables are complete.
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

        // Tiered rule loading. Each tier reads from its own array. Every rule is
        // loaded regardless of its target — including rules that point at the proxy
        // currently selected as the default. Dropping such "redundant with the
        // default" rules is unsound: a more-specific rule in the same tier, or any
        // rule in a lower-priority tier, could otherwise match instead and route the
        // connection somewhere other than the default the dropped rule intended.
        // Keeping them preserves both within-tier specificity and cross-tier priority.
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

    /// Whether any routing rules have been loaded across any tier.
    var hasRules: Bool {
        routingLock.withLock {
            for i in tiers.indices where !tiers[i].isEmpty { return true }
            return false
        }
    }

    /// Matches a domain by walking tiers in priority order. First hit wins.
    func matchDomain(_ domain: String) -> RouteTarget? {
        guard !domain.isEmpty else { return nil }
        // Lowercase once (allocation-free when already lowercase ASCII) and
        // hand the contiguous UTF-8 bytes to every tier, so neither the
        // suffix trie nor the keyword automaton re-splits or re-allocates
        // per tier.
        var lowered = Self.asciiLowercasedIfNeeded(domain)
        return routingLock.withLock {
            lowered.withUTF8 { matchDomainBytes($0) }
        }
    }

    /// Walks tiers in priority order over already-lowercased UTF-8 bytes.
    /// Iterates by index so the per-tier `TierMatchers` value isn't copied
    /// (which would retain/release all its backing buffers) on each lookup.
    private func matchDomainBytes(_ bytes: UnsafeBufferPointer<UInt8>) -> RouteTarget? {
        for i in tiers.indices {
            if let action = tiers[i].lookupDomain(bytes) { return action }
        }
        return nil
    }

    /// Matches an IP address against per-tier CIDR tries in priority order.
    func matchIP(_ ip: String) -> RouteTarget? {
        guard !ip.isEmpty else { return nil }

        return routingLock.withLock { () -> RouteTarget? in
            if ip.contains(":") {
                var addr = in6_addr()
                guard inet_pton(AF_INET6, ip, &addr) == 1 else { return nil }
                // Pack the 16 address bytes into a 128-bit pair once, then reuse
                // it across every tier rather than re-packing per tier.
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

    /// Resolves a RouteTarget to a ProxyConfiguration.
    /// Returns nil for .direct/.reject or when the configuration UUID is not found.
    func resolveConfiguration(action: RouteTarget) -> ProxyConfiguration? {
        switch action {
        case .direct, .reject:
            return nil
        case .proxy(let id):
            return routingLock.withLock { configurationMap[id] }
        }
    }

    // MARK: - Case folding

    /// Lowercases ASCII `A`–`Z` only, returning the input unchanged (no
    /// allocation) when it is already lowercase ASCII. Any uppercase ASCII
    /// or non-ASCII byte defers to Unicode-aware `lowercased()`, so
    /// query-time case folding matches the `lowercased()` applied to rules
    /// at load time.
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

    /// Parses "addr/prefix" IPv6 CIDR into (network bytes, prefix length).
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
// Each matcher node used to carry an `Optional<RouteTarget>` (~32 B due
// to the `UUID` payload in `.proxy`). For tiers with thousands of CIDR
// nodes this dominates the per-node footprint. `ActionTable` interns
// distinct actions into a small `Int16` ID so nodes only need to store
// a 2-byte handle, and resolves IDs back to `RouteTarget` at the tier
// boundary. `.direct`/`.reject` are reserved IDs so they cost no table
// space; `.proxy(UUID)` entries dedupe by UUID. `noneID` is the "no
// action at this node" sentinel.
//
// Scoped `fileprivate` (not nested in `DomainRouter`) so the CIDR
// trie value types below can refer to its sentinel constants without
// crossing a `private` lexical boundary.
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
// Path-compressed binary tries for longest-prefix-match on IP addresses.
// Each non-root node owns the bit-string of the edge from its parent;
// runs of single-child nodes collapse into one. Compared with a bit-
// per-node binary trie, a /24 rule contributes 1–2 nodes instead of
// 24, and for sparse CIDR sets the total node count drops from
// O(prefix-length × rules) to O(rules). One trie per tier; cross-tier
// priority is handled by DomainRouter. Lookup is O(W) in the address
// width (32 for IPv4, 128 for IPv6), independent of rule count.
//
// Storage: nodes are value types stored in a single contiguous `[Node]`
// arena per trie; children are 4-byte indices instead of 8-byte class
// references, and there is no per-node Swift class header / refcount.
// Each node carries an `Int16` action ID into the tier's `ActionTable`
// rather than a fat `Optional<RouteTarget>`. The result is 16 B/node
// for IPv4 and 32 B/node for IPv6, vs. ~80 B before.
//
// The v4 and v6 tries are deliberately separate types: IPv4 edges only
// need 32 bits of storage, so the v4 node stays at half the size of
// the v6 node and the v4 hot loop becomes a tight `UInt32` walk with
// no 128-bit shifts.

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

    /// Inserts a CIDR rule. More-specific prefixes override less-specific
    /// ones during lookup; duplicate prefixes overwrite (last-write-wins).
    mutating func insert(network: UInt32, prefixLen: Int, actionID: Int16) {
        let len = UInt8(prefixLen)
        let bits = Self.maskTop(network, len)
        insertCore(bits: bits, bitLen: len, actionID: actionID)
    }

    // MARK: - Lookup

    /// Looks up an IPv4 address. Returns the deepest action along the path,
    /// or `ActionTable.noneID` if no rule matches. The walk runs over an
    /// unsafe buffer and reads each child node once into a local, avoiding
    /// the repeated bounds-checked subscripts on the hot path.
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

            // Allocate the mid node first so subsequent appends don't shift
            // its index.
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

    /// Keep only the top `n` bits; zero the rest. Used both to canonicalize
    /// incoming rules and to extract the shared prefix when splitting an edge.
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
    /// 8 + 8 + 4 + 4 + 2 + 1 + 5 padding = 32 bytes, 8-byte aligned.
    /// Edges are MSB-first packed into a 128-bit window split across two
    /// `UInt64`s; bits past `bitLen` are kept zero by invariant.
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

    /// Looks up a packed 128-bit IPv6 address (see ``pack16``). Returns the
    /// deepest action along the path, or `ActionTable.noneID`. The address
    /// is packed once by the caller and reused across tiers; the walk runs
    /// over an unsafe buffer and reads each child node once into a local.
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

    /// Pack up to 16 big-endian bytes into a (hi, lo) 128-bit pair. Callable
    /// from ``DomainRouter`` so a v6 address is packed once per lookup and
    /// shared across tiers.
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
