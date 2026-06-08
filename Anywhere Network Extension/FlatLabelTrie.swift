//
//  FlatLabelTrie.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

/// Reverse-label trie for domain-suffix matching, laid out as parallel
/// arrays after ``freeze()``. Each edge is one dot-separated label;
/// lookup walks the host's labels right-to-left and returns the payload
/// at the deepest visited node.
///
/// Memory model: a class-per-node trie is built during ``insert`` (so
/// the wide branching factor at the root stays cheap to mutate), then
/// at ``freeze()`` time the structure is BFS-laid-out across flat
/// arrays — node payloads, CSR-style edge ranges, and per-edge label
/// bytes + target node IDs — and the scratch tree is dropped. The
/// frozen form has no per-node heap allocation and no per-node
/// Dictionary, which is the dominant cost of the class-based form.
/// Labels are stored as bytes so ``lookup`` matches a host's labels
/// without allocating a `String` per label.
///
/// Lifecycle:
///   1. Build: call ``insert(suffix:payload:)`` for each rule.
///   2. Freeze: call ``freeze()`` once after all inserts.
///   3. Lookup: call ``lookup(_:)``. The frozen state is read-only and
///      safe for concurrent reads.
///
/// Inserting after ``freeze()`` traps. Lookup before ``freeze()``
/// returns nil. The trie is build-once-read-many by design; callers
/// that need to re-insert rebuild from scratch (the same pattern the
/// surrounding routing code already uses).
struct FlatLabelTrie<Payload> {

    // MARK: - Build state (dropped on freeze)

    private final class BuildNode {
        var children: [String: BuildNode] = [:]
        var payload: Payload?
    }

    private var buildRoot: BuildNode? = BuildNode()

    // MARK: - Frozen state (populated by freeze)

    /// `nodePayload[i]` is the payload at node `i`, or nil. Root is 0.
    private var nodePayload: ContiguousArray<Payload?> = []

    /// CSR-style edge ranges. Node `i`'s edges live at indices
    /// `[edgeRangeStart[i], edgeRangeStart[i + 1])`. Length is
    /// `nodeCount + 1` once frozen.
    private var edgeRangeStart: ContiguousArray<Int32> = []

    /// Edge labels stored as raw UTF-8 bytes, concatenated in BFS row
    /// order. Edge `e`'s label bytes are
    /// `edgeLabelBytes[edgeLabelOffset[e] ..< edgeLabelOffset[e + 1]]`,
    /// and its target node is `edgeTarget[e]`. Storing bytes instead of
    /// interned label IDs lets ``lookup`` compare a host's labels in place
    /// without allocating a `String` per label. `edgeLabelOffset.count ==
    /// edgeCount + 1`; `edgeTarget.count == edgeCount`.
    private var edgeLabelOffset: ContiguousArray<Int32> = []
    private var edgeLabelBytes: ContiguousArray<UInt8> = []
    private var edgeTarget: ContiguousArray<Int32> = []

    // MARK: - State

    private var frozen = false
    private(set) var isEmpty: Bool = true

    // MARK: - Build API

    /// Inserts a payload at the terminal for `suffix`. The suffix must
    /// be pre-normalized (lowercased, trimmed) and dot-separated.
    /// Empty labels (e.g., from `"foo..bar"`) are dropped by
    /// `String.split`'s default behavior.
    ///
    /// Returns `true` iff this insert created a new terminal — i.e.,
    /// the node's payload was nil before. Useful for callers that
    /// count distinct rules vs. overwrites.
    @discardableResult
    mutating func insert(suffix: String, payload: Payload) -> Bool {
        var node = buildRoot!
        for labelSub in suffix.split(separator: ".").reversed() {
            let label = String(labelSub)
            if let child = node.children[label] {
                node = child
            } else {
                let child = BuildNode()
                node.children[label] = child
                node = child
            }
        }

        let wasNewTerminal = node.payload == nil
        node.payload = payload
        isEmpty = false
        return wasNewTerminal
    }

    /// Freezes the trie into its flat representation. Subsequent
    /// inserts trap; subsequent freezes are no-ops.
    mutating func freeze() {
        guard !frozen else { return }
        guard let root = buildRoot else {
            frozen = true
            return
        }

        var queue: [BuildNode] = []
        queue.reserveCapacity(64)
        queue.append(root)

        var payloads: [Payload?] = []
        payloads.append(root.payload)

        var edgeStarts: [Int32] = [0]
        var labelOffsets: [Int32] = [0]
        var labelBytes: [UInt8] = []
        var targets: [Int32] = []

        var head = 0
        while head < queue.count {
            let node = queue[head]; head += 1
            // Sort by label for a stable, cache-friendly edge order.
            let sortedChildren = node.children.sorted { $0.key < $1.key }
            for (label, child) in sortedChildren {
                let childID = Int32(queue.count)
                queue.append(child)
                payloads.append(child.payload)
                labelBytes.append(contentsOf: label.utf8)
                labelOffsets.append(Int32(labelBytes.count))
                targets.append(childID)
            }
            edgeStarts.append(Int32(targets.count))
        }

        nodePayload = ContiguousArray(payloads)
        edgeRangeStart = ContiguousArray(edgeStarts)
        edgeLabelOffset = ContiguousArray(labelOffsets)
        edgeLabelBytes = ContiguousArray(labelBytes)
        edgeTarget = ContiguousArray(targets)

        buildRoot = nil
        frozen = true
    }

    // MARK: - Read API

    /// Returns the payload at the deepest matching node along the
    /// reverse-label path of `host`, or nil. `host` is the host's raw
    /// UTF-8 bytes, pre-normalized (lowercased); labels are split on '.'
    /// in place so no per-label `String` is allocated. Returns nil before
    /// ``freeze()``. The root's payload is intentionally not considered a
    /// match (matches existing label-trie semantics).
    func lookup(_ host: UnsafeBufferPointer<UInt8>) -> Payload? {
        guard frozen, !nodePayload.isEmpty else { return nil }

        var deepest: Payload? = nil
        var nodeID = 0

        // Walk the host's labels right-to-left without allocating. A label
        // is a maximal run of bytes between '.' (0x2E) separators; empty
        // labels (leading/trailing dot, "a..b") are skipped, matching the
        // `String.split(separator:)` semantics the build side relies on.
        let dot = UInt8(ascii: ".")
        var end = host.count
        while end > 0 {
            var start = end
            while start > 0 && host[start - 1] != dot { start -= 1 }
            let labelLen = end - start
            if labelLen == 0 {
                end = start - 1   // skip the separator before this empty label
                continue
            }

            // Linear-scan this node's edges for one whose label bytes equal
            // host[start..<end].
            let edgeLo = Int(edgeRangeStart[nodeID])
            let edgeHi = Int(edgeRangeStart[nodeID + 1])
            var found: Int32 = -1
            var e = edgeLo
            while e < edgeHi {
                let lo = Int(edgeLabelOffset[e])
                let hi = Int(edgeLabelOffset[e + 1])
                if hi - lo == labelLen {
                    var j = 0
                    while j < labelLen && edgeLabelBytes[lo + j] == host[start + j] { j += 1 }
                    if j == labelLen { found = edgeTarget[e]; break }
                }
                e += 1
            }

            if found < 0 { return deepest }
            nodeID = Int(found)
            if let p = nodePayload[nodeID] { deepest = p }

            end = start - 1   // advance past this label and its separator
        }

        return deepest
    }
}
