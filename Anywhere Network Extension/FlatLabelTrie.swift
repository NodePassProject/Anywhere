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
/// at ``freeze()`` time the structure is BFS-laid-out across four flat
/// arrays — node payloads, CSR-style edge ranges, and (label, target)
/// pairs — and the scratch tree is dropped. The frozen form has no
/// per-node heap allocation and no per-node Dictionary, which is the
/// dominant cost of the class-based form.
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
        var children: [Int32: BuildNode] = [:]
        var payload: Payload?
    }

    private var buildRoot: BuildNode? = BuildNode()

    /// Label → small integer ID, populated during build.
    private var labelIDs: [String: Int32] = [:]

    // MARK: - Frozen state (populated by freeze)

    /// `nodePayload[i]` is the payload at node `i`, or nil. Root is 0.
    private var nodePayload: ContiguousArray<Payload?> = []

    /// CSR-style edge ranges. Node `i`'s edges live at indices
    /// `[edgeRangeStart[i], edgeRangeStart[i + 1])`. Length is
    /// `nodeCount + 1` once frozen.
    private var edgeRangeStart: ContiguousArray<Int32> = []

    /// Edge label IDs and target node IDs, packed in BFS row order.
    /// `edgeLabel.count == edgeTarget.count == total edge count`.
    private var edgeLabel: ContiguousArray<Int32> = []
    private var edgeTarget: ContiguousArray<Int32> = []

    /// Frozen copy of ``labelIDs``. Empty until freeze.
    private var labelTable: [String: Int32] = [:]

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
        precondition(!frozen, "FlatLabelTrie: insert after freeze")

        var node = buildRoot!
        for labelSub in suffix.split(separator: ".").reversed() {
            let label = String(labelSub)
            let id: Int32
            if let existing = labelIDs[label] {
                id = existing
            } else {
                id = Int32(labelIDs.count)
                labelIDs[label] = id
            }
            if let child = node.children[id] {
                node = child
            } else {
                let child = BuildNode()
                node.children[id] = child
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
        var labels: [Int32] = []
        var targets: [Int32] = []

        var head = 0
        while head < queue.count {
            let node = queue[head]; head += 1
            // Sort by label ID for a stable, cache-friendly edge order.
            let sortedChildren = node.children.sorted { $0.key < $1.key }
            for (labelID, child) in sortedChildren {
                let childID = Int32(queue.count)
                queue.append(child)
                payloads.append(child.payload)
                labels.append(labelID)
                targets.append(childID)
            }
            edgeStarts.append(Int32(labels.count))
        }

        nodePayload = ContiguousArray(payloads)
        edgeRangeStart = ContiguousArray(edgeStarts)
        edgeLabel = ContiguousArray(labels)
        edgeTarget = ContiguousArray(targets)
        labelTable = labelIDs

        buildRoot = nil
        labelIDs = [:]
        frozen = true
    }

    // MARK: - Read API

    /// Returns the payload at the deepest matching node along the
    /// reverse-label path of `host`, or nil. The host must be
    /// pre-normalized (lowercased) and dot-separated. Returns nil
    /// before ``freeze()``. The root's payload is intentionally not
    /// considered a match (matches existing label-trie semantics).
    func lookup(_ host: String) -> Payload? {
        guard frozen, !nodePayload.isEmpty else { return nil }

        var deepest: Payload? = nil
        var nodeID: Int = 0

        for labelSub in host.split(separator: ".").reversed() {
            guard let labelID = labelTable[String(labelSub)] else { return deepest }

            let start = Int(edgeRangeStart[nodeID])
            let end = Int(edgeRangeStart[nodeID + 1])

            var found: Int32 = -1
            var i = start
            while i < end {
                if edgeLabel[i] == labelID {
                    found = edgeTarget[i]
                    break
                }
                i += 1
            }

            if found < 0 { return deepest }
            nodeID = Int(found)
            if let p = nodePayload[nodeID] { deepest = p }
        }

        return deepest
    }
}
