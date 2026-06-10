//
//  FlatLabelTrie.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

/// Reverse-label trie for domain-suffix matching: lookup walks the host's labels
/// right-to-left and returns the payload at the deepest visited node. freeze()
/// flattens the scratch tree into CSR arrays so lookup never allocates; insert
/// after freeze traps, and the frozen state is safe for concurrent reads.
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

    /// CSR edge ranges: node `i`'s edges live at `[edgeRangeStart[i], edgeRangeStart[i + 1])`.
    /// Length is `nodeCount + 1` once frozen.
    private var edgeRangeStart: ContiguousArray<Int32> = []

    /// Edge labels as raw UTF-8 bytes in BFS row order: edge `e`'s label is
    /// `edgeLabelBytes[edgeLabelOffset[e] ..< edgeLabelOffset[e + 1]]`, its target
    /// node `edgeTarget[e]`. `edgeLabelOffset.count == edgeCount + 1`.
    private var edgeLabelOffset: ContiguousArray<Int32> = []
    private var edgeLabelBytes: ContiguousArray<UInt8> = []
    private var edgeTarget: ContiguousArray<Int32> = []

    // MARK: - State

    private var frozen = false
    private(set) var isEmpty: Bool = true

    // MARK: - Build API

    /// Inserts a payload at the terminal for `suffix` (pre-normalized: lowercased,
    /// dot-separated). Returns `true` iff a new terminal was created.
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

    /// Flattens the trie. Subsequent inserts trap; repeat freezes are no-ops.
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

    /// Payload at the deepest matching node for `host` (raw UTF-8, pre-lowercased),
    /// or nil; nil before freeze(). The root's payload is intentionally never a match.
    func lookup(_ host: UnsafeBufferPointer<UInt8>) -> Payload? {
        guard frozen, !nodePayload.isEmpty else { return nil }

        var deepest: Payload? = nil
        var nodeID = 0

        // Split labels right-to-left in place; empty labels are skipped, matching
        // `String.split` on the build side.
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
