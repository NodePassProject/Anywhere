//
//  FlatLabelTrie.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

/// freeze() flattens the scratch tree into CSR arrays so lookup never allocates;
/// insert after freeze traps, and the frozen state is safe for concurrent reads.
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
                end = start - 1
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

            end = start - 1
        }

        return deepest
    }
}

// MARK: - Bulk construction
//
// `buildBulk` avoids the `insert`/`freeze` `BuildNode` scratch tree, whose
// `[String: BuildNode]` dictionaries run to tens of MB for hundreds of thousands
// of sibling suffixes — transient scaffolding that overflowed the Network
// Extension memory limit. It sorts entries into reversed-label order, builds a
// compact parallel-array node arena (labels referenced by offset, not copied),
// and flattens to the same CSR arrays. Peak memory tracks output, not input. A
// given trie uses one path or the other; `insert`/`freeze` stay for MITM.

extension FlatLabelTrie {
    /// `offset`/`length` delimit the suffix's lowercased UTF-8 bytes in the
    /// `buildBulk` buffer; `order` (collection index) breaks ties between identical
    /// suffixes so the last-collected one wins, matching `insert`'s overwrite.
    struct BulkEntry {
        var offset: Int32
        var length: Int32
        var payload: Payload
        var order: Int32
    }

    /// Builds the frozen trie from `entries` (sorted in place). `base` must remain
    /// valid for the call; matched label bytes are copied into the trie before it
    /// returns, so `base` need not outlive it.
    mutating func buildBulk(base: UnsafeBufferPointer<UInt8>, entries: inout [BulkEntry]) {
        guard !frozen else { return }
        frozen = true
        buildRoot = nil
        isEmpty = entries.isEmpty

        let dot = UInt8(ascii: ".")

        // Reversed-label order (TLD first), ties broken by collection order so a
        // repeated suffix's last occurrence overwrites.
        entries.sort { a, b in
            let c = Self.compareReversedLabels(base, a.offset, a.length, b.offset, b.length, dot: dot)
            return c != 0 ? c < 0 : a.order < b.order
        }

        // Node arena (root = node 0). Labels reference `base` by offset/length.
        var nodeParent: [Int32] = [-1]
        var nodeLabelOffset: [Int32] = [0]
        var nodeLabelLength: [Int32] = [0]
        var payloads: [Payload?] = [nil]

        // Open path from root to the deepest current node; `stackLabel*` holds the
        // label of each node above the root, aligned so depth d ↔ index d - 1.
        var stackNode: [Int32] = [0]
        var stackLabelOffset: [Int32] = []
        var stackLabelLength: [Int32] = []

        // Current entry's reversed labels, reused across entries.
        var labelOffset: [Int32] = []
        var labelLength: [Int32] = []
        labelOffset.reserveCapacity(8)
        labelLength.reserveCapacity(8)

        for entry in entries {
            labelOffset.removeAll(keepingCapacity: true)
            labelLength.removeAll(keepingCapacity: true)
            var end = Int(entry.offset) + Int(entry.length)
            let low = Int(entry.offset)
            while let label = Self.nextLabel(base, &end, low, dot) {
                labelOffset.append(Int32(label.start))
                labelLength.append(Int32(label.length))
            }

            // Longest run of leading labels shared with the open path.
            var matched = 0
            let openLabels = stackNode.count - 1
            while matched < labelOffset.count, matched < openLabels,
                  Self.bytesEqual(base, labelOffset[matched], labelLength[matched],
                                  stackLabelOffset[matched], stackLabelLength[matched]) {
                matched += 1
            }

            // Drop the diverged tail of the open path.
            if stackNode.count > matched + 1 {
                stackNode.removeLast(stackNode.count - (matched + 1))
                stackLabelOffset.removeLast(stackLabelOffset.count - matched)
                stackLabelLength.removeLast(stackLabelLength.count - matched)
            }

            // Append nodes for the labels past the shared prefix.
            var k = matched
            while k < labelOffset.count {
                let id = Int32(nodeParent.count)
                nodeParent.append(stackNode[stackNode.count - 1])
                nodeLabelOffset.append(labelOffset[k])
                nodeLabelLength.append(labelLength[k])
                payloads.append(nil)
                stackNode.append(id)
                stackLabelOffset.append(labelOffset[k])
                stackLabelLength.append(labelLength[k])
                k += 1
            }

            // Deepest node carries the payload (root for an empty suffix — never matched).
            payloads[Int(stackNode[stackNode.count - 1])] = entry.payload
        }

        // Flatten the arena to CSR. Children are contiguous per parent; because
        // entries were sorted, each parent's children are also label-sorted.
        let nodeCount = nodeParent.count
        var cursor = [Int32](repeating: 0, count: nodeCount)        // child count, then write cursor
        for i in 1..<nodeCount { cursor[Int(nodeParent[i])] += 1 }

        var starts = [Int32](repeating: 0, count: nodeCount + 1)
        for n in 0..<nodeCount { starts[n + 1] = starts[n] + cursor[n] }
        let edgeCount = Int(starts[nodeCount])

        for n in 0..<nodeCount { cursor[n] = starts[n] }            // reuse as write cursor
        var targets = [Int32](repeating: 0, count: edgeCount)
        for i in 1..<nodeCount {
            let parent = Int(nodeParent[i])
            targets[Int(cursor[parent])] = Int32(i)
            cursor[parent] += 1
        }

        var labelOffsets = [Int32](repeating: 0, count: edgeCount + 1)
        var labelBytes: [UInt8] = []
        labelBytes.reserveCapacity(edgeCount * 8)
        for e in 0..<edgeCount {
            let node = Int(targets[e])
            let off = Int(nodeLabelOffset[node])
            let len = Int(nodeLabelLength[node])
            for k in 0..<len { labelBytes.append(base[off + k]) }
            labelOffsets[e + 1] = Int32(labelBytes.count)
        }

        nodePayload = ContiguousArray(payloads)
        edgeRangeStart = ContiguousArray(starts)
        edgeLabelOffset = ContiguousArray(labelOffsets)
        edgeLabelBytes = ContiguousArray(labelBytes)
        edgeTarget = ContiguousArray(targets)
    }

    /// Next label scanning right-to-left from `end` (exclusive) down to `low`,
    /// skipping empty labels — matching `split(separator: ".")` then `.reversed()`.
    /// Advances `end` past the consumed label and its separator.
    private static func nextLabel(_ base: UnsafeBufferPointer<UInt8>, _ end: inout Int, _ low: Int, _ dot: UInt8) -> (start: Int, length: Int)? {
        while end > low {
            var start = end
            while start > low && base[start - 1] != dot { start -= 1 }
            let length = end - start
            end = start - 1
            if length > 0 { return (start, length) }
        }
        return nil
    }

    private static func bytesEqual(_ base: UnsafeBufferPointer<UInt8>, _ off1: Int32, _ len1: Int32, _ off2: Int32, _ len2: Int32) -> Bool {
        guard len1 == len2 else { return false }
        let a = Int(off1), b = Int(off2)
        var k = 0
        while k < Int(len1) {
            if base[a + k] != base[b + k] { return false }
            k += 1
        }
        return true
    }

    /// Orders two suffixes by label sequence read right-to-left (the trie's
    /// descent order): compare TLD, then next label inward, etc.; a shorter
    /// sequence sorts first. Returns <0, 0, or >0.
    private static func compareReversedLabels(_ base: UnsafeBufferPointer<UInt8>, _ aOff: Int32, _ aLen: Int32, _ bOff: Int32, _ bLen: Int32, dot: UInt8) -> Int {
        var aEnd = Int(aOff) + Int(aLen); let aLow = Int(aOff)
        var bEnd = Int(bOff) + Int(bLen); let bLow = Int(bOff)
        while true {
            let a = nextLabel(base, &aEnd, aLow, dot)
            let b = nextLabel(base, &bEnd, bLow, dot)
            if a == nil && b == nil { return 0 }
            guard let la = a else { return -1 }
            guard let lb = b else { return 1 }
            let n = min(la.length, lb.length)
            var k = 0
            while k < n {
                let x = base[la.start + k], y = base[lb.start + k]
                if x != y { return x < y ? -1 : 1 }
                k += 1
            }
            if la.length != lb.length { return la.length < lb.length ? -1 : 1 }
        }
    }
}
