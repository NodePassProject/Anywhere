//
//  FlatLabelTrie.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import Foundation

// MARK: - Succinct bitvector
//
// A LOUDS-encoded trie navigates by rank/select over two bitvectors rather than
// by following stored child pointers. This is a minimal rank/select structure:
// the rank index is one `UInt32` cumulative popcount per 64-bit word (~0.5 bits
// of overhead per stored bit). `lookup` only needs `rank1` and `select0`; both
// are O(log words) here (a binary search over the rank index plus an in-word
// scan), which is more than fast enough at this scale and keeps the structure
// tiny. Value type with COW arrays, so a frozen trie is safe for concurrent reads.

fileprivate struct LOUDSBitVector {
    private(set) var words: ContiguousArray<UInt64> = []
    private(set) var rank: ContiguousArray<UInt32> = []      // rank[w] = #ones in words[0..<w]
    private(set) var nbits: Int = 0

    mutating func append(_ bit: Bool) {
        let w = nbits >> 6
        if w >= words.count { words.append(0) }
        if bit { words[w] |= (UInt64(1) << UInt64(nbits & 63)) }
        nbits += 1
    }

    /// Builds the cumulative-popcount index. Call once after all `append`s.
    mutating func build() {
        rank = ContiguousArray(repeating: 0, count: words.count + 1)
        var acc: UInt32 = 0
        for i in 0..<words.count {
            rank[i] = acc
            acc &+= UInt32(words[i].nonzeroBitCount)
        }
        rank[words.count] = acc
    }

    /// Number of set bits in `[0, i)`. `i` may equal `nbits`.
    @inline(__always)
    func rank1(_ i: Int) -> Int {
        let w = i >> 6, rem = i & 63
        var r = Int(rank[w])
        if rem != 0 { r += (words[w] & ((UInt64(1) << UInt64(rem)) &- 1)).nonzeroBitCount }
        return r
    }

    /// 0-based position of the `k`-th zero (1-based `k`). Padding bits past
    /// `nbits` in the final word are masked off so they are never selected.
    @inline(__always)
    func select0(_ k: Int) -> Int {
        var lo = 0, hi = words.count
        while lo < hi {
            let mid = (lo + hi) >> 1
            let bitsUpTo = Swift.min((mid + 1) << 6, nbits)
            if bitsUpTo - Int(rank[mid + 1]) < k { lo = mid + 1 } else { hi = mid }
        }
        let w = lo
        var remaining = k - ((w << 6) - Int(rank[w]))
        let valid = Swift.min(64, nbits - (w << 6))
        let mask: UInt64 = valid >= 64 ? ~0 : ((UInt64(1) << UInt64(valid)) &- 1)
        var word = (~words[w]) & mask
        var pos = 0
        while true {
            pos = word.trailingZeroBitCount
            remaining -= 1
            if remaining == 0 { break }
            word &= word &- 1
        }
        return (w << 6) + pos
    }

    var byteSize: Int { words.count * 8 + rank.count * MemoryLayout<UInt32>.stride }
}

// MARK: - FlatLabelTrie
//
// A reversed-label domain-suffix trie. `freeze()`/`buildBulk()` flatten the
// scratch tree into a LOUDS succinct representation so lookup never allocates;
// inserting after freeze traps, and the frozen state is safe for concurrent reads.
//
// The frozen form is a Level-Order Unary Degree Sequence (LOUDS) trie:
//   • `louds`  — the structure. "10" for a virtual super-root, then for each
//                node in BFS order ("1" per child) + "0". Node `i` is the
//                `(i+1)`-th set bit; a node's children occupy a contiguous BFS-id
//                range, so each descent is one `select0` (to find the child
//                block) + a binary search over the children's labels.
//   • `term`   — one bit per node: set iff the node carries a payload.
//   • `labelBytes`/`labelOff` — each node's incoming edge label.
//   • `payloadTable` — payloads for terminal nodes only, in terminal-rank order.
//
// Versus the previous CSR encoding this drops the per-node `edgeRangeStart` and
// per-edge `edgeTarget` `Int32` arrays (child links are implicit in `louds`) and
// the mostly-nil `[Payload?]` array (payloads are kept only at terminals),
// roughly halving the footprint for large suffix sets while making lookups
// faster than the old linear edge scan at high fan-out (e.g. many `*.com` rules).
struct FlatLabelTrie<Payload> {

    // MARK: - Build state (dropped on freeze)

    private final class BuildNode {
        var children: [String: BuildNode] = [:]
        var payload: Payload?
    }

    private var buildRoot: BuildNode? = BuildNode()

    // MARK: - Frozen state (populated by freeze / buildBulk)

    fileprivate var louds = LOUDSBitVector()
    fileprivate var term  = LOUDSBitVector()

    /// Node `i`'s incoming label is `labelBytes[labelOff[i] ..< labelOff[i + 1]]`.
    /// `labelOff.count == nodeCount + 1`; the root (node 0) has an empty label.
    fileprivate var labelOff: ContiguousArray<Int32> = []
    fileprivate var labelBytes: ContiguousArray<UInt8> = []

    /// Payloads for terminal nodes only, in ascending node order. The payload of
    /// terminal node `i` is `payloadTable[term.rank1(i)]`.
    fileprivate var payloadTable: ContiguousArray<Payload> = []

    fileprivate var nodeCount = 0

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

    /// Flattens the scratch tree into the LOUDS arrays. Subsequent inserts trap;
    /// repeat freezes are no-ops.
    mutating func freeze() {
        guard !frozen else { return }
        guard let root = buildRoot else { frozen = true; return }

        var queue: [BuildNode] = []
        queue.reserveCapacity(64)
        queue.append(root)

        louds.append(true); louds.append(false)         // virtual super-root "10"
        var labelOffsets: [Int32] = [0, 0]              // node 0 (root) has an empty label
        var bytes: [UInt8] = []
        var termFlags: [Bool] = [false]                 // the root never matches
        var payloads: [Payload] = []

        var head = 0
        while head < queue.count {
            let node = queue[head]; head += 1
            // Byte-order child sort so the binary-search comparator always agrees,
            // and so this path matches buildBulk's ordering for ASCII/punycode labels.
            let sortedChildren = node.children.sorted { $0.key.utf8.lexicographicallyPrecedes($1.key.utf8) }
            for (label, child) in sortedChildren {
                louds.append(true)
                queue.append(child)
                bytes.append(contentsOf: label.utf8)
                labelOffsets.append(Int32(bytes.count))
                if let p = child.payload { termFlags.append(true); payloads.append(p) }
                else { termFlags.append(false) }
            }
            louds.append(false)
        }

        nodeCount = queue.count
        for f in termFlags { term.append(f) }
        louds.build(); term.build()
        labelOff = ContiguousArray(labelOffsets)
        labelBytes = ContiguousArray(bytes)
        payloadTable = ContiguousArray(payloads)

        buildRoot = nil
        frozen = true
    }

    // MARK: - Read API

    /// Payload at the deepest matching node for `host` (raw UTF-8, pre-lowercased),
    /// or nil; nil before freeze(). The root's payload is intentionally never a match.
    func lookup(_ host: UnsafeBufferPointer<UInt8>) -> Payload? {
        guard frozen, nodeCount > 0 else { return nil }

        var deepest: Payload? = nil
        var node = 0

        // Split labels right-to-left in place; empty labels are skipped, matching
        // `String.split` on the build side.
        let dot = UInt8(ascii: ".")
        var end = host.count
        while end > 0 {
            var start = end
            while start > 0 && host[start - 1] != dot { start -= 1 }
            let labelLen = end - start
            if labelLen == 0 { end = start - 1; continue }

            // Children of `node` occupy the BFS-id range [firstChildID, +childCount),
            // delimited by node's two LOUDS zeros; they are sorted by label.
            let z1 = louds.select0(node + 1)
            let z2 = louds.select0(node + 2)
            let childCount = z2 - z1 - 1
            if childCount == 0 { return deepest }
            let firstChildID = louds.rank1(z1 + 2) - 1

            var lo = firstChildID, hi = firstChildID + childCount
            var found = -1
            while lo < hi {
                let mid = (lo + hi) >> 1
                let o = Int(labelOff[mid]); let n = Int(labelOff[mid + 1]) - o
                let m = Swift.min(n, labelLen)
                var k = 0; var c = 0
                while k < m {
                    let a = labelBytes[o + k], b = host[start + k]
                    if a != b { c = a < b ? -1 : 1; break }
                    k += 1
                }
                if c == 0 { c = (n == labelLen) ? 0 : (n < labelLen ? -1 : 1) }
                if c < 0 { lo = mid + 1 } else if c > 0 { hi = mid } else { found = mid; break }
            }

            if found < 0 { return deepest }
            node = found
            let r = term.rank1(node)
            if term.rank1(node + 1) - r == 1 { deepest = payloadTable[r] }

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
// then BFS-flattens that arena into the LOUDS arrays. Peak memory tracks output,
// not input. A given trie uses one path or the other; `insert`/`freeze` stay for MITM.

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

        // Group children per parent in creation-id space. Because entries were
        // sorted, each parent's children come out label-sorted.
        let n = nodeParent.count
        var cursor = [Int32](repeating: 0, count: n)        // child count, then write cursor
        for i in 1..<n { cursor[Int(nodeParent[i])] += 1 }
        var starts = [Int32](repeating: 0, count: n + 1)
        for v in 0..<n { starts[v + 1] = starts[v] + cursor[v] }
        for v in 0..<n { cursor[v] = starts[v] }
        var targets = [Int32](repeating: 0, count: Int(starts[n]))
        for i in 1..<n {
            let parent = Int(nodeParent[i])
            targets[Int(cursor[parent])] = Int32(i)
            cursor[parent] += 1
        }

        // BFS the creation-id tree to assign BFS ids and emit LOUDS. Children are
        // contiguous per parent and already label-sorted, so the emitted order is
        // BFS with label-sorted siblings — exactly what lookup's binary search needs.
        var order: [Int32] = []                             // bfs id -> creation id
        order.reserveCapacity(n)
        order.append(0)

        louds.append(true); louds.append(false)             // virtual super-root
        var labelOffsets: [Int32] = [0, 0]
        var bytes: [UInt8] = []
        bytes.reserveCapacity(n * 7)
        var termFlags: [Bool] = [false]
        var payloadsOut: [Payload] = []

        var head = 0
        while head < order.count {
            let cid = Int(order[head]); head += 1
            let lo = Int(starts[cid]), hi = Int(starts[cid + 1])
            for e in lo..<hi {
                let childCid = Int(targets[e])
                order.append(Int32(childCid))
                louds.append(true)
                let off = Int(nodeLabelOffset[childCid]), len = Int(nodeLabelLength[childCid])
                for j in 0..<len { bytes.append(base[off + j]) }
                labelOffsets.append(Int32(bytes.count))
                if let p = payloads[childCid] { termFlags.append(true); payloadsOut.append(p) }
                else { termFlags.append(false) }
            }
            louds.append(false)
        }

        nodeCount = order.count
        for f in termFlags { term.append(f) }
        louds.build(); term.build()
        labelOff = ContiguousArray(labelOffsets)
        labelBytes = ContiguousArray(bytes)
        payloadTable = ContiguousArray(payloadsOut)
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
            guard let labelA = a else { return -1 }
            guard let lb = b else { return 1 }
            let n = min(labelA.length, lb.length)
            var k = 0
            while k < n {
                let x = base[labelA.start + k], y = base[lb.start + k]
                if x != y { return x < y ? -1 : 1 }
                k += 1
            }
            if labelA.length != lb.length { return labelA.length < lb.length ? -1 : 1 }
        }
    }
}
