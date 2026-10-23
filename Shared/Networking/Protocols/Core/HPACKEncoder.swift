//
//  HPACKEncoder.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation

nonisolated struct HPACKField: Hashable, Sendable {
    let name: String
    let value: String
}

nonisolated struct HPACKIndexingHints: Sendable {
    var neverIndexed: Set<String> = []
    var indexedFields: Set<HPACKField> = []
}

nonisolated class HPACKDecoder {
    private static let defaultMaxTableSize = 4096

    static let maxDecodedHeaderListSize = 256 * 1024

    private var dynamicTable: [(name: String, value: String)] = []

    private var currentSize = 0

    private let protocolMaxSize = HPACKDecoder.defaultMaxTableSize

    private var maxSize = HPACKDecoder.defaultMaxTableSize

    func decodeHeaders(from data: Data) -> (fields: [(name: String, value: String)], neverIndexed: Set<String>)? {
        decode(data, collectsIndexedFields: false).map { ($0.fields, $0.indexing.neverIndexed) }
    }

    func decodeHeadersWithIndexing(from data: Data) -> (fields: [(name: String, value: String)], indexing: HPACKIndexingHints)? {
        decode(data, collectsIndexedFields: true)
    }

    private func decode(_ data: Data, collectsIndexedFields: Bool) -> (fields: [(name: String, value: String)], indexing: HPACKIndexingHints)? {
        var headers: [(name: String, value: String)] = []
        var indexing = HPACKIndexingHints()
        var offset = data.startIndex
        var listSize = 0
        func account(_ name: String, _ value: String) -> Bool {
            listSize += Self.wireOctetCount(name) + Self.wireOctetCount(value) + 32
            return listSize <= Self.maxDecodedHeaderListSize
        }

        while offset < data.endIndex {
            let byte = data[offset]

            if byte & 0x80 != 0 {
                let index = HPACKEncoder.decodeInteger(from: data, at: &offset, prefixBits: 7)
                guard let index, let entry = HPACKEncoder.lookupEntry(index, dynamicTable: dynamicTable) else {
                    return nil
                }
                headers.append(entry)
                guard account(entry.name, entry.value) else { return nil }
                if collectsIndexedFields, index > HPACKEncoder.staticTableCount {
                    indexing.indexedFields.insert(HPACKField(name: entry.name, value: entry.value))
                }

            } else if byte & 0xC0 == 0x40 {
                guard let (name, value) = HPACKEncoder.decodeLiteral(
                    from: data,
                    at: &offset,
                    prefixBits: 6,
                    dynamicTable: dynamicTable
                ) else { return nil }
                headers.append((name, value))
                guard account(name, value) else { return nil }
                insertWithEviction(name: name, value: value)
                if collectsIndexedFields {
                    indexing.indexedFields.insert(HPACKField(name: name, value: value))
                }

            } else if byte & 0xF0 == 0x00 || byte & 0xF0 == 0x10 {
                let isNeverIndexed = (byte & 0xF0 == 0x10)
                guard let (name, value) = HPACKEncoder.decodeLiteral(
                    from: data,
                    at: &offset,
                    prefixBits: 4,
                    dynamicTable: dynamicTable
                ) else { return nil }
                headers.append((name, value))
                guard account(name, value) else { return nil }
                if isNeverIndexed { indexing.neverIndexed.insert(name.lowercased()) }

            } else if byte & 0xE0 == 0x20 {
                guard let newSize = HPACKEncoder.decodeInteger(from: data, at: &offset, prefixBits: 5) else {
                    return nil
                }
                guard newSize <= protocolMaxSize else { return nil }
                maxSize = newSize
                evictToFit()
            } else {
                return nil
            }
        }

        return (headers, indexing)
    }

    private func entrySize(name: String, value: String) -> Int {
        Self.wireOctetCount(name) + Self.wireOctetCount(value) + 32
    }

    static func wireOctetCount(_ headerString: String) -> Int {
        var octetCount = 0
        for byte in headerString.utf8 where byte != 0xC2 && byte != 0xC3 {
            octetCount += 1
        }
        return octetCount
    }

    private func insertWithEviction(name: String, value: String) {
        let size = entrySize(name: name, value: value)
        while currentSize + size > maxSize, let last = dynamicTable.last {
            currentSize -= entrySize(name: last.name, value: last.value)
            dynamicTable.removeLast()
        }
        guard size <= maxSize else {
            return
        }
        dynamicTable.insert((name, value), at: 0)
        currentSize += size
    }

    private func evictToFit() {
        while currentSize > maxSize, let last = dynamicTable.last {
            currentSize -= entrySize(name: last.name, value: last.value)
            dynamicTable.removeLast()
        }
    }
}

nonisolated enum HPACKEncoder {

    // MARK: - CONNECT Request Encoding

    static func encodeConnectRequest(
        authority: String,
        extraHeaders: [(name: String, value: String)]
    ) -> Data {
        var block = Data()
        encodeLiteralWithoutIndexing(nameIndex: 2, value: "CONNECT", into: &block)
        encodeLiteralWithoutIndexing(nameIndex: 1, value: authority, into: &block)
        for header in extraHeaders {
            let name = lowercasedName(header.name)
            if let nameIdx = staticTableNameIndex[name] {
                encodeLiteralWithoutIndexing(nameIndex: nameIdx, value: header.value, into: &block)
            } else {
                encodeLiteralWithoutIndexing(name: name, value: header.value, into: &block)
            }
        }
        return block
    }

    // MARK: - Generic Header Block Encoding

    static func encodeHeaderBlock(
        _ headers: [(name: String, value: String)],
        neverIndexed: Set<String> = []
    ) -> Data {
        var block = Data()
        block.reserveCapacity(headers.reduce(0) { $0 + $1.name.utf8.count + $1.value.utf8.count + 4 })
        for header in headers {
            let name = lowercasedName(header.name)
            if !neverIndexed.isEmpty, neverIndexed.contains(name) {
                if let nameIdx = staticTableNameIndex[name] {
                    encodeLiteralNeverIndexed(nameIndex: nameIdx, value: header.value, into: &block)
                } else {
                    encodeLiteralNeverIndexed(name: name, value: header.value, into: &block)
                }
            } else if let fullIndex = staticTableFullIndex(name, header.value) {
                encodeIndexed(fullIndex, into: &block)
            } else if let nameIdx = staticTableNameIndex[name] {
                encodeLiteralWithoutIndexing(nameIndex: nameIdx, value: header.value, into: &block)
            } else {
                encodeLiteralWithoutIndexing(name: name, value: header.value, into: &block)
            }
        }
        return block
    }

    // MARK: - Response Decoding

    static func decodeHeaders(from data: Data) -> [(name: String, value: String)]? {
        var headers: [(name: String, value: String)] = []
        var offset = data.startIndex
        var dynamicTable: [(name: String, value: String)] = []

        while offset < data.endIndex {
            let byte = data[offset]

            if byte & 0x80 != 0 {
                let index = decodeInteger(from: data, at: &offset, prefixBits: 7)
                guard let index, let entry = lookupEntry(index, dynamicTable: dynamicTable) else {
                    return nil
                }
                headers.append(entry)

            } else if byte & 0xC0 == 0x40 {
                guard let (name, value) = decodeLiteral(
                    from: data,
                    at: &offset,
                    prefixBits: 6,
                    dynamicTable: dynamicTable
                ) else { return nil }
                headers.append((name, value))
                dynamicTable.insert((name, value), at: 0)

            } else if byte & 0xF0 == 0x00 || byte & 0xF0 == 0x10 {
                guard let (name, value) = decodeLiteral(
                    from: data,
                    at: &offset,
                    prefixBits: 4,
                    dynamicTable: dynamicTable
                ) else { return nil }
                headers.append((name, value))

            } else if byte & 0xE0 == 0x20 {
                let _ = decodeInteger(from: data, at: &offset, prefixBits: 5)
            } else {
                return nil
            }
        }

        return headers
    }

    // MARK: - Integer Encoding

    static func encodeInteger(_ value: Int, prefixBits: Int, into data: inout Data) {
        encodeInteger(value, prefixBits: prefixBits, flags: 0, into: &data)
    }

    fileprivate static func encodeInteger(_ value: Int, prefixBits: Int, flags: UInt8, into data: inout Data) {
        let maxPrefix = (1 << prefixBits) - 1
        if value < maxPrefix {
            data.append(flags | UInt8(value))
        } else {
            data.append(flags | UInt8(maxPrefix))
            var remaining = value - maxPrefix
            while remaining >= 128 {
                data.append(UInt8(remaining % 128 + 128))
                remaining /= 128
            }
            data.append(UInt8(remaining))
        }
    }

    static func decodeInteger(from data: Data, at offset: inout Int, prefixBits: Int) -> Int? {
        guard offset < data.endIndex else { return nil }
        let maxPrefix = (1 << prefixBits) - 1
        var value = Int(data[offset] & UInt8(maxPrefix))
        offset += 1

        if value < maxPrefix {
            return value
        }

        var shiftBits = 0
        repeat {
            guard offset < data.endIndex else { return nil }
            guard shiftBits < 32 else { return nil }
            let b = data[offset]
            offset += 1
            let (next, overflow) = value.addingReportingOverflow(Int(b & 0x7F) << shiftBits)
            guard !overflow else { return nil }
            value = next
            shiftBits += 7
            if b & 0x80 == 0 { break }
        } while true

        return value
    }

    // MARK: - String Encoding

    static func encodeString(_ string: String, into data: inout Data) {
        let appendedASCII = string.utf8.withContiguousStorageIfAvailable { bytes -> Bool in
            guard !bytes.contains(where: { $0 >= 0x80 }) else { return false }
            encodeInteger(bytes.count, prefixBits: 7, flags: 0x00, into: &data)
            data.append(bytes)
            return true
        } ?? false
        guard !appendedASCII else { return }
        let bytes: [UInt8]
        if let latin1 = string.data(using: .isoLatin1) {
            bytes = [UInt8](latin1)
        } else {
            bytes = [UInt8](string.utf8)
        }
        encodeInteger(bytes.count, prefixBits: 7, flags: 0x00, into: &data)
        data.append(contentsOf: bytes)
    }

    static func decodeString(from data: Data, at offset: inout Int) -> String? {
        guard offset < data.endIndex else { return nil }
        let huffman = data[offset] & 0x80 != 0
        guard let length = decodeInteger(from: data, at: &offset, prefixBits: 7) else { return nil }
        guard length >= 0, length <= data.endIndex - offset else { return nil }

        let stringData = data[offset..<(offset + length)]
        offset += length

        if huffman {
            guard let decoded = HPACKHuffman.decode(stringData) else { return nil }
            return decoded.withUnsafeBytes { latin1String($0) }
        } else {
            return stringData.withUnsafeBytes { latin1String($0) }
        }
    }

    private static func latin1String(_ bytes: UnsafeRawBufferPointer) -> String {
        guard bytes.contains(where: { $0 >= 0x80 }) else {
            return String(decoding: bytes, as: UTF8.self)
        }
        var scalars = String.UnicodeScalarView()
        for byte in bytes {
            scalars.append(Unicode.Scalar(byte))
        }
        return String(scalars)
    }

    // MARK: - Indexed Header Encoding

    private static func encodeIndexed(_ index: Int, into data: inout Data) {
        encodeInteger(index, prefixBits: 7, flags: 0x80, into: &data)
    }

    // MARK: - Literal Header Encoding

    private static func encodeLiteralWithoutIndexing(nameIndex: Int, value: String, into data: inout Data) {
        encodeInteger(nameIndex, prefixBits: 4, flags: 0x00, into: &data)
        encodeString(value, into: &data)
    }

    private static func encodeLiteralWithoutIndexing(name: String, value: String, into data: inout Data) {
        data.append(0x00)
        encodeString(name, into: &data)
        encodeString(value, into: &data)
    }

    private static func encodeLiteralNeverIndexed(nameIndex: Int, value: String, into data: inout Data) {
        encodeInteger(nameIndex, prefixBits: 4, flags: 0x10, into: &data)
        encodeString(value, into: &data)
    }

    private static func encodeLiteralNeverIndexed(name: String, value: String, into data: inout Data) {
        data.append(0x10)
        encodeString(name, into: &data)
        encodeString(value, into: &data)
    }

    // MARK: - Literal Header Decoding

    static func decodeLiteral(
        from data: Data,
        at offset: inout Int,
        prefixBits: Int,
        dynamicTable: [(name: String, value: String)]
    ) -> (name: String, value: String)? {
        guard let nameIndex = decodeInteger(from: data, at: &offset, prefixBits: prefixBits) else {
            return nil
        }

        let name: String
        if nameIndex == 0 {
            guard let n = decodeString(from: data, at: &offset) else { return nil }
            name = n
        } else {
            guard let entry = lookupEntry(nameIndex, dynamicTable: dynamicTable) else { return nil }
            name = entry.name
        }

        guard let value = decodeString(from: data, at: &offset) else { return nil }
        return (name, value)
    }

    // MARK: - Table Lookup

    static func lookupEntry(
        _ index: Int,
        dynamicTable: [(name: String, value: String)]
    ) -> (name: String, value: String)? {
        guard index >= 1 else { return nil }
        if index <= staticTable.count {
            return staticTable[index - 1]
        }
        let dynIndex = index - staticTable.count - 1
        guard dynIndex < dynamicTable.count else { return nil }
        return dynamicTable[dynIndex]
    }

    fileprivate static func lowercasedName(_ name: String) -> String {
        name.utf8.contains(where: { $0 >= 0x80 || (0x41...0x5A).contains($0) }) ? name.lowercased() : name
    }

    fileprivate static let staticTableNameIndex: [String: Int] = {
        var indices: [String: Int] = [:]
        for (i, entry) in staticTable.enumerated() where indices[entry.name] == nil {
            indices[entry.name] = i + 1
        }
        return indices
    }()

    fileprivate static func staticTableFullIndex(_ name: String, _ value: String) -> Int? {
        guard var index = staticTableNameIndex[name] else { return nil }
        while index <= staticTable.count, staticTable[index - 1].name == name {
            if staticTable[index - 1].value == value { return index }
            index += 1
        }
        return nil
    }

    fileprivate static var staticTableCount: Int { staticTable.count }

    // MARK: - HPACK Static Table (RFC 7541 Appendix A)

    private static let staticTable: [(name: String, value: String)] = [
        (":authority", ""),                          // 1
        (":method", "GET"),                          // 2
        (":method", "POST"),                         // 3
        (":path", "/"),                              // 4
        (":path", "/index.html"),                    // 5
        (":scheme", "http"),                         // 6
        (":scheme", "https"),                        // 7
        (":status", "200"),                          // 8
        (":status", "204"),                          // 9
        (":status", "206"),                          // 10
        (":status", "304"),                          // 11
        (":status", "400"),                          // 12
        (":status", "404"),                          // 13
        (":status", "500"),                          // 14
        ("accept-charset", ""),                      // 15
        ("accept-encoding", "gzip, deflate"),        // 16
        ("accept-language", ""),                     // 17
        ("accept-ranges", ""),                       // 18
        ("accept", ""),                              // 19
        ("access-control-allow-origin", ""),         // 20
        ("age", ""),                                 // 21
        ("allow", ""),                               // 22
        ("authorization", ""),                       // 23
        ("cache-control", ""),                       // 24
        ("content-disposition", ""),                 // 25
        ("content-encoding", ""),                    // 26
        ("content-language", ""),                    // 27
        ("content-length", ""),                      // 28
        ("content-location", ""),                    // 29
        ("content-range", ""),                       // 30
        ("content-type", ""),                        // 31
        ("cookie", ""),                              // 32
        ("date", ""),                                // 33
        ("etag", ""),                                // 34
        ("expect", ""),                              // 35
        ("expires", ""),                             // 36
        ("from", ""),                                // 37
        ("host", ""),                                // 38
        ("if-match", ""),                            // 39
        ("if-modified-since", ""),                   // 40
        ("if-none-match", ""),                       // 41
        ("if-range", ""),                            // 42
        ("if-unmodified-since", ""),                 // 43
        ("last-modified", ""),                       // 44
        ("link", ""),                                // 45
        ("location", ""),                            // 46
        ("max-forwards", ""),                        // 47
        ("proxy-authenticate", ""),                  // 48
        ("proxy-authorization", ""),                 // 49
        ("range", ""),                               // 50
        ("referer", ""),                             // 51
        ("refresh", ""),                             // 52
        ("retry-after", ""),                         // 53
        ("server", ""),                              // 54
        ("set-cookie", ""),                          // 55
        ("strict-transport-security", ""),           // 56
        ("transfer-encoding", ""),                   // 57
        ("user-agent", ""),                          // 58
        ("vary", ""),                                // 59
        ("via", ""),                                 // 60
        ("www-authenticate", ""),                    // 61
    ]
}

// MARK: - Dynamic Table Encoder

nonisolated final class HPACKDynamicEncoder {
    static let defaultMaxTableSize = 4096

    private struct Entry {
        let field: HPACKField
        let size: Int
    }

    private let preferredMaxSize: Int
    private var maxSize: Int
    private var currentSize = 0
    private var entries: [Entry] = []
    private var head = 0
    private var insertedCount = 0
    private var fieldIDs: [HPACKField: Int] = [:]
    private var nameIDs: [String: Int] = [:]
    private var pendingMinimumSize: Int?
    private var pendingFinalSize: Int?

    init(preferredMaxSize: Int = HPACKDynamicEncoder.defaultMaxTableSize) {
        self.preferredMaxSize = min(preferredMaxSize, Self.defaultMaxTableSize)
        self.maxSize = self.preferredMaxSize
    }

    func setPeerMaxTableSize(_ size: Int) {
        let target = min(size, preferredMaxSize)
        guard target != (pendingFinalSize ?? maxSize) else { return }
        pendingMinimumSize = min(pendingMinimumSize ?? target, target)
        pendingFinalSize = target
    }

    func encodeHeaderBlock(
        _ headers: [(name: String, value: String)],
        neverIndexed: Set<String> = [],
        indexedFields: Set<HPACKField> = []
    ) -> Data {
        var block = Data()
        block.reserveCapacity(headers.reduce(8) { $0 + $1.name.utf8.count + $1.value.utf8.count + 4 })
        emitPendingSizeUpdates(into: &block)
        for header in headers {
            let name = HPACKEncoder.lowercasedName(header.name)
            let field = HPACKField(name: name, value: header.value)
            let nameIsASCII = Self.isASCII(name)
            let isASCII = nameIsASCII && Self.isASCII(header.value)
            let nameIndex = HPACKEncoder.staticTableNameIndex[name] ?? (nameIsASCII ? dynamicNameIndex(name) : nil)
            if !neverIndexed.isEmpty, neverIndexed.contains(name) {
                if let nameIndex {
                    HPACKEncoder.encodeInteger(nameIndex, prefixBits: 4, flags: 0x10, into: &block)
                } else {
                    block.append(0x10)
                    HPACKEncoder.encodeString(name, into: &block)
                }
                HPACKEncoder.encodeString(header.value, into: &block)
            } else if let index = HPACKEncoder.staticTableFullIndex(name, header.value) ?? (isASCII ? dynamicFieldIndex(field) : nil) {
                HPACKEncoder.encodeInteger(index, prefixBits: 7, flags: 0x80, into: &block)
            } else {
                let size = name.utf8.count + header.value.utf8.count + 32
                let indexes = isASCII && size * 4 <= maxSize * 3 && indexedFields.contains(field)
                let flags: UInt8 = indexes ? 0x40 : 0x00
                if let nameIndex {
                    HPACKEncoder.encodeInteger(nameIndex, prefixBits: indexes ? 6 : 4, flags: flags, into: &block)
                } else {
                    block.append(flags)
                    HPACKEncoder.encodeString(name, into: &block)
                }
                HPACKEncoder.encodeString(header.value, into: &block)
                if indexes { insert(field, size: size) }
            }
        }
        return block
    }

    private func emitPendingSizeUpdates(into block: inout Data) {
        guard let finalSize = pendingFinalSize else { return }
        if let minimumSize = pendingMinimumSize, minimumSize < finalSize {
            HPACKEncoder.encodeInteger(minimumSize, prefixBits: 5, flags: 0x20, into: &block)
            resize(to: minimumSize)
        }
        HPACKEncoder.encodeInteger(finalSize, prefixBits: 5, flags: 0x20, into: &block)
        resize(to: finalSize)
        pendingMinimumSize = nil
        pendingFinalSize = nil
    }

    private func resize(to size: Int) {
        maxSize = size
        while currentSize > maxSize { evictOldest() }
    }

    private func insert(_ field: HPACKField, size: Int) {
        while currentSize + size > maxSize, head < entries.count { evictOldest() }
        guard size <= maxSize else { return }
        let id = insertedCount
        insertedCount += 1
        entries.append(Entry(field: field, size: size))
        currentSize += size
        fieldIDs[field] = id
        nameIDs[field.name] = id
    }

    private func evictOldest() {
        guard head < entries.count else { return }
        let id = insertedCount - (entries.count - head)
        let entry = entries[head]
        currentSize -= entry.size
        if fieldIDs[entry.field] == id { fieldIDs.removeValue(forKey: entry.field) }
        if nameIDs[entry.field.name] == id { nameIDs.removeValue(forKey: entry.field.name) }
        head += 1
        if head == entries.count {
            entries.removeAll(keepingCapacity: true)
            head = 0
        } else if head >= 32, head * 2 >= entries.count {
            entries.removeFirst(head)
            head = 0
        }
    }

    private func dynamicFieldIndex(_ field: HPACKField) -> Int? {
        fieldIDs[field].map(index(forID:))
    }

    private func dynamicNameIndex(_ name: String) -> Int? {
        nameIDs[name].map(index(forID:))
    }

    private func index(forID id: Int) -> Int {
        HPACKEncoder.staticTableCount + insertedCount - id
    }

    private static func isASCII(_ string: String) -> Bool {
        !string.utf8.contains(where: { $0 >= 0x80 })
    }
}

// MARK: - HPACK Huffman Decoder

nonisolated enum HPACKHuffman {
    private struct Node {
        var left: Int32 = -1
        var right: Int32 = -1
        var symbol: Int16 = -1
    }

    private static let tree: [Node] = {
        var nodes = [Node()]
        for (sym, entry) in huffmanTable.enumerated() {
            let (code, bits) = entry
            var index = 0
            for bitPos in 0..<Int(bits) {
                let bit = (code >> (31 - UInt32(bitPos))) & 1
                if bit == 0 {
                    if nodes[index].left < 0 {
                        nodes.append(Node())
                        nodes[index].left = Int32(nodes.count - 1)
                    }
                    index = Int(nodes[index].left)
                } else {
                    if nodes[index].right < 0 {
                        nodes.append(Node())
                        nodes[index].right = Int32(nodes.count - 1)
                    }
                    index = Int(nodes[index].right)
                }
            }
            nodes[index].symbol = Int16(sym)
        }
        return nodes
    }()

    static func encodedByteLength(_ string: String) -> Int {
        var bits = 0
        for byte in string.utf8 {
            bits += Int(huffmanTable[Int(byte)].1)
        }
        return (bits + 7) / 8
    }

    private struct Transition {
        var next: UInt16 = 0
        var symbol: UInt8 = 0
        var tailBits: UInt8 = 0
        var flags: UInt8 = 0
    }

    private static let emitsSymbol: UInt8 = 0x01
    private static let failsDecode: UInt8 = 0x02
    private static let tailAllOnes: UInt8 = 0x04

    private static let transitions: [Transition] = {
        var stateOfNode = [Int](repeating: -1, count: tree.count)
        var internalNodes: [Int] = []
        for (index, node) in tree.enumerated() where node.symbol < 0 {
            stateOfNode[index] = internalNodes.count
            internalNodes.append(index)
        }
        var table: [Transition] = []
        table.reserveCapacity(internalNodes.count * 16)
        for start in internalNodes {
            for nibble in 0..<16 {
                var node = start
                var transition = Transition(flags: tailAllOnes)
                for shift in stride(from: 3, through: 0, by: -1) {
                    let bit = (nibble >> shift) & 1
                    transition.tailBits += 1
                    if bit == 0 { transition.flags &= ~tailAllOnes }
                    let child = bit == 0 ? tree[node].left : tree[node].right
                    guard child >= 0 else {
                        transition.flags |= failsDecode
                        break
                    }
                    node = Int(child)
                    let symbol = tree[node].symbol
                    guard symbol >= 0 else { continue }
                    guard symbol != 256 else {
                        transition.flags |= failsDecode
                        break
                    }
                    transition.symbol = UInt8(symbol)
                    transition.flags |= emitsSymbol | tailAllOnes
                    transition.tailBits = 0
                    node = 0
                }
                if transition.flags & failsDecode == 0 {
                    transition.next = UInt16(stateOfNode[node])
                }
                table.append(transition)
            }
        }
        return table
    }()

    static func decode(_ data: some Collection<UInt8>) -> [UInt8]? {
        if let decoded = data.withContiguousStorageIfAvailable({ decode(bytes: $0) }) {
            return decoded
        }
        return Array(data).withUnsafeBufferPointer { decode(bytes: $0) }
    }

    private static func decode(bytes data: UnsafeBufferPointer<UInt8>) -> [UInt8]? {
        var result: [UInt8] = []
        result.reserveCapacity(data.count * 8 / 5)
        var state = 0
        var bitsSinceSymbol = 0
        var paddingAllOnes = true

        let walked = transitions.withUnsafeBufferPointer { table -> Bool in
            for byte in data {
                var nibble = byte >> 4
                for _ in 0..<2 {
                    let transition = table[state &* 16 &+ Int(nibble)]
                    guard transition.flags & failsDecode == 0 else { return false }
                    if transition.flags & emitsSymbol != 0 {
                        result.append(transition.symbol)
                        bitsSinceSymbol = Int(transition.tailBits)
                        paddingAllOnes = transition.flags & tailAllOnes != 0
                    } else {
                        bitsSinceSymbol += 4
                        paddingAllOnes = paddingAllOnes && transition.flags & tailAllOnes != 0
                    }
                    state = Int(transition.next)
                    nibble = byte & 0x0F
                }
            }
            return true
        }
        guard walked else { return nil }

        if state != 0 {
            guard paddingAllOnes, bitsSinceSymbol < 8 else { return nil }
        }
        return result
    }

    // MARK: - Huffman Code Table

    private static let huffmanTable: [(UInt32, UInt8)] = [
        (0xffc00000, 13), (0xffffb000, 23), (0xfffffe20, 28), (0xfffffe30, 28),
        (0xfffffe40, 28), (0xfffffe50, 28), (0xfffffe60, 28), (0xfffffe70, 28),
        (0xfffffe80, 28), (0xffffea00, 24), (0xfffffff0, 30), (0xfffffe90, 28),
        (0xfffffea0, 28), (0xfffffff4, 30), (0xfffffeb0, 28), (0xfffffec0, 28),
        (0xfffffed0, 28), (0xfffffee0, 28), (0xfffffef0, 28), (0xffffff00, 28),
        (0xffffff10, 28), (0xffffff20, 28), (0xfffffff8, 30), (0xffffff30, 28),
        (0xffffff40, 28), (0xffffff50, 28), (0xffffff60, 28), (0xffffff70, 28),
        (0xffffff80, 28), (0xffffff90, 28), (0xffffffa0, 28), (0xffffffb0, 28),
        // 32–63: printable ASCII
        (0x50000000,  6), (0xfe000000, 10), (0xfe400000, 10), (0xffa00000, 12),
        (0xffc80000, 13), (0x54000000,  6), (0xf8000000,  8), (0xff400000, 11),
        (0xfe800000, 10), (0xfec00000, 10), (0xf9000000,  8), (0xff600000, 11),
        (0xfa000000,  8), (0x58000000,  6), (0x5c000000,  6), (0x60000000,  6),
        (0x00000000,  5), (0x08000000,  5), (0x10000000,  5), (0x64000000,  6),
        (0x68000000,  6), (0x6c000000,  6), (0x70000000,  6), (0x74000000,  6),
        (0x78000000,  6), (0x7c000000,  6), (0xb8000000,  7), (0xfb000000,  8),
        (0xfff80000, 15), (0x80000000,  6), (0xffb00000, 12), (0xff000000, 10),
        // 64–95
        (0xffd00000, 13), (0x84000000,  6), (0xba000000,  7), (0xbc000000,  7),
        (0xbe000000,  7), (0xc0000000,  7), (0xc2000000,  7), (0xc4000000,  7),
        (0xc6000000,  7), (0xc8000000,  7), (0xca000000,  7), (0xcc000000,  7),
        (0xce000000,  7), (0xd0000000,  7), (0xd2000000,  7), (0xd4000000,  7),
        (0xd6000000,  7), (0xd8000000,  7), (0xda000000,  7), (0xdc000000,  7),
        (0xde000000,  7), (0xe0000000,  7), (0xe2000000,  7), (0xe4000000,  7),
        (0xfc000000,  8), (0xe6000000,  7), (0xfd000000,  8), (0xffd80000, 13),
        (0xfffe0000, 19), (0xffe00000, 13), (0xfff00000, 14), (0x88000000,  6),
        // 96–127
        (0xfffa0000, 15), (0x18000000,  5), (0x8c000000,  6), (0x20000000,  5),
        (0x90000000,  6), (0x28000000,  5), (0x94000000,  6), (0x98000000,  6),
        (0x9c000000,  6), (0x30000000,  5), (0xe8000000,  7), (0xea000000,  7),
        (0xa0000000,  6), (0xa4000000,  6), (0xa8000000,  6), (0x38000000,  5),
        (0xac000000,  6), (0xec000000,  7), (0xb0000000,  6), (0x40000000,  5),
        (0x48000000,  5), (0xb4000000,  6), (0xee000000,  7), (0xf0000000,  7),
        (0xf2000000,  7), (0xf4000000,  7), (0xf6000000,  7), (0xfffc0000, 15),
        (0xff800000, 11), (0xfff40000, 14), (0xffe80000, 13), (0xffffffc0, 28),
        // 128–159
        (0xfffe6000, 20), (0xffff4800, 22), (0xfffe7000, 20), (0xfffe8000, 20),
        (0xffff4c00, 22), (0xffff5000, 22), (0xffff5400, 22), (0xffffb200, 23),
        (0xffff5800, 22), (0xffffb400, 23), (0xffffb600, 23), (0xffffb800, 23),
        (0xffffba00, 23), (0xffffbc00, 23), (0xffffeb00, 24), (0xffffbe00, 23),
        (0xffffec00, 24), (0xffffed00, 24), (0xffff5c00, 22), (0xffffc000, 23),
        (0xffffee00, 24), (0xffffc200, 23), (0xffffc400, 23), (0xffffc600, 23),
        (0xffffc800, 23), (0xfffee000, 21), (0xffff6000, 22), (0xffffca00, 23),
        (0xffff6400, 22), (0xffffcc00, 23), (0xffffce00, 23), (0xffffef00, 24),
        // 160–191
        (0xffff6800, 22), (0xfffee800, 21), (0xfffe9000, 20), (0xffff6c00, 22),
        (0xffff7000, 22), (0xffffd000, 23), (0xffffd200, 23), (0xfffef000, 21),
        (0xffffd400, 23), (0xffff7400, 22), (0xffff7800, 22), (0xfffff000, 24),
        (0xfffef800, 21), (0xffff7c00, 22), (0xffffd600, 23), (0xffffd800, 23),
        (0xffff0000, 21), (0xffff0800, 21), (0xffff8000, 22), (0xffff1000, 21),
        (0xffffda00, 23), (0xffff8400, 22), (0xffffdc00, 23), (0xffffde00, 23),
        (0xfffea000, 20), (0xffff8800, 22), (0xffff8c00, 22), (0xffff9000, 22),
        (0xffffe000, 23), (0xffff9400, 22), (0xffff9800, 22), (0xffffe200, 23),
        // 192–223
        (0xfffff800, 26), (0xfffff840, 26), (0xfffeb000, 20), (0xfffe2000, 19),
        (0xffff9c00, 22), (0xffffe400, 23), (0xffffa000, 22), (0xfffff600, 25),
        (0xfffff880, 26), (0xfffff8c0, 26), (0xfffff900, 26), (0xfffffbc0, 27),
        (0xfffffbe0, 27), (0xfffff940, 26), (0xfffff100, 24), (0xfffff680, 25),
        (0xfffe4000, 19), (0xffff1800, 21), (0xfffff980, 26), (0xfffffc00, 27),
        (0xfffffc20, 27), (0xfffff9c0, 26), (0xfffffc40, 27), (0xfffff200, 24),
        (0xffff2000, 21), (0xffff2800, 21), (0xfffffa00, 26), (0xfffffa40, 26),
        (0xffffffd0, 28), (0xfffffc60, 27), (0xfffffc80, 27), (0xfffffca0, 27),
        // 224–256 (256 = EOS)
        (0xfffec000, 20), (0xfffff300, 24), (0xfffed000, 20), (0xffff3000, 21),
        (0xffffa400, 22), (0xffff3800, 21), (0xffff4000, 21), (0xffffe600, 23),
        (0xffffa800, 22), (0xffffac00, 22), (0xfffff700, 25), (0xfffff780, 25),
        (0xfffff400, 24), (0xfffff500, 24), (0xfffffa80, 26), (0xffffe800, 23),
        (0xfffffac0, 26), (0xfffffcc0, 27), (0xfffffb00, 26), (0xfffffb40, 26),
        (0xfffffce0, 27), (0xfffffd00, 27), (0xfffffd20, 27), (0xfffffd40, 27),
        (0xfffffd60, 27), (0xffffffe0, 28), (0xfffffd80, 27), (0xfffffda0, 27),
        (0xfffffdc0, 27), (0xfffffde0, 27), (0xfffffe00, 27), (0xfffffb80, 26),
        (0xfffffffc, 30),  // 256 = EOS
    ]
}

// MARK: - HTTP/2 frame wire format

nonisolated enum HTTP2FrameWire {
    static let headerSize = 9

    static func appendHeader(
        type: UInt8,
        flags: UInt8,
        streamID: UInt32,
        payloadLength: Int,
        into out: inout Data
    ) {
        out.append(UInt8((payloadLength >> 16) & 0xFF))
        out.append(UInt8((payloadLength >> 8) & 0xFF))
        out.append(UInt8(payloadLength & 0xFF))
        out.append(type)
        out.append(flags)
        let maskedStreamID = streamID & 0x7FFF_FFFF
        out.append(UInt8((maskedStreamID >> 24) & 0xFF))
        out.append(UInt8((maskedStreamID >> 16) & 0xFF))
        out.append(UInt8((maskedStreamID >> 8) & 0xFF))
        out.append(UInt8(maskedStreamID & 0xFF))
    }

    static func appendUInt32(_ value: UInt32, into out: inout Data) {
        out.append(UInt8((value >> 24) & 0xFF))
        out.append(UInt8((value >> 16) & 0xFF))
        out.append(UInt8((value >> 8) & 0xFF))
        out.append(UInt8(value & 0xFF))
    }

    static func readUInt32(_ payload: Data, offset: Int = 0) -> UInt32? {
        let s = payload.startIndex + offset
        guard s >= payload.startIndex, s + 4 <= payload.endIndex else { return nil }
        return UInt32(payload[s]) << 24 | UInt32(payload[s + 1]) << 16
             | UInt32(payload[s + 2]) << 8 | UInt32(payload[s + 3])
    }

    static func parseSettings(_ payload: Data) -> [(id: UInt16, value: UInt32)] {
        var result: [(id: UInt16, value: UInt32)] = []
        var offset = payload.startIndex
        while offset + 6 <= payload.endIndex {
            let id = UInt16(payload[offset]) << 8 | UInt16(payload[offset + 1])
            let value = UInt32(payload[offset + 2]) << 24 | UInt32(payload[offset + 3]) << 16
                      | UInt32(payload[offset + 4]) << 8 | UInt32(payload[offset + 5])
            result.append((id: id, value: value))
            offset += 6
        }
        return result
    }

    static func parseGoaway(_ payload: Data) -> (lastStreamID: UInt32, errorCode: UInt32)? {
        guard let last = readUInt32(payload, offset: 0),
              let error = readUInt32(payload, offset: 4) else { return nil }
        return (last & 0x7FFF_FFFF, error)
    }
}
