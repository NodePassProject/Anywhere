//
//  QUICClientHelloSniffer.swift
//  Anywhere
//
//  Created by NodePassProject on 10/25/26.
//

import Foundation
import AnywhereQUIC

nonisolated struct QUICClientHelloSniffer {
    enum State: Equatable {
        case needMore
        case notQUIC
        case found(serverName: String)
        case unavailable
    }

    static let minimumInitialDatagramSize = 1200
    static let defaultBufferLimit = 8192
    static let defaultDatagramLimit = 4

    private let bufferLimit: Int
    private let datagramLimit: Int
    private var buffer: [UInt8] = []
    private var filled: [Range<Int>] = []
    private var datagramsFed = 0
    private(set) var state: State = .needMore

    init(bufferLimit: Int = Self.defaultBufferLimit, datagramLimit: Int = Self.defaultDatagramLimit) {
        self.bufferLimit = bufferLimit
        self.datagramLimit = datagramLimit
    }

    static func looksLikeClientInitial(_ datagram: Data) -> Bool {
        datagram.count >= Self.minimumInitialDatagramSize && QUICInitialPeek.hasSupportedLongHeader(datagram)
            || GQUICClientHello.looksLikeClientHello(datagram)
    }

    mutating func feed(_ datagram: Data) -> State {
        guard state == .needMore else { return state }
        datagramsFed += 1
        if GQUICClientHello.hasPublicHeader(datagram) {
            if let fragments = GQUICClientHello.cryptoStreamFragments(datagram) {
                feed(fragments: fragments)
            } else if datagramsFed == 1 {
                state = .unavailable
            }
        } else {
            do {
                let peek = try QUICInitialPeek.parse(datagram)
                feed(fragments: peek.cryptoFragments.map { (offset: $0.offset, data: $0.data) })
            } catch {
                if datagramsFed == 1 {
                    state = error == .notInitial ? .notQUIC : .unavailable
                }
            }
        }
        if state == .needMore, datagramsFed >= datagramLimit {
            state = .unavailable
        }
        return state
    }

    mutating func feed(fragments: [(offset: Int, data: Data)]) {
        for fragment in fragments where state == .needMore {
            insert(fragment.data, at: fragment.offset)
        }
        if state == .needMore {
            state = parse()
        }
    }

    // MARK: - Reassembly

    private mutating func insert(_ data: Data, at offset: Int) {
        guard !data.isEmpty, offset >= 0 else { return }
        let end = offset + data.count
        guard end <= bufferLimit else {
            state = .unavailable
            return
        }
        if buffer.count < end {
            buffer.append(contentsOf: repeatElement(0, count: end - buffer.count))
        }
        buffer.replaceSubrange(offset..<end, with: data)

        var merged = offset..<end
        var others: [Range<Int>] = []
        for range in filled {
            if range.upperBound < merged.lowerBound || range.lowerBound > merged.upperBound {
                others.append(range)
            } else {
                merged = min(range.lowerBound, merged.lowerBound)..<max(range.upperBound, merged.upperBound)
            }
        }
        others.append(merged)
        filled = others.sorted { $0.lowerBound < $1.lowerBound }
    }

    private var contiguousLength: Int {
        guard let head = filled.first, head.lowerBound == 0 else { return 0 }
        return head.upperBound
    }

    // MARK: - Parsing

    private func parse() -> State {
        let available = contiguousLength
        guard available >= 4 else { return .needMore }
        if GQUICClientHello.isMessageStart(buffer) {
            switch GQUICClientHello.serverName(in: buffer, available: available, limit: bufferLimit) {
            case .needMore: return .needMore
            case .unavailable: return .unavailable
            case .found(let serverName): return .found(serverName: serverName)
            }
        }
        guard buffer[0] == TLSHandshakeType.clientHello else { return .unavailable }
        let messageLength = 4 + (Int(buffer[1]) << 16 | Int(buffer[2]) << 8 | Int(buffer[3]))
        guard messageLength <= bufferLimit else { return .unavailable }
        guard available >= messageLength else { return .needMore }
        guard let parsed = try? TLSClientHelloParser.parseHandshakeBody(Data(buffer[0..<messageLength])),
              let serverName = parsed.serverName,
              serverName.utf8.count <= 253 else {
            return .unavailable
        }
        return .found(serverName: serverName)
    }
}
