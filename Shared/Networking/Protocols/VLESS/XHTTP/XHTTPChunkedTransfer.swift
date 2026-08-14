//
//  XHTTPChunkedTransfer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

// MARK: - ChunkedTransferDecoder

nonisolated struct ChunkedTransferDecoder {
    private enum Phase: PhaseTransitionable {
        case parsing
        case finished
        case malformed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.parsing, .finished),
                 (.parsing, .malformed):
                return true
            default:
                return false
            }
        }
    }

    private var buffer = Data()
    private var phase: Phase = .parsing

    var isFinished: Bool { phase == .finished }
    var isMalformed: Bool { phase == .malformed }

    private static let maxSizeLineLength = 1024

    mutating func feed(_ data: Data) {
        buffer.append(data)
    }

    mutating func nextChunk() -> Data? {
        guard case .parsing = phase else { return nil }

        let crlf = Data([0x0D, 0x0A])
        guard let crlfRange = buffer.range(of: crlf) else {
            if buffer.count > Self.maxSizeLineLength { Phase.transition(&phase, to: .malformed) }
            return nil
        }

        let sizeLineData = buffer[buffer.startIndex..<crlfRange.lowerBound]
        guard sizeLineData.count <= Self.maxSizeLineLength,
              let sizeLine = String(data: Data(sizeLineData), encoding: .ascii) else {
            Phase.transition(&phase, to: .malformed)
            return nil
        }

        let sizeStr = sizeLine.split(separator: ";", maxSplits: 1).first.map(String.init) ?? sizeLine
        guard let chunkSize = UInt64(sizeStr.trimmingCharacters(in: .whitespaces), radix: 16) else {
            Phase.transition(&phase, to: .malformed)
            return nil
        }

        if chunkSize == 0 {
            Phase.transition(&phase, to: .finished)
            let termEnd = crlfRange.upperBound
            if buffer.endIndex >= termEnd + 2 {
                buffer.removeFirst(termEnd + 2 - buffer.startIndex)
            }
            buffer = Data()
            return nil
        }

        let dataStart = crlfRange.upperBound
        let needed = dataStart + Int(chunkSize) + 2
        guard buffer.endIndex >= needed else {
            return nil
        }

        let chunkData = buffer.subdata(in: dataStart..<dataStart + Int(chunkSize))

        buffer.removeFirst(needed - buffer.startIndex)
        if buffer.isEmpty { buffer = Data() } else { buffer = Data(buffer) }

        return chunkData
    }
}

// MARK: - ChunkedTransferEncoder

nonisolated enum ChunkedTransferEncoder {
    static func encode(_ data: Data) -> Data {
        let sizeStr = String(data.count, radix: 16)
        var encoded = Data()
        encoded.append(contentsOf: sizeStr.utf8)
        encoded.append(contentsOf: [0x0D, 0x0A])
        encoded.append(data)
        encoded.append(contentsOf: [0x0D, 0x0A])
        return encoded
    }

    static func encodeTerminator() -> Data {
        return Data([0x30, 0x0D, 0x0A, 0x0D, 0x0A])
    }
}
