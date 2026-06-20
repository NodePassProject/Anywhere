//
//  XHTTPChunkedTransfer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

// MARK: - ChunkedTransferDecoder

/// Chunked transfer decoder (RFC 7230 §4.1); tolerates partial reads across `feed` calls.
struct ChunkedTransferDecoder {
    private var buffer = Data()
    private var _isFinished = false

    var isFinished: Bool { _isFinished }

    mutating func feed(_ data: Data) {
        buffer.append(data)
    }

    /// Returns the next complete chunk's payload (without framing), or nil if more data is needed;
    /// the zero-length terminator sets `isFinished`.
    mutating func nextChunk() -> Data? {
        guard !_isFinished else { return nil }

        let crlf = Data([0x0D, 0x0A])
        guard let crlfRange = buffer.range(of: crlf) else {
            return nil
        }

        let sizeLineData = buffer[buffer.startIndex..<crlfRange.lowerBound]
        guard let sizeLine = String(data: Data(sizeLineData), encoding: .ascii) else {
            return nil
        }

        // Parse hex chunk size (ignoring chunk extensions after ";")
        let sizeStr = sizeLine.split(separator: ";", maxSplits: 1).first.map(String.init) ?? sizeLine
        guard let chunkSize = UInt64(sizeStr.trimmingCharacters(in: .whitespaces), radix: 16) else {
            return nil
        }

        if chunkSize == 0 {
            _isFinished = true
            let termEnd = crlfRange.upperBound
            // +2 skips the trailing CRLF after the zero chunk
            if buffer.endIndex >= termEnd + 2 {
                buffer.removeFirst(termEnd + 2 - buffer.startIndex)
            }
            buffer = Data()
            return nil
        }

        let dataStart = crlfRange.upperBound
        let needed = dataStart + Int(chunkSize) + 2 // chunk data + \r\n
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

/// Chunked transfer encoder (RFC 7230 §4.1).
enum ChunkedTransferEncoder {
    /// Encodes data as a single chunked-encoded chunk: `{hex-size}\r\n{data}\r\n`.
    static func encode(_ data: Data) -> Data {
        let sizeStr = String(data.count, radix: 16)
        var encoded = Data()
        encoded.append(contentsOf: sizeStr.utf8)
        encoded.append(contentsOf: [0x0D, 0x0A])
        encoded.append(data)
        encoded.append(contentsOf: [0x0D, 0x0A])
        return encoded
    }

    /// Encodes the terminal zero-length chunk: `0\r\n\r\n`.
    static func encodeTerminator() -> Data {
        return Data([0x30, 0x0D, 0x0A, 0x0D, 0x0A])
    }
}
