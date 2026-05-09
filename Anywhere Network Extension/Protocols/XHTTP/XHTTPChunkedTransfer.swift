//
//  XHTTPConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation

// MARK: - ChunkedTransferDecoder

/// Stateful chunked transfer encoding decoder (HTTP/1.1 RFC 7230 §4.1).
///
/// Handles partial reads: data can be fed incrementally and chunks extracted as they become complete.
struct ChunkedTransferDecoder {
    private var buffer = Data()
    private var _isFinished = false

    var isFinished: Bool { _isFinished }

    /// Feed raw data from the transport into the decoder.
    mutating func feed(_ data: Data) {
        buffer.append(data)
    }

    /// Try to extract the next complete chunk from the buffer.
    ///
    /// Returns the chunk payload (without framing), or `nil` if not enough data is available yet.
    /// Returns empty `Data()` if a zero-length terminator chunk is found (EOF).
    mutating func nextChunk() -> Data? {
        guard !_isFinished else { return nil }

        // Look for the chunk-size line ending with \r\n
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
            // Terminal chunk
            _isFinished = true
            // Consume "0\r\n\r\n" (the trailing CRLF after the zero chunk)
            let termEnd = crlfRange.upperBound
            if buffer.endIndex >= termEnd + 2 {
                buffer.removeFirst(termEnd + 2 - buffer.startIndex)
            }
            buffer = Data()
            return nil
        }

        // Check if we have the full chunk data + trailing \r\n
        let dataStart = crlfRange.upperBound
        let needed = dataStart + Int(chunkSize) + 2 // chunk data + \r\n
        guard buffer.endIndex >= needed else {
            return nil // Need more data
        }

        let chunkData = buffer.subdata(in: dataStart..<dataStart + Int(chunkSize))

        // Consume the chunk from the buffer (size line + \r\n + data + \r\n)
        buffer.removeFirst(needed - buffer.startIndex)
        if buffer.isEmpty { buffer = Data() } else { buffer = Data(buffer) }

        return chunkData
    }
}

// MARK: - ChunkedTransferEncoder

/// Chunked transfer encoding encoder (HTTP/1.1 RFC 7230 §4.1).
enum ChunkedTransferEncoder {
    /// Encodes data as a single chunked-encoded chunk: `{hex-size}\r\n{data}\r\n`.
    static func encode(_ data: Data) -> Data {
        let sizeStr = String(data.count, radix: 16)
        var encoded = Data()
        encoded.append(contentsOf: sizeStr.utf8)
        encoded.append(contentsOf: [0x0D, 0x0A]) // \r\n
        encoded.append(data)
        encoded.append(contentsOf: [0x0D, 0x0A]) // \r\n
        return encoded
    }

    /// Encodes the terminal zero-length chunk: `0\r\n\r\n`.
    static func encodeTerminator() -> Data {
        return Data([0x30, 0x0D, 0x0A, 0x0D, 0x0A]) // "0\r\n\r\n"
    }
}
