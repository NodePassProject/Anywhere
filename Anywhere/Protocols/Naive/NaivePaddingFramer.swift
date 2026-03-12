//
//  NaivePaddingFramer.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation

/// Encodes and decodes NaiveProxy padding frames for the first N read/write operations.
///
/// Wire format per frame:
/// ```
/// [1 byte] payload_size >> 8
/// [1 byte] payload_size & 0xFF
/// [1 byte] padding_size
/// [payload_size bytes] payload
/// [padding_size bytes] zeros
/// ```
///
/// After `maxFrames` frames have been processed, data passes through unframed.
struct NaivePaddingFramer {
    static let frameHeaderSize = 3
    static let maxPaddingSize = 255

    private let maxFrames: Int
    private(set) var numReadFrames = 0
    private(set) var numWrittenFrames = 0

    // Read state machine
    private enum ReadState {
        case payloadLength1
        case payloadLength2
        case paddingLength
        case payload
        case padding
    }

    private var state: ReadState = .payloadLength1
    private var readPayloadLength = 0
    private var readPaddingLength = 0

    init(maxFrames: Int = 8) {
        self.maxFrames = maxFrames
    }

    /// Whether padding is still active for reads.
    var isReadPaddingActive: Bool { numReadFrames < maxFrames }

    /// Whether padding is still active for writes.
    var isWritePaddingActive: Bool { numWrittenFrames < maxFrames }

    // MARK: - Read

    /// Reads padded input and extracts payload bytes.
    ///
    /// Handles partial reads — the framer's state machine resumes across calls.
    /// Returns the number of payload bytes written to `output`.
    /// A return value of 0 means only padding/header bytes were consumed (not EOF).
    mutating func read(padded: Data, into output: inout Data) -> Int {
        var offset = 0
        let startCount = output.count

        while offset < padded.count {
            switch state {
            case .payloadLength1:
                if numReadFrames >= maxFrames {
                    // Past padding threshold — raw passthrough
                    output.append(padded.suffix(from: padded.startIndex + offset))
                    offset = padded.count
                    break
                }
                readPayloadLength = Int(padded[padded.startIndex + offset])
                offset += 1
                state = .payloadLength2

            case .payloadLength2:
                readPayloadLength = readPayloadLength * 256 + Int(padded[padded.startIndex + offset])
                offset += 1
                state = .paddingLength

            case .paddingLength:
                readPaddingLength = Int(padded[padded.startIndex + offset])
                offset += 1
                state = .payload

            case .payload:
                let available = padded.count - offset
                let copySize = min(readPayloadLength, available)
                readPayloadLength -= copySize

                output.append(padded[(padded.startIndex + offset)..<(padded.startIndex + offset + copySize)])
                offset += copySize

                if readPayloadLength == 0 {
                    state = .padding
                }

            case .padding:
                let available = padded.count - offset
                let skipSize = min(readPaddingLength, available)
                readPaddingLength -= skipSize
                offset += skipSize

                if readPaddingLength == 0 {
                    if numReadFrames < Int.max - 1 {
                        numReadFrames += 1
                    }
                    state = .payloadLength1
                }
            }
        }

        return output.count - startCount
    }

    // MARK: - Write

    /// Wraps `payload` in a padding frame with the given padding size.
    ///
    /// Returns the framed data (header + payload + zero-padding).
    mutating func write(payload: Data, paddingSize: Int) -> Data {
        let paddingSize = min(paddingSize, Self.maxPaddingSize)
        let frameSize = Self.frameHeaderSize + payload.count + paddingSize

        var frame = Data(capacity: frameSize)
        frame.append(UInt8(payload.count / 256))
        frame.append(UInt8(payload.count % 256))
        frame.append(UInt8(paddingSize))
        frame.append(payload)
        if paddingSize > 0 {
            frame.append(Data(count: paddingSize))
        }

        if numWrittenFrames < Int.max - 1 {
            numWrittenFrames += 1
        }

        return frame
    }
}
