//
//  TCPHeader.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

struct TCPHeader: Hashable, Sendable {
    struct Flags: OptionSet, Hashable, Sendable {
        let rawValue: UInt8

        init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        static let fin = Flags(rawValue: 0x01)
        static let syn = Flags(rawValue: 0x02)
        static let rst = Flags(rawValue: 0x04)
        static let psh = Flags(rawValue: 0x08)
        static let ack = Flags(rawValue: 0x10)
        static let urg = Flags(rawValue: 0x20)
    }

    struct Options: Hashable, Sendable {
        var maximumSegmentSize: UInt16?
        var windowScale: UInt8?

        init(maximumSegmentSize: UInt16? = nil, windowScale: UInt8? = nil) {
            self.maximumSegmentSize = maximumSegmentSize
            self.windowScale = windowScale
        }

        init(parsing bytes: UnsafeRawBufferPointer) {
            var index = 0
            while index < bytes.count {
                let kind = bytes[index]
                switch kind {
                case 0:
                    return
                case 1:
                    index += 1
                case 2:
                    guard index + 4 <= bytes.count, bytes[index + 1] == 4 else { return }
                    maximumSegmentSize = UInt16(bigEndian: bytes.loadUnaligned(fromByteOffset: index + 2, as: UInt16.self))
                    index += 4
                case 3:
                    guard index + 3 <= bytes.count, bytes[index + 1] == 3 else { return }
                    windowScale = bytes[index + 2]
                    index += 3
                default:
                    guard index + 1 < bytes.count else { return }
                    let length = Int(bytes[index + 1])
                    guard length >= 2 else { return }
                    index += length
                }
            }
        }

        var encodedLength: Int {
            (maximumSegmentSize == nil ? 0 : 4) + (windowScale == nil ? 0 : 4)
        }

        func write(to bytes: UnsafeMutableRawBufferPointer) {
            var offset = 0
            if let maximumSegmentSize {
                bytes[offset] = 2
                bytes[offset + 1] = 4
                bytes.storeBytes(of: maximumSegmentSize.bigEndian, toByteOffset: offset + 2, as: UInt16.self)
                offset += 4
            }
            if let windowScale {
                bytes[offset] = 1
                bytes[offset + 1] = 3
                bytes[offset + 2] = 3
                bytes[offset + 3] = windowScale
            }
        }
    }

    static let length = 20

    var sourcePort: UInt16
    var destinationPort: UInt16
    var sequenceNumber: UInt32
    var acknowledgmentNumber: UInt32
    var dataOffset: Int
    var flags: Flags
    var window: UInt16
    var checksum: UInt16
    var urgentPointer: UInt16

    init(
        sourcePort: UInt16,
        destinationPort: UInt16,
        sequenceNumber: UInt32,
        acknowledgmentNumber: UInt32,
        dataOffset: Int = TCPHeader.length,
        flags: Flags,
        window: UInt16,
        checksum: UInt16 = 0,
        urgentPointer: UInt16 = 0
    ) {
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.sequenceNumber = sequenceNumber
        self.acknowledgmentNumber = acknowledgmentNumber
        self.dataOffset = dataOffset
        self.flags = flags
        self.window = window
        self.checksum = checksum
        self.urgentPointer = urgentPointer
    }

    init?(parsing bytes: UnsafeRawBufferPointer) {
        guard bytes.count >= Self.length, let base = bytes.baseAddress else { return nil }
        let dataOffset = Int(base.load(fromByteOffset: 12, as: UInt8.self) >> 4) * 4
        guard dataOffset >= Self.length, dataOffset <= bytes.count else { return nil }
        sourcePort = UInt16(bigEndian: base.loadUnaligned(as: UInt16.self))
        destinationPort = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 2, as: UInt16.self))
        sequenceNumber = UInt32(bigEndian: base.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
        acknowledgmentNumber = UInt32(bigEndian: base.loadUnaligned(fromByteOffset: 8, as: UInt32.self))
        self.dataOffset = dataOffset
        flags = Flags(rawValue: base.load(fromByteOffset: 13, as: UInt8.self) & 0x3F)
        window = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 14, as: UInt16.self))
        checksum = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 16, as: UInt16.self))
        urgentPointer = UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 18, as: UInt16.self))
    }

    func write(to bytes: UnsafeMutableRawBufferPointer) {
        precondition(bytes.count >= Self.length)
        let base = bytes.baseAddress!
        base.storeBytes(of: sourcePort.bigEndian, as: UInt16.self)
        base.storeBytes(of: destinationPort.bigEndian, toByteOffset: 2, as: UInt16.self)
        base.storeBytes(of: sequenceNumber.bigEndian, toByteOffset: 4, as: UInt32.self)
        base.storeBytes(of: acknowledgmentNumber.bigEndian, toByteOffset: 8, as: UInt32.self)
        base.storeBytes(of: UInt8(dataOffset / 4) << 4, toByteOffset: 12, as: UInt8.self)
        base.storeBytes(of: flags.rawValue, toByteOffset: 13, as: UInt8.self)
        base.storeBytes(of: window.bigEndian, toByteOffset: 14, as: UInt16.self)
        base.storeBytes(of: checksum.bigEndian, toByteOffset: 16, as: UInt16.self)
        base.storeBytes(of: urgentPointer.bigEndian, toByteOffset: 18, as: UInt16.self)
    }
}
