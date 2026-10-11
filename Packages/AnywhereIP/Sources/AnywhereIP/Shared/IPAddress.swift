//
//  IPAddress.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

public enum IPAddress: Hashable, Sendable {
    public struct V4: Hashable, Sendable, ExpressibleByIntegerLiteral {
        public var rawValue: UInt32

        public init(rawValue: UInt32) {
            self.rawValue = rawValue
        }

        public init(integerLiteral value: UInt32) {
            rawValue = value
        }

        init(bytes pointer: UnsafeRawPointer) {
            rawValue = UInt32(bigEndian: pointer.loadUnaligned(as: UInt32.self))
        }

        func write(to pointer: UnsafeMutableRawPointer) {
            pointer.storeBytes(of: rawValue.bigEndian, as: UInt32.self)
        }

        var isUnspecified: Bool { rawValue == 0 }
        var isBroadcast: Bool { rawValue == .max }
        var isMulticast: Bool { rawValue >> 28 == 0xE }
        var isLoopback: Bool { rawValue >> 24 == 127 }
    }

    public struct V6: Hashable, Sendable {
        public var high: UInt64
        public var low: UInt64

        public init(high: UInt64, low: UInt64) {
            self.high = high
            self.low = low
        }

        init(bytes pointer: UnsafeRawPointer) {
            high = UInt64(bigEndian: pointer.loadUnaligned(as: UInt64.self))
            low = UInt64(bigEndian: pointer.loadUnaligned(fromByteOffset: 8, as: UInt64.self))
        }

        func write(to pointer: UnsafeMutableRawPointer) {
            pointer.storeBytes(of: high.bigEndian, as: UInt64.self)
            pointer.storeBytes(of: low.bigEndian, toByteOffset: 8, as: UInt64.self)
        }

        var isUnspecified: Bool { high == 0 && low == 0 }
        var isLoopback: Bool { high == 0 && low == 1 }
        var isMulticast: Bool { high >> 56 == 0xFF }
        var isLinkLocal: Bool { high >> 54 == 0x3FA }
        var isIPv4Mapped: Bool { high == 0 && low >> 32 == 0xFFFF }
    }

    case v4(V4)
    case v6(V6)

    public var isIPv6: Bool {
        if case .v6 = self { return true }
        return false
    }

    public var byteCount: Int {
        isIPv6 ? 16 : 4
    }

    public init(bytes pointer: UnsafeRawPointer, isIPv6: Bool) {
        self = isIPv6 ? .v6(V6(bytes: pointer)) : .v4(V4(bytes: pointer))
    }

    public func write(to pointer: UnsafeMutableRawPointer) {
        switch self {
        case .v4(let address): address.write(to: pointer)
        case .v6(let address): address.write(to: pointer)
        }
    }
}

extension IPAddress: CustomStringConvertible {
    public var description: String {
        switch self {
        case .v4(let address):
            let value = address.rawValue
            return "\(value >> 24).\((value >> 16) & 0xFF).\((value >> 8) & 0xFF).\(value & 0xFF)"
        case .v6(let address):
            var groups = [UInt16](repeating: 0, count: 8)
            for index in 0..<4 {
                groups[index] = UInt16(truncatingIfNeeded: address.high >> (48 - 16 * index))
                groups[4 + index] = UInt16(truncatingIfNeeded: address.low >> (48 - 16 * index))
            }
            var bestStart = -1
            var bestLength = 0
            var runStart = -1
            for (index, group) in groups.enumerated() {
                guard group == 0 else {
                    runStart = -1
                    continue
                }
                if runStart < 0 { runStart = index }
                let length = index - runStart + 1
                if length > bestLength {
                    bestStart = runStart
                    bestLength = length
                }
            }
            let hex = groups.map { String($0, radix: 16) }
            guard bestLength >= 2 else { return hex.joined(separator: ":") }
            let head = hex[..<bestStart].joined(separator: ":")
            let tail = hex[(bestStart + bestLength)...].joined(separator: ":")
            return "\(head)::\(tail)"
        }
    }
}
