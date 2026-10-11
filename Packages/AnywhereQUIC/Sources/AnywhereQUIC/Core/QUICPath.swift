//
//  QUICPath.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

#if canImport(Darwin)
import Darwin
#endif

public struct QUICSocketAddress: Sendable {
    public static let unspecified = QUICSocketAddress(bytes: [])

    #if canImport(Darwin)
    private typealias Fields = (port: Range<Int>, address: Range<Int>)

    private static let familyRange: Range<Int> = {
        let offset = MemoryLayout<sockaddr>.offset(of: \.sa_family)!
        return offset..<offset + MemoryLayout<sa_family_t>.size
    }()

    private static let inetFields = Self.fields(
        port: MemoryLayout<sockaddr_in>.offset(of: \.sin_port)!,
        address: MemoryLayout<sockaddr_in>.offset(of: \.sin_addr)!,
        addressLength: MemoryLayout<in_addr>.size
    )

    private static let inet6Fields = Self.fields(
        port: MemoryLayout<sockaddr_in6>.offset(of: \.sin6_port)!,
        address: MemoryLayout<sockaddr_in6>.offset(of: \.sin6_addr)!,
        addressLength: MemoryLayout<in6_addr>.size
    )

    private static func fields(port: Int, address: Int, addressLength: Int) -> Fields {
        return (port..<port + MemoryLayout<in_port_t>.size, address..<address + addressLength)
    }
    #endif

    public var bytes: [UInt8]

    public init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    public init<Value>(copying value: Value) {
        self.bytes = withUnsafeBytes(of: value) { Array($0) }
    }

    #if canImport(Darwin)
    public init(_ address: sockaddr_in) {
        self.init(copying: address)
    }

    public init(_ address: sockaddr_in6) {
        self.init(copying: address)
    }

    public init(_ storage: sockaddr_storage, length: Int) {
        self.bytes = withUnsafeBytes(of: storage) { Array($0.prefix(length)) }
    }
    #endif

    private var comparedRanges: (family: Range<Int>, port: Range<Int>, address: Range<Int>)? {
        #if canImport(Darwin)
        let family = Self.familyRange
        guard self.bytes.count >= family.upperBound else {
            return nil
        }
        let value = self.bytes.withUnsafeBytes { raw in
            return raw.loadUnaligned(fromByteOffset: family.lowerBound, as: sa_family_t.self)
        }
        let fields: Fields
        switch Int32(value) {
        case AF_INET:
            fields = Self.inetFields
        case AF_INET6:
            fields = Self.inet6Fields
        default:
            return nil
        }
        guard self.bytes.count >= Swift.max(fields.port.upperBound, fields.address.upperBound) else {
            return nil
        }
        return (family, fields.port, fields.address)
        #else
        return nil
        #endif
    }
}

extension QUICSocketAddress: Hashable {
    public static func == (lhs: QUICSocketAddress, rhs: QUICSocketAddress) -> Bool {
        if lhs.bytes == rhs.bytes {
            return true
        }
        guard let ranges = lhs.comparedRanges, let other = rhs.comparedRanges else {
            return lhs.bytes == rhs.bytes
        }
        return lhs.bytes[ranges.family] == rhs.bytes[other.family]
            && lhs.bytes[ranges.port] == rhs.bytes[other.port]
            && lhs.bytes[ranges.address] == rhs.bytes[other.address]
    }

    public func hash(into hasher: inout Hasher) {
        guard let ranges = self.comparedRanges else {
            hasher.combine(self.bytes)
            return
        }
        hasher.combine(self.bytes[ranges.family])
        hasher.combine(self.bytes[ranges.port])
        hasher.combine(self.bytes[ranges.address])
    }
}

public struct QUICPath: Hashable, Sendable {
    public var local: QUICSocketAddress
    public var remote: QUICSocketAddress

    public init(local: QUICSocketAddress, remote: QUICSocketAddress) {
        self.local = local
        self.remote = remote
    }
}
