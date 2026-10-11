//
//  QUICConnectionID.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

public struct QUICConnectionID: Sendable {
    public static let maxLength = 20

    private var storage: (UInt64, UInt64, UInt32) = (0, 0, 0)

    public private(set) var count: Int

    public init() {
        self.count = 0
    }

    public init?(_ bytes: some Collection<UInt8>) {
        guard bytes.count <= Self.maxLength else {
            return nil
        }
        self.count = bytes.count
        withUnsafeMutableBytes(of: &self.storage) { raw in
            var index = 0
            for byte in bytes {
                raw[index] = byte
                index += 1
            }
        }
    }

    init(_ bytes: UnsafeRawBufferPointer) {
        precondition(bytes.count <= Self.maxLength)
        self.count = bytes.count
        if bytes.count > 0 {
            withUnsafeMutableBytes(of: &self.storage) { raw in
                raw.copyMemory(from: bytes)
            }
        }
    }

    public static func random(length: Int, using generator: inout some RandomNumberGenerator) -> QUICConnectionID {
        precondition(length >= 0 && length <= Self.maxLength)
        var id = QUICConnectionID()
        id.count = length
        withUnsafeMutableBytes(of: &id.storage) { raw in
            for index in 0..<length {
                raw[index] = UInt8.random(in: .min ... .max, using: &generator)
            }
        }
        return id
    }

    public static func random(length: Int) -> QUICConnectionID {
        var generator = SystemRandomNumberGenerator()
        return Self.random(length: length, using: &generator)
    }

    public var isEmpty: Bool { self.count == 0 }

    public var bytes: [UInt8] {
        return self.withUnsafeBytes { Array($0) }
    }

    public func withUnsafeBytes<Result, E: Error>(
        _ body: (UnsafeRawBufferPointer) throws(E) -> Result
    ) throws(E) -> Result {
        return try Swift.withUnsafeBytes(of: self.storage) { (raw) throws(E) -> Result in
            return try body(UnsafeRawBufferPointer(rebasing: raw[0..<self.count]))
        }
    }
}

extension QUICConnectionID: Hashable {
    public static func == (lhs: QUICConnectionID, rhs: QUICConnectionID) -> Bool {
        return lhs.count == rhs.count
            && lhs.storage.0 == rhs.storage.0
            && lhs.storage.1 == rhs.storage.1
            && lhs.storage.2 == rhs.storage.2
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.count)
        hasher.combine(self.storage.0)
        hasher.combine(self.storage.1)
        hasher.combine(self.storage.2)
    }
}

extension QUICConnectionID: CustomStringConvertible {
    public var description: String {
        return self.bytes.map { byte in
            let hex = String(byte, radix: 16)
            return hex.count == 1 ? "0" + hex : hex
        }.joined()
    }
}

public struct QUICStatelessResetToken: Sendable {
    public static let length = 16

    private var storage: (UInt64, UInt64) = (0, 0)

    public init?(_ bytes: some Collection<UInt8>) {
        guard bytes.count == Self.length else {
            return nil
        }
        withUnsafeMutableBytes(of: &self.storage) { raw in
            var index = 0
            for byte in bytes {
                raw[index] = byte
                index += 1
            }
        }
    }

    init(_ bytes: UnsafeRawBufferPointer) {
        precondition(bytes.count == Self.length)
        withUnsafeMutableBytes(of: &self.storage) { raw in
            raw.copyMemory(from: bytes)
        }
    }

    public static func random(using generator: inout some RandomNumberGenerator) -> QUICStatelessResetToken {
        var token = QUICStatelessResetToken()
        token.storage = (
            generator.next(),
            generator.next()
        )
        return token
    }

    public static func random() -> QUICStatelessResetToken {
        var generator = SystemRandomNumberGenerator()
        return Self.random(using: &generator)
    }

    private init() { }

    public var bytes: [UInt8] {
        return self.withUnsafeBytes { Array($0) }
    }

    public func withUnsafeBytes<Result, E: Error>(
        _ body: (UnsafeRawBufferPointer) throws(E) -> Result
    ) throws(E) -> Result {
        return try Swift.withUnsafeBytes(of: self.storage) { (raw) throws(E) -> Result in
            return try body(raw)
        }
    }
}

extension QUICStatelessResetToken: Hashable {
    public static func == (lhs: QUICStatelessResetToken, rhs: QUICStatelessResetToken) -> Bool {
        return lhs.storage.0 == rhs.storage.0 && lhs.storage.1 == rhs.storage.1
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.storage.0)
        hasher.combine(self.storage.1)
    }
}
