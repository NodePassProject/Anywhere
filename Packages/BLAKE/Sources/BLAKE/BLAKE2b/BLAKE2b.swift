//
//  BLAKE2b.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

import Foundation

public struct BLAKE2b: Sendable {
    public static let blockByteCount = 128
    public static let maximumDigestByteCount = 64
    public static let maximumKeyByteCount = 64

    public let digestByteCount: Int

    private var chainingValue: ChainingValue
    private var byteCount: UInt128 = 0
    private var buffer = SIMD16<UInt64>()
    private var bufferedByteCount = 0

    public init(digestByteCount: Int = maximumDigestByteCount) {
        self.init(digestByteCount: digestByteCount, keyByteCount: 0)
    }

    @inlinable
    public init(key: some ContiguousBytes, digestByteCount: Int = maximumDigestByteCount) {
        self = key.withUnsafeBytes { BLAKE2b(keyBuffer: $0, digestByteCount: digestByteCount) }
    }

    @usableFromInline
    init(keyBuffer key: UnsafeRawBufferPointer, digestByteCount: Int) {
        precondition(
            (1...Self.maximumKeyByteCount).contains(key.count),
            "BLAKE2b key must be 1...\(Self.maximumKeyByteCount) bytes"
        )
        self.init(digestByteCount: digestByteCount, keyByteCount: key.count)
        withUnsafeMutableBytes(of: &buffer) { buffer in
            buffer.copyMemory(from: key)
        }
        bufferedByteCount = Self.blockByteCount
    }

    private init(digestByteCount: Int, keyByteCount: Int) {
        precondition(
            (1...Self.maximumDigestByteCount).contains(digestByteCount),
            "BLAKE2b digest must be 1...\(Self.maximumDigestByteCount) bytes"
        )
        self.digestByteCount = digestByteCount
        let parameterBlock = UInt64(digestByteCount) | UInt64(keyByteCount) << 8 | 0x0101_0000
        var chainingValue = ChainingValue.initializationVector
        chainingValue.h0 ^= parameterBlock
        self.chainingValue = chainingValue
    }

    // MARK: - Hashing

    @inlinable
    public mutating func update(data: some DataProtocol) {
        for region in data.regions {
            region.withUnsafeBytes { update(bufferPointer: $0) }
        }
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        guard var input = bufferPointer.baseAddress, !bufferPointer.isEmpty else { return }
        var remaining = bufferPointer.count
        let availableByteCount = Self.blockByteCount - bufferedByteCount
        if remaining > availableByteCount {
            withUnsafeMutableBytes(of: &buffer) { buffer in
                let block = buffer.baseAddress!
                (block + bufferedByteCount).copyMemory(from: input, byteCount: availableByteCount)
                byteCount &+= UInt128(Self.blockByteCount)
                Self.compress(&chainingValue, block: block, byteCount: byteCount, isLastBlock: false)
            }
            bufferedByteCount = 0
            input += availableByteCount
            remaining -= availableByteCount
            while remaining > Self.blockByteCount {
                byteCount &+= UInt128(Self.blockByteCount)
                Self.compress(&chainingValue, block: input, byteCount: byteCount, isLastBlock: false)
                input += Self.blockByteCount
                remaining -= Self.blockByteCount
            }
        }
        withUnsafeMutableBytes(of: &buffer) { buffer in
            (buffer.baseAddress! + bufferedByteCount).copyMemory(from: input, byteCount: remaining)
        }
        bufferedByteCount += remaining
    }

    public func finalize() -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: digestByteCount) { digest, initializedCount in
            finalize(into: UnsafeMutableRawBufferPointer(digest))
            initializedCount = digestByteCount
        }
    }

    public func finalize(into digest: UnsafeMutableRawBufferPointer) {
        precondition(digest.count == digestByteCount, "BLAKE2b digest buffer must be \(digestByteCount) bytes")
        var chainingValue = chainingValue
        var block = buffer
        withUnsafeMutableBytes(of: &block) { block in
            let block = block.baseAddress!
            (block + bufferedByteCount).initializeMemory(
                as: UInt8.self,
                repeating: 0,
                count: Self.blockByteCount - bufferedByteCount
            )
            Self.compress(
                &chainingValue,
                block: block,
                byteCount: byteCount &+ UInt128(bufferedByteCount),
                isLastBlock: true
            )
        }
        withUnsafeTemporaryAllocation(byteCount: Self.maximumDigestByteCount, alignment: 1) { fullDigest in
            chainingValue.storeLittleEndianBytes(to: fullDigest.baseAddress!)
            digest.copyMemory(from: UnsafeRawBufferPointer(rebasing: fullDigest.prefix(digestByteCount)))
        }
    }

    // MARK: - One-Shot Hashing

    @inlinable
    public static func hash(data: some DataProtocol, digestByteCount: Int = maximumDigestByteCount) -> [UInt8] {
        var hasher = BLAKE2b(digestByteCount: digestByteCount)
        hasher.update(data: data)
        return hasher.finalize()
    }
}
