//
//  BLAKE3.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

import Foundation

public struct BLAKE3: Sendable {
    public static let keyByteCount = 32
    public static let defaultOutputByteCount = 32
    public static let blockByteCount = 64
    static let chunkByteCount = 1024

    private let key: ChainingValue
    private let flags: Flags
    private var chunkState: ChunkState
    private var chainingValueStack: [ChainingValue] = []

    public init() {
        self.init(key: .initializationVector, flags: [])
    }

    @inlinable
    public init(key: some ContiguousBytes) {
        self = key.withUnsafeBytes { BLAKE3(keyBuffer: $0) }
    }

    @usableFromInline
    init(keyBuffer key: UnsafeRawBufferPointer) {
        precondition(key.count == Self.keyByteCount, "BLAKE3 key must be \(Self.keyByteCount) bytes")
        self.init(key: ChainingValue(littleEndianBytes: key.baseAddress!), flags: .keyedHash)
    }

    public init(derivingKeyWithContext context: String) {
        var contextHasher = Self.contextHasher()
        var context = context
        context.withUTF8 { contextHasher.update(bufferPointer: UnsafeRawBufferPointer($0)) }
        self.init(contextHasher: contextHasher)
    }

    @inlinable
    public init(derivingKeyWithContext context: some DataProtocol) {
        var contextHasher = Self.contextHasher()
        contextHasher.update(data: context)
        self.init(contextHasher: contextHasher)
    }

    @usableFromInline
    static func contextHasher() -> BLAKE3 {
        BLAKE3(key: .initializationVector, flags: .deriveKeyContext)
    }

    @usableFromInline
    init(contextHasher: BLAKE3) {
        let contextKey = withUnsafeTemporaryAllocation(byteCount: Self.keyByteCount, alignment: 1) { contextKey in
            contextHasher.finalize(into: contextKey)
            return ChainingValue(littleEndianBytes: contextKey.baseAddress!)
        }
        self.init(key: contextKey, flags: .deriveKeyMaterial)
    }

    private init(key: ChainingValue, flags: Flags) {
        self.key = key
        self.flags = flags
        self.chunkState = ChunkState(key: key, chunkCounter: 0, flags: flags)
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
        while remaining > 0 {
            if chunkState.byteCount == Self.chunkByteCount {
                completeChunk(chainingValue: chunkState.output().chainingValue())
            }
            while chunkState.byteCount == 0, remaining > Self.chunkByteCount {
                completeChunk(chainingValue: ChunkState.chainingValue(
                    ofChunk: input,
                    key: key,
                    chunkCounter: chunkState.chunkCounter,
                    flags: flags
                ))
                input += Self.chunkByteCount
                remaining -= Self.chunkByteCount
            }
            let byteCount = min(Self.chunkByteCount - chunkState.byteCount, remaining)
            chunkState.update(UnsafeRawBufferPointer(start: input, count: byteCount))
            input += byteCount
            remaining -= byteCount
        }
    }

    public func finalize(outputByteCount: Int = defaultOutputByteCount) -> [UInt8] {
        [UInt8](unsafeUninitializedCapacity: outputByteCount) { output, initializedCount in
            finalize(into: UnsafeMutableRawBufferPointer(output))
            initializedCount = outputByteCount
        }
    }

    public func finalize(into output: UnsafeMutableRawBufferPointer) {
        guard !output.isEmpty else { return }
        var rootOutput = chunkState.output()
        for chainingValue in chainingValueStack.reversed() {
            rootOutput = .parent(left: chainingValue, right: rootOutput.chainingValue(), key: key, flags: flags)
        }
        rootOutput.writeRootBytes(into: output)
    }

    private mutating func completeChunk(chainingValue: ChainingValue) {
        var chainingValue = chainingValue
        var chunkCount = chunkState.chunkCounter + 1
        chunkState = ChunkState(key: key, chunkCounter: chunkCount, flags: flags)
        while chunkCount & 1 == 0 {
            chainingValue = Output.parent(
                left: chainingValueStack.removeLast(),
                right: chainingValue,
                key: key,
                flags: flags
            ).chainingValue()
            chunkCount >>= 1
        }
        chainingValueStack.append(chainingValue)
    }

    // MARK: - One-Shot Hashing

    @inlinable
    public static func hash(data: some DataProtocol, outputByteCount: Int = defaultOutputByteCount) -> [UInt8] {
        var hasher = BLAKE3()
        hasher.update(data: data)
        return hasher.finalize(outputByteCount: outputByteCount)
    }

    @inlinable
    public static func deriveKey(
        context: String,
        keyMaterial: some DataProtocol,
        outputByteCount: Int = defaultOutputByteCount
    ) -> [UInt8] {
        var hasher = BLAKE3(derivingKeyWithContext: context)
        hasher.update(data: keyMaterial)
        return hasher.finalize(outputByteCount: outputByteCount)
    }

    @inlinable
    public static func deriveKey(
        context: some DataProtocol,
        keyMaterial: some DataProtocol,
        outputByteCount: Int = defaultOutputByteCount
    ) -> [UInt8] {
        var hasher = BLAKE3(derivingKeyWithContext: context)
        hasher.update(data: keyMaterial)
        return hasher.finalize(outputByteCount: outputByteCount)
    }
}
