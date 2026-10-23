//
//  BLAKE3+ChunkState.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

extension BLAKE3 {
    struct ChunkState {
        let chunkCounter: UInt64
        private let flags: Flags
        private var chainingValue: ChainingValue
        private var block = SIMD16<UInt32>()
        private var blockByteCount = 0
        private var compressedBlockCount = 0

        init(key: ChainingValue, chunkCounter: UInt64, flags: Flags) {
            self.chunkCounter = chunkCounter
            self.flags = flags
            self.chainingValue = key
        }

        var byteCount: Int {
            compressedBlockCount * BLAKE3.blockByteCount + blockByteCount
        }

        private var startFlag: Flags {
            compressedBlockCount == 0 ? .chunkStart : []
        }

        mutating func update(_ bytes: UnsafeRawBufferPointer) {
            guard var input = bytes.baseAddress, !bytes.isEmpty else { return }
            var remaining = bytes.count
            if blockByteCount > 0 {
                let fillCount = min(BLAKE3.blockByteCount - blockByteCount, remaining)
                fillBlock(from: input, byteCount: fillCount)
                input += fillCount
                remaining -= fillCount
                guard remaining > 0 else { return }
                withUnsafeBytes(of: block) { block in
                    BLAKE3.compress(
                        &chainingValue,
                        block: block.baseAddress!,
                        blockLength: BLAKE3.blockByteCount,
                        counter: chunkCounter,
                        flags: flags.union(startFlag)
                    )
                }
                compressedBlockCount += 1
                block = SIMD16()
                blockByteCount = 0
            }
            while remaining > BLAKE3.blockByteCount {
                BLAKE3.compress(
                    &chainingValue,
                    block: input,
                    blockLength: BLAKE3.blockByteCount,
                    counter: chunkCounter,
                    flags: flags.union(startFlag)
                )
                compressedBlockCount += 1
                input += BLAKE3.blockByteCount
                remaining -= BLAKE3.blockByteCount
            }
            fillBlock(from: input, byteCount: remaining)
        }

        func output() -> Output {
            Output(
                inputChainingValue: chainingValue,
                block: block,
                blockLength: blockByteCount,
                counter: chunkCounter,
                flags: flags.union(startFlag).union(.chunkEnd)
            )
        }

        static func chainingValue(
            ofChunk chunk: UnsafeRawPointer,
            key: ChainingValue,
            chunkCounter: UInt64,
            flags: Flags
        ) -> ChainingValue {
            var chainingValue = key
            var block = chunk
            var blockFlags = flags.union(.chunkStart)
            var remainingBlockCount = BLAKE3.chunkByteCount / BLAKE3.blockByteCount
            while remainingBlockCount > 0 {
                if remainingBlockCount == 1 {
                    blockFlags.formUnion(.chunkEnd)
                }
                BLAKE3.compress(
                    &chainingValue,
                    block: block,
                    blockLength: BLAKE3.blockByteCount,
                    counter: chunkCounter,
                    flags: blockFlags
                )
                blockFlags = flags
                block += BLAKE3.blockByteCount
                remainingBlockCount -= 1
            }
            return chainingValue
        }

        private mutating func fillBlock(from input: UnsafeRawPointer, byteCount: Int) {
            withUnsafeMutableBytes(of: &block) { block in
                (block.baseAddress! + blockByteCount).copyMemory(from: input, byteCount: byteCount)
            }
            blockByteCount += byteCount
        }
    }
}
