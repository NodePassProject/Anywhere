//
//  BLAKE3+Output.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

extension BLAKE3 {
    struct Output {
        let inputChainingValue: ChainingValue
        let block: SIMD16<UInt32>
        let blockLength: Int
        let counter: UInt64
        let flags: Flags

        static func parent(
            left: ChainingValue,
            right: ChainingValue,
            key: ChainingValue,
            flags: Flags
        ) -> Output {
            var block = SIMD16<UInt32>()
            withUnsafeMutableBytes(of: &block) { block in
                left.storeLittleEndianBytes(to: block.baseAddress!)
                right.storeLittleEndianBytes(to: block.baseAddress! + BLAKE3.keyByteCount)
            }
            return Output(
                inputChainingValue: key,
                block: block,
                blockLength: BLAKE3.blockByteCount,
                counter: 0,
                flags: flags.union(.parent)
            )
        }

        func chainingValue() -> ChainingValue {
            var chainingValue = inputChainingValue
            withUnsafeBytes(of: block) { block in
                BLAKE3.compress(
                    &chainingValue,
                    block: block.baseAddress!,
                    blockLength: blockLength,
                    counter: counter,
                    flags: flags
                )
            }
            return chainingValue
        }

        func writeRootBytes(into output: UnsafeMutableRawBufferPointer) {
            guard var destination = output.baseAddress else { return }
            var remaining = output.count
            var outputBlockCounter: UInt64 = 0
            withUnsafeBytes(of: block) { block in
                let block = block.baseAddress!
                while remaining >= BLAKE3.blockByteCount {
                    BLAKE3.compressXOF(
                        inputChainingValue,
                        block: block,
                        blockLength: blockLength,
                        counter: outputBlockCounter,
                        flags: flags.union(.root),
                        into: destination
                    )
                    outputBlockCounter += 1
                    destination += BLAKE3.blockByteCount
                    remaining -= BLAKE3.blockByteCount
                }
                guard remaining > 0 else { return }
                var outputBlock = SIMD16<UInt32>()
                withUnsafeMutableBytes(of: &outputBlock) { outputBlock in
                    BLAKE3.compressXOF(
                        inputChainingValue,
                        block: block,
                        blockLength: blockLength,
                        counter: outputBlockCounter,
                        flags: flags.union(.root),
                        into: outputBlock.baseAddress!
                    )
                    destination.copyMemory(from: outputBlock.baseAddress!, byteCount: remaining)
                }
            }
        }
    }
}
