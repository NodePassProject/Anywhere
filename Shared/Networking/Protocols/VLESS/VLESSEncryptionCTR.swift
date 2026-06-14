//
//  VLESSEncryptionCTR.swift
//  Anywhere
//
//  Created by NodePassProject on 5/13/26.
//

import Foundation
import CommonCrypto

/// AES-256-CTR keystream for VLESS encryption's `xorpub`/`random` modes:
/// key = BLAKE3-derive(context "VLESS", key), 16-byte IV as the initial
/// big-endian counter. Stateful — one instance per direction.
final class VLESSEncryptionCTR {
    private var cryptor: CCCryptorRef?
    private let lock = UnfairLock()

    init(key: Data, iv: Data) throws {
        guard iv.count == 16 else {
            throw VLESSEncryptionError.framingError("VLESS CTR IV must be 16 bytes, got \(iv.count)")
        }
        let derivedKey = Blake3Hasher.deriveKey(context: "VLESS", input: key, count: 32)

        var ref: CCCryptorRef?
        let status = derivedKey.withUnsafeBytes { keyPtr -> CCCryptorStatus in
            iv.withUnsafeBytes { ivPtr in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivPtr.baseAddress,
                    keyPtr.baseAddress,
                    32,
                    nil, 0,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &ref
                )
            }
        }
        guard status == kCCSuccess, let ref else {
            throw VLESSEncryptionError.framingError("CCCryptorCreateWithMode failed: \(status)")
        }
        self.cryptor = ref
    }

    deinit {
        if let cryptor {
            CCCryptorRelease(cryptor)
        }
    }

    /// Advance the keystream by `data.count` bytes and return the XOR'd output.
    func process(_ data: Data) -> Data {
        if data.isEmpty { return data }
        return lock.withLock {
            let count = data.count
            var output = Data(count: count)
            var dataOutMoved: Int = 0
            _ = output.withUnsafeMutableBytes { outPtr -> CCCryptorStatus in
                data.withUnsafeBytes { inPtr in
                    CCCryptorUpdate(
                        cryptor,
                        inPtr.baseAddress, count,
                        outPtr.baseAddress, count,
                        &dataOutMoved
                    )
                }
            }
            return output
        }
    }

    /// XOR keystream bytes directly into a mutable buffer, avoiding an extra copy.
    func processInPlace(_ buffer: UnsafeMutableRawBufferPointer) {
        if buffer.count == 0 { return }
        lock.withLock {
            var dataOutMoved: Int = 0
            _ = CCCryptorUpdate(
                cryptor,
                buffer.baseAddress, buffer.count,
                buffer.baseAddress, buffer.count,
                &dataOutMoved
            )
        }
    }
}
