//
//  VLESSEncryptionCTR.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/13/26.
//

import Foundation
import CommonCrypto

/// AES-256-CTR keystream used by VLESS encryption's `xorpub` and `random`
/// modes. Matches Xray-core's `NewCTR` in `proxy/vless/encryption/xor.go`:
/// the 32-byte AES key is derived from `(context="VLESS", key)` via BLAKE3,
/// and the 16-byte IV is used as the initial counter (big-endian).
///
/// XOR is a stream operation, so a single instance carries state and must
/// not be shared across simultaneous callers. The framing layer keeps one
/// CTR for outbound bytes and one for inbound, each used from a single
/// direction's serial queue.
final class VLESSEncryptionCTR {
    private var cryptor: CCCryptorRef?
    private let lock = UnfairLock()

    init(key: Data, iv: Data) {
        precondition(iv.count == 16, "VLESS CTR IV must be 16 bytes")
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
        precondition(status == kCCSuccess, "CCCryptorCreateWithMode failed: \(status)")
        self.cryptor = ref
    }

    deinit {
        if let cryptor {
            CCCryptorRelease(cryptor)
        }
    }

    /// Advance the keystream by `data.count` bytes and return the XOR'd
    /// output. Equivalent to Go's `cipher.Stream.XORKeyStream(dst, src)`.
    func process(_ data: Data) -> Data {
        if data.isEmpty { return data }
        return lock.withLock {
            let count = data.count
            var output = Data(count: count)
            var dataOutMoved: Int = 0
            let status = output.withUnsafeMutableBytes { outPtr -> CCCryptorStatus in
                data.withUnsafeBytes { inPtr in
                    CCCryptorUpdate(
                        cryptor,
                        inPtr.baseAddress, count,
                        outPtr.baseAddress, count,
                        &dataOutMoved
                    )
                }
            }
            precondition(status == kCCSuccess, "CCCryptorUpdate failed: \(status)")
            precondition(dataOutMoved == count, "CTR stream cipher must not buffer")
            return output
        }
    }

    /// XOR `count` bytes from the keystream directly into a mutable buffer.
    /// Used by ``VLESSXORConnection`` so it can mutate slices of an in-flight
    /// transport buffer without an extra copy.
    func processInPlace(_ buffer: UnsafeMutableRawBufferPointer) {
        if buffer.count == 0 { return }
        lock.withLock {
            var dataOutMoved: Int = 0
            let status = CCCryptorUpdate(
                cryptor,
                buffer.baseAddress, buffer.count,
                buffer.baseAddress, buffer.count,
                &dataOutMoved
            )
            precondition(status == kCCSuccess, "CCCryptorUpdate failed: \(status)")
            precondition(dataOutMoved == buffer.count, "CTR stream cipher must not buffer")
        }
    }
}
