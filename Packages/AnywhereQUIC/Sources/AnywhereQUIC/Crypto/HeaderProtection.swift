//
//  HeaderProtection.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import CommonCrypto

final class HeaderProtector {
    private enum Backend {
        case aes(AESECBEncryptor)
        case chaCha20([UInt8])
    }

    private let backend: Backend

    init(aead: AEADAlgorithm, key: [UInt8]) {
        precondition(key.count == aead.keyLength)
        switch aead {
        case .aes128GCM, .aes256GCM:
            self.backend = .aes(AESECBEncryptor(key: key))
        case .chaCha20Poly1305:
            self.backend = .chaCha20(key)
        }
    }

    func mask(sample: UnsafeRawBufferPointer) -> (UInt8, UInt8, UInt8, UInt8, UInt8) {
        precondition(sample.count >= 16)
        switch self.backend {
        case .aes(let encryptor):
            var block = (UInt64(0), UInt64(0))
            withUnsafeMutableBytes(of: &block) { out in
                encryptor.encryptBlock(sample, into: out)
            }
            return withUnsafeBytes(of: block) { ($0[0], $0[1], $0[2], $0[3], $0[4]) }
        case .chaCha20(let key):
            let counter = UInt32(sample[0])
                | UInt32(sample[1]) << 8
                | UInt32(sample[2]) << 16
                | UInt32(sample[3]) << 24
            var nonce = (UInt32(0), UInt32(0), UInt32(0))
            withUnsafeMutableBytes(of: &nonce) { raw in
                raw.copyMemory(from: UnsafeRawBufferPointer(rebasing: sample[4..<16]))
            }
            let stream = ChaCha20.block(key: key, counter: counter, nonce: nonce)
            return (stream[0], stream[1], stream[2], stream[3], stream[4])
        }
    }
}

private final class AESECBEncryptor {
    private let cryptor: CCCryptorRef

    init(key: [UInt8]) {
        var reference: CCCryptorRef?
        let status = key.withUnsafeBytes { keyBytes in
            return CCCryptorCreateWithMode(
                CCOperation(kCCEncrypt),
                CCMode(kCCModeECB),
                CCAlgorithm(kCCAlgorithmAES),
                CCPadding(ccNoPadding),
                nil,
                keyBytes.baseAddress,
                keyBytes.count,
                nil,
                0,
                0,
                0,
                &reference
            )
        }
        guard status == kCCSuccess, let reference else {
            preconditionFailure("AES cryptor creation failed")
        }
        self.cryptor = reference
    }

    deinit {
        CCCryptorRelease(self.cryptor)
    }

    func encryptBlock(_ input: UnsafeRawBufferPointer, into output: UnsafeMutableRawBufferPointer) {
        precondition(input.count >= 16 && output.count >= 16)
        var moved = 0
        let status = CCCryptorUpdate(self.cryptor, input.baseAddress, 16, output.baseAddress, 16, &moved)
        precondition(status == kCCSuccess && moved == 16, "AES block encryption failed")
    }
}

private enum ChaCha20 {
    private static func rotate(_ value: UInt32, _ count: UInt32) -> UInt32 {
        return value << count | value >> (32 - count)
    }

    private static func quarterRound(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        state[a] &+= state[b]
        state[d] ^= state[a]
        state[d] = Self.rotate(state[d], 16)
        state[c] &+= state[d]
        state[b] ^= state[c]
        state[b] = Self.rotate(state[b], 12)
        state[a] &+= state[b]
        state[d] ^= state[a]
        state[d] = Self.rotate(state[d], 8)
        state[c] &+= state[d]
        state[b] ^= state[c]
        state[b] = Self.rotate(state[b], 7)
    }

    static func block(key: [UInt8], counter: UInt32, nonce: (UInt32, UInt32, UInt32)) -> [UInt8] {
        precondition(key.count == 32)
        var state = [UInt32](repeating: 0, count: 16)
        state[0] = 0x6170_7865
        state[1] = 0x3320_646E
        state[2] = 0x7962_2D32
        state[3] = 0x6B20_6574
        for index in 0..<8 {
            let base = index * 4
            state[4 + index] = UInt32(key[base])
                | UInt32(key[base + 1]) << 8
                | UInt32(key[base + 2]) << 16
                | UInt32(key[base + 3]) << 24
        }
        state[12] = counter
        state[13] = UInt32(littleEndian: nonce.0)
        state[14] = UInt32(littleEndian: nonce.1)
        state[15] = UInt32(littleEndian: nonce.2)
        var working = state
        for _ in 0..<10 {
            Self.quarterRound(&working, 0, 4, 8, 12)
            Self.quarterRound(&working, 1, 5, 9, 13)
            Self.quarterRound(&working, 2, 6, 10, 14)
            Self.quarterRound(&working, 3, 7, 11, 15)
            Self.quarterRound(&working, 0, 5, 10, 15)
            Self.quarterRound(&working, 1, 6, 11, 12)
            Self.quarterRound(&working, 2, 7, 8, 13)
            Self.quarterRound(&working, 3, 4, 9, 14)
        }
        var output = [UInt8](repeating: 0, count: 64)
        for index in 0..<16 {
            let word = working[index] &+ state[index]
            output[index * 4] = UInt8(truncatingIfNeeded: word)
            output[index * 4 + 1] = UInt8(truncatingIfNeeded: word >> 8)
            output[index * 4 + 2] = UInt8(truncatingIfNeeded: word >> 16)
            output[index * 4 + 3] = UInt8(truncatingIfNeeded: word >> 24)
        }
        return output
    }
}
