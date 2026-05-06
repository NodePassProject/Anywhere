//
//  VMessCrypto.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/6/26.
//

import CommonCrypto
import CryptoKit
import Foundation

enum VMessCrypto {
    private static let kdfSalt = Data("VMess AEAD KDF".utf8)
    private static let sha256BlockSize = 64

    static func randomData(count: Int) -> Data {
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { raw in
            SecRandomCopyBytes(kSecRandomDefault, count, raw.baseAddress!)
        }
        if status != errSecSuccess {
            var fallback = [UInt8](repeating: 0, count: count)
            for i in fallback.indices { fallback[i] = UInt8.random(in: .min ... .max) }
            return Data(fallback)
        }
        return data
    }

    static func md5(_ data: Data) -> Data {
        Data(Insecure.MD5.hash(data: data))
    }

    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func hmacSHA256(key: Data, data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    static func commandKey(for uuid: UUID) -> Data {
        var input = uuid.vmessBytes
        input.append(Data("c48619fe-8f02-49e0-b9e9-edf763e17e21".utf8))
        return md5(input)
    }

    static func kdf(_ key: Data, path: Data...) -> Data {
        kdf(key, path: path)
    }

    static func kdf(_ key: Data, path: [Data]) -> Data {
        kdfHash(level: path.count, path: path, data: key)
    }

    static func kdf16(_ key: Data, path: Data...) -> Data {
        Data(kdf(key, path: path).prefix(16))
    }

    static func kdf16(_ key: Data, path: [Data]) -> Data {
        Data(kdf(key, path: path).prefix(16))
    }

    private static func kdfHash(level: Int, path: [Data], data: Data) -> Data {
        guard level > 0 else {
            return hmacSHA256(key: kdfSalt, data: data)
        }

        var key = path[level - 1]
        if key.count > sha256BlockSize {
            key = kdfHash(level: level - 1, path: path, data: key)
        }

        var ipad = Data(repeating: 0x36, count: sha256BlockSize)
        var opad = Data(repeating: 0x5c, count: sha256BlockSize)
        for (index, byte) in key.enumerated() {
            ipad[index] = byte ^ 0x36
            opad[index] = byte ^ 0x5c
        }

        var innerInput = Data(capacity: sha256BlockSize + data.count)
        innerInput.append(ipad)
        innerInput.append(data)
        let inner = kdfHash(level: level - 1, path: path, data: innerInput)

        var outerInput = Data(capacity: sha256BlockSize + inner.count)
        outerInput.append(opad)
        outerInput.append(inner)
        return kdfHash(level: level - 1, path: path, data: outerInput)
    }

    static func aesECBEncryptBlock(_ block: Data, key: Data) throws -> Data {
        guard block.count == kCCBlockSizeAES128 else {
            throw ProxyError.protocolError("VMess AES block size must be 16 bytes")
        }
        var output = Data(count: kCCBlockSizeAES128)
        let outputCapacity = output.count
        var outputLength: size_t = 0
        let status = output.withUnsafeMutableBytes { outRaw in
            block.withUnsafeBytes { blockRaw in
                key.withUnsafeBytes { keyRaw in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        keyRaw.baseAddress, key.count,
                        nil,
                        blockRaw.baseAddress, block.count,
                        outRaw.baseAddress, outputCapacity,
                        &outputLength
                    )
                }
            }
        }
        guard status == kCCSuccess, outputLength == kCCBlockSizeAES128 else {
            throw ProxyError.protocolError("VMess AES block encryption failed")
        }
        return output
    }

    static func sealAESGCM(key: Data, nonce: Data, plaintext: Data, aad: Data = Data()) throws -> Data {
        let box = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )
        var output = Data(box.ciphertext)
        output.append(box.tag)
        return output
    }

    static func openAESGCM(key: Data, nonce: Data, ciphertextAndTag: Data, aad: Data = Data()) throws -> Data {
        guard ciphertextAndTag.count >= 16 else {
            throw ProxyError.invalidResponse("VMess AES-GCM payload is too short")
        }
        let ciphertext = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
        let tag = ciphertextAndTag.suffix(16)
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        return Data(try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad))
    }

    static func sealChaCha20Poly1305(
        key: Data,
        nonce: Data,
        plaintext: Data,
        expandedKey: Data? = nil
    ) throws -> Data {
        let box = try ChaChaPoly.seal(
            plaintext,
            using: SymmetricKey(data: expandedKey ?? generateChaCha20Poly1305Key(from: key)),
            nonce: ChaChaPoly.Nonce(data: nonce)
        )
        var output = Data(box.ciphertext)
        output.append(box.tag)
        return output
    }

    static func openChaCha20Poly1305(
        key: Data,
        nonce: Data,
        ciphertextAndTag: Data,
        expandedKey: Data? = nil
    ) throws -> Data {
        guard ciphertextAndTag.count >= 16 else {
            throw ProxyError.invalidResponse("VMess ChaCha20-Poly1305 payload is too short")
        }
        let ciphertext = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
        let tag = ciphertextAndTag.suffix(16)
        let box = try ChaChaPoly.SealedBox(
            nonce: ChaChaPoly.Nonce(data: nonce),
            ciphertext: ciphertext,
            tag: tag
        )
        return Data(try ChaChaPoly.open(box, using: SymmetricKey(data: expandedKey ?? generateChaCha20Poly1305Key(from: key))))
    }

    static func generateChaCha20Poly1305Key(from key: Data) -> Data {
        let first = md5(key)
        let second = md5(first)
        var output = Data(capacity: 32)
        output.append(first)
        output.append(second)
        return output
    }

    static func crc32IEEE(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xffffffff
        for byte in data {
            let index = Int((crc ^ UInt32(byte)) & 0xff)
            crc = (crc >> 8) ^ crc32Table[index]
        }
        return crc ^ 0xffffffff
    }

    static func fnv1a32(_ data: Data) -> UInt32 {
        var hash: UInt32 = 2166136261
        for byte in data {
            hash ^= UInt32(byte)
            hash = hash &* 16777619
        }
        return hash
    }

    static func appendUInt16BE(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0xff))
    }

    static func appendUInt32BE(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    static func appendInt64BE(_ value: Int64, to data: inout Data) {
        let unsigned = UInt64(bitPattern: value)
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((unsigned >> UInt64(shift)) & 0xff))
        }
    }

    static func readUInt16BE(_ data: Data, offset: Int = 0) -> UInt16 {
        (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
    }

    struct ShakeSizeParser {
        private var shake: Shake128

        init(nonce: Data) {
            shake = Shake128(seed: nonce)
        }

        mutating func encode(_ size: UInt16) -> UInt16 {
            shake.readUInt16BE() ^ size
        }

        mutating func decode(_ value: UInt16) -> UInt16 {
            shake.readUInt16BE() ^ value
        }

        mutating func nextPaddingLength() -> UInt16 {
            shake.readUInt16BE() % 64
        }
    }

    private struct Shake128 {
        private static let rate = 168
        private static let roundConstants: [UInt64] = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
        ]
        private static let rotationOffsets: [UInt64] = [
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14,
        ]

        private var state = [UInt64](repeating: 0, count: 25)
        private var buffer = [UInt8](repeating: 0, count: rate)
        private var bufferOffset = rate
        private var hasSqueezedBlock = false

        init(seed: Data) {
            var absorbOffset = 0
            for byte in seed {
                xor(byte, at: absorbOffset)
                absorbOffset += 1
                if absorbOffset == Self.rate {
                    permute()
                    absorbOffset = 0
                }
            }
            xor(0x1f, at: absorbOffset)
            xor(0x80, at: Self.rate - 1)
            permute()
        }

        mutating func readUInt16BE() -> UInt16 {
            (UInt16(readByte()) << 8) | UInt16(readByte())
        }

        private mutating func readByte() -> UInt8 {
            if bufferOffset == Self.rate {
                fillBuffer()
            }
            let byte = buffer[bufferOffset]
            bufferOffset += 1
            return byte
        }

        private mutating func xor(_ byte: UInt8, at offset: Int) {
            state[offset / 8] ^= UInt64(byte) << UInt64((offset % 8) * 8)
        }

        private mutating func fillBuffer() {
            if hasSqueezedBlock {
                permute()
            } else {
                hasSqueezedBlock = true
            }
            for offset in 0..<Self.rate {
                buffer[offset] = UInt8((state[offset / 8] >> UInt64((offset % 8) * 8)) & 0xff)
            }
            bufferOffset = 0
        }

        private mutating func permute() {
            var c = [UInt64](repeating: 0, count: 5)
            var d = [UInt64](repeating: 0, count: 5)
            var b = [UInt64](repeating: 0, count: 25)

            for roundConstant in Self.roundConstants {
                for x in 0..<5 {
                    c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                }
                for x in 0..<5 {
                    d[x] = c[(x + 4) % 5] ^ Self.rotateLeft(c[(x + 1) % 5], by: 1)
                }
                for x in 0..<5 {
                    for y in 0..<5 {
                        state[x + 5 * y] ^= d[x]
                    }
                }

                for x in 0..<5 {
                    for y in 0..<5 {
                        let source = x + 5 * y
                        let destination = y + 5 * ((2 * x + 3 * y) % 5)
                        b[destination] = Self.rotateLeft(state[source], by: Self.rotationOffsets[source])
                    }
                }

                for x in 0..<5 {
                    for y in 0..<5 {
                        state[x + 5 * y] = b[x + 5 * y]
                            ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
                    }
                }

                state[0] ^= roundConstant
            }
        }

        private static func rotateLeft(_ value: UInt64, by amount: UInt64) -> UInt64 {
            guard amount != 0 else { return value }
            return (value << amount) | (value >> (64 - amount))
        }
    }

    private static let crc32Table: [UInt32] = {
        (0..<256).map { i -> UInt32 in
            var crc = UInt32(i)
            for _ in 0..<8 {
                if crc & 1 == 1 {
                    crc = 0xedb88320 ^ (crc >> 1)
                } else {
                    crc >>= 1
                }
            }
            return crc
        }
    }()
}

private extension UUID {
    var vmessBytes: Data {
        let bytes = uuid
        return Data([
            bytes.0, bytes.1, bytes.2, bytes.3,
            bytes.4, bytes.5, bytes.6, bytes.7,
            bytes.8, bytes.9, bytes.10, bytes.11,
            bytes.12, bytes.13, bytes.14, bytes.15,
        ])
    }
}
