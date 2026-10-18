//
//  SudokuNativeCrypto.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation
import CryptoKit
import Security

nonisolated enum SudokuNativeCrypto {
    static func randomData(count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { raw -> OSStatus in
            guard let base = raw.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "random generator failed")) }
        return data
    }

    static func randomNonZeroUInt32() throws -> UInt32 {
        while true {
            let bytes = [UInt8](try randomData(count: 4))
            let value = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            if value != 0 && value != UInt32.max { return value }
        }
    }

    static func randomNonZeroUInt64() throws -> UInt64 {
        while true {
            let bytes = [UInt8](try randomData(count: 8))
            let value = bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            if value != 0 && value != UInt64.max { return value }
        }
    }

    static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
    static func sha256(_ string: String) -> Data { sha256(Data(string.utf8)) }

    static func hmacSHA256(key: Data, parts: [Data]) -> Data {
        var auth = HMAC<SHA256>(key: SymmetricKey(data: key))
        for part in parts { auth.update(data: part) }
        return Data(auth.finalize())
    }

    static func hkdfExpand(prk: Data, info: String, count: Int) -> Data {
        var produced = Data()
        var block = Data()
        var counter: UInt8 = 1
        while produced.count < count {
            var parts: [Data] = []
            if !block.isEmpty { parts.append(block) }
            parts.append(Data(info.utf8))
            parts.append(Data([counter]))
            block = hmacSHA256(key: prk, parts: parts)
            produced.append(block.prefix(count - produced.count))
            counter &+= 1
        }
        return produced
    }

    static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        hmacSHA256(key: salt, parts: [ikm])
    }

    static func pskBases(_ psk: String) -> (c2s: Data, s2c: Data) {
        let sum = sha256(psk)
        return (
            hkdfExpand(prk: sum, info: "sudoku-psk-c2s", count: 32),
            hkdfExpand(prk: sum, info: "sudoku-psk-s2c", count: 32)
        )
    }

    static func sessionBases(psk: String, shared: Data, nonce: Data) -> (c2s: Data, s2c: Data) {
        let salt = sha256(psk)
        var ikm = Data()
        ikm.append(shared)
        ikm.append(nonce)
        let prk = hkdfExtract(salt: salt, ikm: ikm)
        return (
            hkdfExpand(prk: prk, info: "sudoku-session-c2s", count: 32),
            hkdfExpand(prk: prk, info: "sudoku-session-s2c", count: 32)
        )
    }

    static func recordEpochKey(base: Data, method: SudokuAEADMethod, epoch: UInt32) -> Data {
        var epochBE = epoch.bigEndian
        let epochData = Data(bytes: &epochBE, count: 4)
        let methodName = method == .aes128GCM ? "aes-128-gcm" : "chacha20-poly1305"
        return hmacSHA256(key: base, parts: [Data("sudoku-record:".utf8), Data(methodName.utf8), epochData])
    }

    static func recordSymmetricKey(base: Data, method: SudokuAEADMethod, epoch: UInt32) -> SymmetricKey {
        let bytes = recordEpochKey(base: base, method: method, epoch: epoch)
        return SymmetricKey(data: bytes.prefix(method == .aes128GCM ? 16 : 32))
    }

    static func seal(method: SudokuAEADMethod, key: Data, nonce: Data, plaintext: Data, aad: Data) throws -> Data {
        try seal(method: method, key: SymmetricKey(data: key.prefix(method == .aes128GCM ? 16 : 32)), nonce: nonce, plaintext: plaintext, aad: aad)
    }

    static func openRecord(method: SudokuAEADMethod, key: SymmetricKey, body: Data) throws -> Data {
        let header = body.prefix(12)
        do {
            switch method {
            case .aes128GCM:
                return try AES.GCM.open(AES.GCM.SealedBox(combined: body), using: key, authenticating: header)
            case .chacha20Poly1305:
                return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: body), using: key, authenticating: header)
            case .none:
                return body
            }
        } catch {
            let detail = method == .aes128GCM ? "AES-GCM open failed" : "ChaCha20-Poly1305 open failed"
            throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: detail))
        }
    }

    static func seal(method: SudokuAEADMethod, key: SymmetricKey, nonce: Data, plaintext: Data, aad: Data) throws -> Data {
        switch method {
        case .aes128GCM:
            let box = try AES.GCM.seal(
                plaintext,
                using: key,
                nonce: AES.GCM.Nonce(data: nonce),
                authenticating: aad
            )
            guard let combined = box.combined else {
                throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "invalid record nonce length"))
            }
            return combined.dropFirst(nonce.count)
        case .chacha20Poly1305:
            let box = try ChaChaPoly.seal(
                plaintext,
                using: key,
                nonce: ChaChaPoly.Nonce(data: nonce),
                authenticating: aad
            )
            return box.combined.dropFirst(nonce.count)
        case .none:
            return plaintext
        }
    }

    static func open(method: SudokuAEADMethod, key: Data, nonce: Data, ciphertext: Data, aad: Data) throws -> Data {
        try open(method: method, key: SymmetricKey(data: key.prefix(method == .aes128GCM ? 16 : 32)), nonce: nonce, ciphertext: ciphertext, aad: aad)
    }

    static func open(method: SudokuAEADMethod, key: SymmetricKey, nonce: Data, ciphertext: Data, aad: Data) throws -> Data {
        switch method {
        case .aes128GCM:
            guard ciphertext.count >= 16 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "short AES-GCM frame")) }
            let split = ciphertext.count - 16
            do {
                let box = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: nonce),
                    ciphertext: ciphertext.prefix(split),
                    tag: ciphertext.suffix(16)
                )
                return try AES.GCM.open(box, using: key, authenticating: aad)
            } catch {
                throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "AES-GCM open failed"))
            }
        case .chacha20Poly1305:
            guard ciphertext.count >= 16 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "short ChaCha20-Poly1305 frame")) }
            let split = ciphertext.count - 16
            do {
                let box = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonce),
                    ciphertext: ciphertext.prefix(split),
                    tag: ciphertext.suffix(16)
                )
                return try ChaChaPoly.open(box, using: key, authenticating: aad)
            } catch {
                throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "ChaCha20-Poly1305 open failed"))
            }
        case .none:
            return ciphertext
        }
    }
}
