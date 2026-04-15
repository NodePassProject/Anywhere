//
//  ShadowsocksAEAD.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/6/26.
//

import Foundation
import CryptoKit
import CommonCrypto

// MARK: - ShadowsocksCipher

/// Supported Shadowsocks AEAD cipher methods.
enum ShadowsocksCipher {
    case aes128gcm
    case aes256gcm
    case chacha20poly1305
    case none
    // Shadowsocks 2022 (BLAKE3-based)
    case blake3aes128gcm
    case blake3aes256gcm
    case blake3chacha20poly1305

    var keySize: Int {
        switch self {
        case .aes128gcm, .blake3aes128gcm: return 16
        case .aes256gcm, .chacha20poly1305: return 32
        case .blake3aes256gcm, .blake3chacha20poly1305: return 32
        case .none: return 0
        }
    }

    /// Salt size (also called IV size in Xray-core). Equals keySize for all ciphers.
    var saltSize: Int { keySize }

    /// AEAD authentication tag size (16 for all AEAD ciphers).
    var tagSize: Int {
        switch self {
        case .none: return 0
        default: return 16
        }
    }

    /// AEAD nonce size (12 for GCM and ChaCha20-Poly1305).
    var nonceSize: Int {
        switch self {
        case .none: return 0
        default: return 12
        }
    }

    /// Whether this is a Shadowsocks 2022 cipher.
    var isSS2022: Bool {
        switch self {
        case .blake3aes128gcm, .blake3aes256gcm, .blake3chacha20poly1305: return true
        default: return false
        }
    }

    init?(method: String) {
        switch method.lowercased() {
        case "aes-128-gcm": self = .aes128gcm
        case "aes-256-gcm": self = .aes256gcm
        case "chacha20-ietf-poly1305", "chacha20-poly1305": self = .chacha20poly1305
        case "none", "plain": self = .none
        case "2022-blake3-aes-128-gcm": self = .blake3aes128gcm
        case "2022-blake3-aes-256-gcm": self = .blake3aes256gcm
        case "2022-blake3-chacha20-poly1305": self = .blake3chacha20poly1305
        default: return nil
        }
    }
}

// MARK: - Key Derivation

/// Shadowsocks key derivation utilities.
enum ShadowsocksKeyDerivation {

    /// Derives a master key from a password using EVP_BytesToKey (MD5-based).
    /// Matches `passwordToCipherKey()` in Xray-core config.go.
    static func deriveKey(password: String, keySize: Int) -> Data {
        guard keySize > 0 else { return Data() }
        let passwordData = Array(password.utf8)
        var result = Data()
        var prev = Data()

        while result.count < keySize {
            var input = Data()
            input.append(prev)
            input.append(contentsOf: passwordData)

            var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
            input.withUnsafeBytes { ptr in
                _ = CC_MD5(ptr.baseAddress, CC_LONG(input.count), &digest)
            }

            prev = Data(digest)
            result.append(prev)
        }

        return Data(result.prefix(keySize))
    }

    /// Derives a subkey from the master key and salt using HKDF-SHA1.
    /// info = "ss-subkey", matching Xray-core's `hkdfSHA1()`.
    static func deriveSubkey(masterKey: Data, salt: Data, keySize: Int) -> Data {
        let symmetricKey = SymmetricKey(data: masterKey)
        let info = "ss-subkey".data(using: .utf8)!
        let derivedKey = HKDF<Insecure.SHA1>.deriveKey(
            inputKeyMaterial: symmetricKey,
            salt: salt,
            info: info,
            outputByteCount: keySize
        )
        return derivedKey.withUnsafeBytes { Data($0) }
    }

    /// Decodes a base64-encoded PSK for Shadowsocks 2022.
    /// The decoded key must be exactly keySize bytes.
    static func decodePSK(password: String, keySize: Int) -> Data? {
        // Support colon-separated multi-PSK (use the last one for client)
        let parts = password.split(separator: ":")
        guard let lastPart = parts.last,
              let psk = Data(base64Encoded: ShadowsocksKeyDerivation.padBase64(String(lastPart))) else {
            return nil
        }
        guard psk.count == keySize else {
            return nil
        }
        return psk
    }

    /// Decodes ALL colon-separated base64-encoded PSKs for Shadowsocks 2022 multi-user mode.
    /// Returns nil if any PSK fails to decode or has wrong size.
    static func decodePSKList(password: String, keySize: Int) -> [Data]? {
        let parts = password.split(separator: ":")
        var psks: [Data] = []
        for part in parts {
            guard let psk = Data(base64Encoded: padBase64(String(part))) else {
                return nil
            }
            guard psk.count == keySize else {
                return nil
            }
            psks.append(psk)
        }
        return psks.isEmpty ? nil : psks
    }

    /// Computes the first 16 bytes of BLAKE3 hash of the given data.
    /// Used for identity header pskHash computation.
    static func blake3Hash16(_ data: Data) -> Data {
        Blake3Hasher.hash(data, count: 16)
    }

    /// Derives an identity subkey using BLAKE3 DeriveKey mode.
    /// context = "shadowsocks 2022 identity subkey", input = psk + salt.
    static func deriveIdentitySubkey(psk: Data, salt: Data, keySize: Int) -> Data {
        var input = Data(psk)
        input.append(salt)
        return Blake3Hasher.deriveKey(context: "shadowsocks 2022 identity subkey",
                                     input: input, count: keySize)
    }

    /// Derives a session key using BLAKE3 DeriveKey mode.
    /// context = "shadowsocks 2022 session subkey", input = psk + salt.
    /// Matching sing-shadowsocks SessionKey().
    static func deriveSessionKey(psk: Data, salt: Data, keySize: Int) -> Data {
        var input = Data(psk)
        input.append(salt)
        return Blake3Hasher.deriveKey(context: "shadowsocks 2022 session subkey",
                                     input: input, count: keySize)
    }

    private static func padBase64(_ string: String) -> String {
        let remainder = string.count % 4
        if remainder == 0 { return string }
        return string + String(repeating: "=", count: 4 - remainder)
    }
}

// MARK: - Nonce Generator

/// Generates incrementing AEAD nonces matching Xray-core's GenerateAEADNonceWithSize.
/// Starts at all 0xFF, increments little-endian before each use.
/// First returned nonce = all zeros.
struct ShadowsocksNonce {
    private var bytes: [UInt8]

    init(size: Int) {
        bytes = [UInt8](repeating: 0xFF, count: size)
    }

    /// Increments the nonce (little-endian) and returns the new value.
    mutating func next() -> Data {
        for i in 0..<bytes.count {
            bytes[i] &+= 1
            if bytes[i] != 0 { break }
        }
        return Data(bytes)
    }
}

// MARK: - AEAD Seal/Open

/// Low-level AEAD operations.
enum ShadowsocksAEADCrypto {

    static func seal(cipher: ShadowsocksCipher, key: Data, nonce: Data, plaintext: Data) throws -> Data {
        let symmetricKey = SymmetricKey(data: key)

        switch cipher {
        case .aes128gcm, .aes256gcm, .blake3aes128gcm, .blake3aes256gcm:
            let nonceObj = try AES.GCM.Nonce(data: nonce)
            let sealed = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonceObj)
            // combined = nonce(12) + ciphertext + tag; skip nonce prefix
            guard let combined = sealed.combined else { throw ShadowsocksError.decryptionFailed }
            return combined.suffix(from: 12)

        case .chacha20poly1305, .blake3chacha20poly1305:
            let nonceObj = try ChaChaPoly.Nonce(data: nonce)
            let sealed = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: nonceObj)
            let combined = sealed.combined
            return combined.suffix(from: 12)

        case .none:
            return plaintext
        }
    }

    static func open(cipher: ShadowsocksCipher, key: Data, nonce: Data, ciphertext: Data) throws -> Data {
        guard cipher != .none else { return ciphertext }

        let symmetricKey = SymmetricKey(data: key)
        let tagSize = cipher.tagSize
        guard ciphertext.count >= tagSize else {
            throw ShadowsocksError.decryptionFailed
        }

        let ct = ciphertext.prefix(ciphertext.count - tagSize)
        let tag = ciphertext.suffix(tagSize)

        switch cipher {
        case .aes128gcm, .aes256gcm, .blake3aes128gcm, .blake3aes256gcm:
            let nonceObj = try AES.GCM.Nonce(data: nonce)
            let box = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
            return try AES.GCM.open(box, using: symmetricKey)

        case .chacha20poly1305, .blake3chacha20poly1305:
            let nonceObj = try ChaChaPoly.Nonce(data: nonce)
            let box = try ChaChaPoly.SealedBox(nonce: nonceObj, ciphertext: ct, tag: tag)
            return try ChaChaPoly.open(box, using: symmetricKey)

        case .none:
            return ciphertext
        }
    }
}

// MARK: - ShadowsocksAEADWriter (Encrypt)

/// Encrypts data into Shadowsocks AEAD chunk format.
///
/// Chunk format: `[Encrypted 2-byte length + 16-byte tag] [Encrypted payload + 16-byte tag]`
/// Max payload per chunk: 0x3FFF (16383 bytes).
/// The salt is prepended to the first output.
class ShadowsocksAEADWriter {
    private let cipher: ShadowsocksCipher
    private let subkey: Data
    private var nonce: ShadowsocksNonce
    private var salt: Data
    private var saltWritten = false

    /// Maximum payload bytes per chunk (matching Xray-core).
    static let maxPayloadSize = 0x3FFF // 16383

    init(cipher: ShadowsocksCipher, masterKey: Data) {
        self.cipher = cipher
        self.nonce = ShadowsocksNonce(size: cipher.nonceSize)

        guard cipher != .none else {
            self.salt = Data()
            self.subkey = Data()
            return
        }

        // Generate random salt
        var saltBytes = [UInt8](repeating: 0, count: cipher.saltSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        self.salt = Data(saltBytes)

        // Derive subkey
        self.subkey = ShadowsocksKeyDerivation.deriveSubkey(
            masterKey: masterKey, salt: salt, keySize: cipher.keySize
        )
    }

    /// Encrypts plaintext into AEAD chunks. Prepends salt on first call.
    func seal(plaintext: Data) throws -> Data {
        guard cipher != .none else {
            return plaintext
        }

        var output = Data()

        // Prepend salt on first write
        if !saltWritten {
            output.append(salt)
            saltWritten = true
        }

        // Split into chunks
        var offset = 0
        while offset < plaintext.count {
            let remaining = plaintext.count - offset
            let chunkSize = min(remaining, Self.maxPayloadSize)
            let chunk = plaintext[plaintext.startIndex.advanced(by: offset)..<plaintext.startIndex.advanced(by: offset + chunkSize)]

            // Encrypt 2-byte length header
            let lengthBytes = Data([UInt8(chunkSize >> 8), UInt8(chunkSize & 0xFF)])
            let encryptedLength = try ShadowsocksAEADCrypto.seal(
                cipher: cipher, key: subkey, nonce: nonce.next(), plaintext: lengthBytes
            )
            output.append(encryptedLength)

            // Encrypt payload
            let encryptedPayload = try ShadowsocksAEADCrypto.seal(
                cipher: cipher, key: subkey, nonce: nonce.next(), plaintext: chunk
            )
            output.append(encryptedPayload)

            offset += chunkSize
        }

        return output
    }
}

// MARK: - ShadowsocksAEADReader (Decrypt)

/// Decrypts Shadowsocks AEAD chunk format.
///
/// State machine: `.waitingSalt` -> `.readingLength` -> `.readingPayload`
class ShadowsocksAEADReader {
    private let cipher: ShadowsocksCipher
    private let masterKey: Data
    private var subkey: Data?
    private var nonce: ShadowsocksNonce
    private var state: State = .waitingSalt
    private var buffer = Data()
    private var bufferOffset = 0
    private var pendingPayloadLength = 0

    /// Compaction threshold — avoid O(n) shifts until dead space is significant.
    private static let compactThreshold = 4096

    private enum State {
        case waitingSalt
        case readingLength
        case readingPayload
    }

    init(cipher: ShadowsocksCipher, masterKey: Data) {
        self.cipher = cipher
        self.masterKey = masterKey
        self.nonce = ShadowsocksNonce(size: cipher.nonceSize)

        if cipher == .none {
            self.subkey = Data()
            self.state = .readingLength
        }
    }

    /// Feeds ciphertext and returns any available decrypted plaintext.
    func open(ciphertext: Data) throws -> Data {
        guard cipher != .none else { return ciphertext }

        buffer.append(ciphertext)
        var output = Data()

        while true {
            let remaining = buffer.count - bufferOffset
            switch state {
            case .waitingSalt:
                guard remaining >= cipher.saltSize else { break }
                let salt = buffer[bufferOffset..<(bufferOffset + cipher.saltSize)]
                bufferOffset += cipher.saltSize
                self.subkey = ShadowsocksKeyDerivation.deriveSubkey(
                    masterKey: masterKey, salt: salt, keySize: cipher.keySize
                )
                state = .readingLength
                continue

            case .readingLength:
                // Encrypted length = 2 bytes + tagSize
                let needed = 2 + cipher.tagSize
                guard remaining >= needed else { break }

                let encryptedLength = buffer[bufferOffset..<(bufferOffset + needed)]
                bufferOffset += needed

                guard let subkey else { throw ShadowsocksError.decryptionFailed }
                let lengthData = try ShadowsocksAEADCrypto.open(
                    cipher: cipher, key: subkey, nonce: nonce.next(), ciphertext: encryptedLength
                )
                guard lengthData.count == 2 else { throw ShadowsocksError.decryptionFailed }

                pendingPayloadLength = Int(UInt16(lengthData[lengthData.startIndex]) << 8 | UInt16(lengthData[lengthData.startIndex + 1]))
                state = .readingPayload
                continue

            case .readingPayload:
                // Encrypted payload = payloadLength + tagSize
                let needed = pendingPayloadLength + cipher.tagSize
                guard remaining >= needed else { break }

                let encryptedPayload = buffer[bufferOffset..<(bufferOffset + needed)]
                bufferOffset += needed

                guard let subkey else { throw ShadowsocksError.decryptionFailed }
                let payload = try ShadowsocksAEADCrypto.open(
                    cipher: cipher, key: subkey, nonce: nonce.next(), ciphertext: encryptedPayload
                )
                output.append(payload)

                state = .readingLength
                continue
            }
            break
        }

        // Compact buffer only when dead space exceeds threshold
        if bufferOffset > Self.compactThreshold {
            buffer.removeSubrange(0..<bufferOffset)
            bufferOffset = 0
        } else if bufferOffset > 0 && bufferOffset == buffer.count {
            buffer.removeAll(keepingCapacity: true)
            bufferOffset = 0
        }

        return output
    }
}

// MARK: - UDP Crypto

/// Per-packet encryption/decryption for Shadowsocks UDP.
enum ShadowsocksUDPCrypto {

    /// Encrypts a UDP packet: random salt + single AEAD seal (no chunking).
    static func encrypt(cipher: ShadowsocksCipher, masterKey: Data, payload: Data) throws -> Data {
        guard cipher != .none else { return payload }

        // Generate random salt
        var saltBytes = [UInt8](repeating: 0, count: cipher.saltSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, saltBytes.count, &saltBytes)
        let salt = Data(saltBytes)

        let subkey = ShadowsocksKeyDerivation.deriveSubkey(
            masterKey: masterKey, salt: salt, keySize: cipher.keySize
        )

        // Single AEAD seal with all-zero nonce
        let nonce = Data(repeating: 0, count: cipher.nonceSize)
        let encrypted = try ShadowsocksAEADCrypto.seal(
            cipher: cipher, key: subkey, nonce: nonce, plaintext: payload
        )

        var result = Data(capacity: salt.count + encrypted.count)
        result.append(salt)
        result.append(encrypted)
        return result
    }

    /// Decrypts a UDP packet: extract salt, derive subkey, AEAD open.
    static func decrypt(cipher: ShadowsocksCipher, masterKey: Data, data: Data) throws -> Data {
        guard cipher != .none else { return data }

        guard data.count > cipher.saltSize + cipher.tagSize else {
            throw ShadowsocksError.decryptionFailed
        }

        let salt = data.prefix(cipher.saltSize)
        let ciphertext = data.suffix(from: data.startIndex + cipher.saltSize)

        let subkey = ShadowsocksKeyDerivation.deriveSubkey(
            masterKey: masterKey, salt: salt, keySize: cipher.keySize
        )

        let nonce = Data(repeating: 0, count: cipher.nonceSize)
        return try ShadowsocksAEADCrypto.open(
            cipher: cipher, key: subkey, nonce: nonce, ciphertext: ciphertext
        )
    }
}

// MARK: - Errors

enum ShadowsocksError: Error, LocalizedError {
    case invalidMethod(String)
    case decryptionFailed
    case invalidAddress
    case badTimestamp
    case badRequestSalt
    case badHeaderType
    case invalidPSK

    var errorDescription: String? {
        switch self {
        case .invalidMethod(let method):
            return "Unsupported Shadowsocks method: \(method)"
        case .decryptionFailed:
            return "Shadowsocks AEAD decryption failed"
        case .invalidAddress:
            return "Invalid Shadowsocks address header"
        case .badTimestamp:
            return "Shadowsocks 2022 bad timestamp"
        case .badRequestSalt:
            return "Shadowsocks 2022 bad request salt"
        case .badHeaderType:
            return "Shadowsocks 2022 bad header type"
        case .invalidPSK:
            return "Invalid Shadowsocks 2022 PSK"
        }
    }
}
