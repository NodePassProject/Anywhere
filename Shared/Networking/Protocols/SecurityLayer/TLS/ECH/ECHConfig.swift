//
//  ECHConfig.swift
//  Anywhere
//
//  Created by NodePassProject on 6/14/26.
//

import Foundation

// MARK: - HPKE Identifiers (RFC 9180)

enum ECHKemID {
    static let dhkemX25519HKDFSHA256: UInt16 = 0x0020
}

enum ECHKdfID {
    static let hkdfSHA256: UInt16 = 0x0001
    static let hkdfSHA384: UInt16 = 0x0002
    static let hkdfSHA512: UInt16 = 0x0003
}

enum ECHAeadID {
    static let aesGCM128: UInt16 = 0x0001
    static let aesGCM256: UInt16 = 0x0002
    static let chaCha20Poly1305: UInt16 = 0x0003
}

/// The ECH extension codepoint, also the ECHConfig version we understand.
let echExtensionCodepoint: UInt16 = 0xFE0D

let echSupportedKEMs: Set<UInt16> = [ECHKemID.dhkemX25519HKDFSHA256]

let echSupportedKDFs: Set<UInt16> = [
    ECHKdfID.hkdfSHA256, ECHKdfID.hkdfSHA384, ECHKdfID.hkdfSHA512,
]

let echSupportedAEADs: Set<UInt16> = [
    ECHAeadID.aesGCM128, ECHAeadID.aesGCM256, ECHAeadID.chaCha20Poly1305,
]

// MARK: - Model

struct ECHCipherSuite: Equatable {
    let kdfID: UInt16
    let aeadID: UInt16
}

struct ECHConfigExtension {
    let type: UInt16
    let data: Data
}

struct ECHConfig {
    /// Full config bytes including the 2-byte version and 2-byte length header.
    /// Feeds the HPKE `info` string ("tls ech\0" || raw), so must be preserved
    /// exactly as received.
    let raw: Data

    let version: UInt16
    let configID: UInt8
    let kemID: UInt16
    let publicKey: Data
    let cipherSuites: [ECHCipherSuite]
    let maxNameLength: UInt8
    let publicName: String
    let publicNameRaw: Data
    let extensions: [ECHConfigExtension]
}

// MARK: - Errors

enum ECHConfigError: Error, LocalizedError {
    case malformedConfigList
    case malformedConfig
    case noCompatibleConfig
    case noCompatibleCipherSuite

    var errorDescription: String? {
        switch self {
        case .malformedConfigList:     return "Malformed ECHConfigList"
        case .malformedConfig:         return "Malformed ECHConfig"
        case .noCompatibleConfig:      return "ECHConfigList contains no usable config"
        case .noCompatibleCipherSuite: return "ECHConfig offers no supported HPKE cipher suite"
        }
    }
}

// MARK: - Parsing

enum ECHConfigParser {

    /// 2-byte total length followed by `ECHConfig` records (version, length,
    /// body). Configs with an unrecognized version are skipped, not rejected,
    /// for forward compatibility.
    static func parseConfigList(_ data: Data) throws -> [ECHConfig] {
        let bytes = [UInt8](data)
        guard bytes.count >= 2 else { throw ECHConfigError.malformedConfigList }

        let listLength = Int(bytes[0]) << 8 | Int(bytes[1])
        guard listLength == bytes.count - 2 else { throw ECHConfigError.malformedConfigList }

        var configs: [ECHConfig] = []
        var position = 2
        while position < bytes.count {
            // Record header: version(2) + length(2).
            guard position + 4 <= bytes.count else { throw ECHConfigError.malformedConfig }
            let version = UInt16(bytes[position]) << 8 | UInt16(bytes[position + 1])
            let bodyLength = Int(bytes[position + 2]) << 8 | Int(bytes[position + 3])
            let recordEnd = position + 4 + bodyLength
            guard recordEnd <= bytes.count else { throw ECHConfigError.malformedConfig }

            let raw = Data(bytes[position..<recordEnd])
            if version == echExtensionCodepoint {
                let body = Data(bytes[(position + 4)..<recordEnd])
                if let config = try parseConfigBody(body, version: version, raw: raw) {
                    configs.append(config)
                }
            }
            position = recordEnd
        }
        return configs
    }

    private static func parseConfigBody(_ body: Data, version: UInt16, raw: Data) throws -> ECHConfig? {
        var reader = ECHByteReader(body)

        guard let configID = reader.readUInt8(),
              let kemID = reader.readUInt16(),
              let publicKey = reader.readUInt16LengthPrefixed(),
              let cipherSuiteBytes = reader.readUInt16LengthPrefixed()
        else { throw ECHConfigError.malformedConfig }

        var csReader = ECHByteReader(cipherSuiteBytes)
        var cipherSuites: [ECHCipherSuite] = []
        while !csReader.isEmpty {
            guard let kdfID = csReader.readUInt16(), let aeadID = csReader.readUInt16() else {
                throw ECHConfigError.malformedConfig
            }
            cipherSuites.append(ECHCipherSuite(kdfID: kdfID, aeadID: aeadID))
        }

        guard let maxNameLength = reader.readUInt8(),
              let publicNameRaw = reader.readUInt8LengthPrefixed(),
              let extensionBytes = reader.readUInt16LengthPrefixed()
        else { throw ECHConfigError.malformedConfig }

        var extReader = ECHByteReader(extensionBytes)
        var extensions: [ECHConfigExtension] = []
        while !extReader.isEmpty {
            guard let type = extReader.readUInt16(), let data = extReader.readUInt16LengthPrefixed() else {
                throw ECHConfigError.malformedConfig
            }
            extensions.append(ECHConfigExtension(type: type, data: data))
        }

        // Trailing bytes past the declared fields mean a malformed config.
        guard reader.isEmpty else { throw ECHConfigError.malformedConfig }

        return ECHConfig(
            raw: raw,
            version: version,
            configID: configID,
            kemID: kemID,
            publicKey: publicKey,
            cipherSuites: cipherSuites,
            maxNameLength: maxNameLength,
            publicName: String(decoding: publicNameRaw, as: UTF8.self),
            publicNameRaw: publicNameRaw,
            extensions: extensions
        )
    }
}

// MARK: - Selection

extension ECHConfig {

    /// First usable config: supported KEM, at least one supported cipher suite,
    /// DNS-like public_name, and no mandatory extension (high bit of type set).
    static func pick(from list: [ECHConfig]) -> ECHConfig? {
        for config in list {
            guard echSupportedKEMs.contains(config.kemID) else { continue }
            guard config.cipherSuites.contains(where: {
                echSupportedAEADs.contains($0.aeadID) && echSupportedKDFs.contains($0.kdfID)
            }) else { continue }
            guard ECHConfig.isValidDNSName(config.publicName) else { continue }
            let hasMandatoryUnsupportedExt = config.extensions.contains { $0.type & 0x8000 != 0 }
            guard !hasMandatoryUnsupportedExt else { continue }
            return config
        }
        return nil
    }

    func pickCipherSuite() -> ECHCipherSuite? {
        cipherSuites.first { echSupportedAEADs.contains($0.aeadID) && echSupportedKDFs.contains($0.kdfID) }
    }

    static func isValidDNSName(_ name: String) -> Bool {
        guard name.count <= 253 else { return false }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count > 1 else { return false }
        for label in labels {
            guard !label.isEmpty else { return false }
            let characters = Array(label)
            for (i, c) in characters.enumerated() {
                if c == "-" && (i == 0 || i == characters.count - 1) { return false }
                let isDigit = c >= "0" && c <= "9"
                let isLower = c >= "a" && c <= "z"
                let isUpper = c >= "A" && c <= "Z"
                if !isDigit && !isLower && !isUpper && c != "-" { return false }
            }
        }
        return true
    }
}

// MARK: - Byte Reader

/// Self-contained so the ECH code carries no cross-target dependencies.
struct ECHByteReader {
    private let bytes: [UInt8]
    private var offset: Int = 0

    init(_ data: Data) { self.bytes = [UInt8](data) }
    init(_ bytes: [UInt8]) { self.bytes = bytes }

    var isEmpty: Bool { offset >= bytes.count }
    var remaining: Int { bytes.count - offset }

    mutating func readUInt8() -> UInt8? {
        guard offset + 1 <= bytes.count else { return nil }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func readUInt16() -> UInt16? {
        guard offset + 2 <= bytes.count else { return nil }
        defer { offset += 2 }
        return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    mutating func readBytes(_ count: Int) -> Data? {
        guard count >= 0, offset + count <= bytes.count else { return nil }
        defer { offset += count }
        return Data(bytes[offset..<(offset + count)])
    }

    mutating func readUInt8LengthPrefixed() -> Data? {
        guard let length = readUInt8() else { return nil }
        return readBytes(Int(length))
    }

    mutating func readUInt16LengthPrefixed() -> Data? {
        guard let length = readUInt16() else { return nil }
        return readBytes(Int(length))
    }

    @discardableResult
    mutating func skip(_ count: Int) -> Bool {
        guard count >= 0, offset + count <= bytes.count else { return false }
        offset += count
        return true
    }
}
