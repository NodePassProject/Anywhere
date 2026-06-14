//
//  VLESSEncryption.swift
//  Anywhere
//
//  Created by NodePassProject on 5/10/26.
//

import Foundation

/// Parsed VLESS `encryption` (client) field, the `mlkem768x25519plus` scheme:
/// `mlkem768x25519plus.<xor>.<rtt>[.<padSeg>...].<base64Key>[.<base64Key>...]`.
struct VLESSEncryptionConfig: Equatable, Hashable {

    enum XORMode: UInt8 {
        case native = 0
        case xorpub = 1
        case random = 2
    }

    enum RTTMode {
        case oneRTT
        case zeroRTT
    }

    let xorMode: XORMode
    let rttMode: RTTMode
    /// Raw padding spec preserved verbatim for re-serialization; empty means use the default schedule.
    let padding: String
    /// Public keys in NFS-relay order: 32 bytes = X25519, 1184 = ML-KEM-768 encapsulation key.
    let publicKeys: [Data]

    /// `Account.Seconds` wire value: 0 for 1-RTT, 1 for 0-RTT; the server decides the actual ticket lifetime.
    var seconds: UInt32 {
        rttMode == .zeroRTT ? 1 : 0
    }

    enum ParseError: Error, LocalizedError, Equatable {
        case wrongScheme
        case missingFields
        case unknownXORMode(String)
        case unknownRTTMode(String)
        case invalidPublicKey(String)
        case noPublicKeys

        var errorDescription: String? {
            switch self {
            case .wrongScheme:
                return "VLESS encryption: unsupported scheme (expected \"mlkem768x25519plus\")"
            case .missingFields:
                return "VLESS encryption: too few fields"
            case .unknownXORMode(let s):
                return "VLESS encryption: unknown XOR mode \"\(s)\""
            case .unknownRTTMode(let s):
                return "VLESS encryption: unknown RTT mode \"\(s)\""
            case .invalidPublicKey(let s):
                return "VLESS encryption: invalid public key \"\(s)\""
            case .noPublicKeys:
                return "VLESS encryption: no public keys"
            }
        }
    }

    /// Returns `nil` for the `"none"`/empty sentinels; throws for any other malformed
    /// value rather than silently downgrading to plaintext.
    static func parse(_ string: String) throws -> VLESSEncryptionConfig? {
        if string.isEmpty || string == "none" {
            return nil
        }

        let segments = string.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count >= 4 else {
            throw ParseError.missingFields
        }
        guard segments[0] == "mlkem768x25519plus" else {
            throw ParseError.wrongScheme
        }

        let xorMode: XORMode
        switch segments[1] {
        case "native": xorMode = .native
        case "xorpub": xorMode = .xorpub
        case "random": xorMode = .random
        default:
            throw ParseError.unknownXORMode(String(segments[1]))
        }

        let rttMode: RTTMode
        switch segments[2] {
        case "1rtt": rttMode = .oneRTT
        case "0rtt": rttMode = .zeroRTT
        default:
            throw ParseError.unknownRTTMode(String(segments[2]))
        }

        // Segments shorter than 20 chars are padding specs, the rest are base64url
        // keys — the `len(r) < 20` heuristic.
        var paddingSegments: [String] = []
        var publicKeys: [Data] = []
        for raw in segments[3...] {
            let s = String(raw)
            if s.count < 20 {
                paddingSegments.append(s)
                continue
            }
            guard let key = Data(base64URLEncoded: s),
                  key.count == 32 || key.count == 1184 else {
                throw ParseError.invalidPublicKey(s)
            }
            publicKeys.append(key)
        }

        guard !publicKeys.isEmpty else {
            throw ParseError.noPublicKeys
        }

        return VLESSEncryptionConfig(
            xorMode: xorMode,
            rttMode: rttMode,
            padding: paddingSegments.joined(separator: "."),
            publicKeys: publicKeys
        )
    }

    /// Re-encodes as the canonical `mlkem768x25519plus...` string; round-trips with `parse`.
    func encoded() -> String {
        var parts: [String] = ["mlkem768x25519plus"]
        switch xorMode {
        case .native: parts.append("native")
        case .xorpub: parts.append("xorpub")
        case .random: parts.append("random")
        }
        switch rttMode {
        case .oneRTT: parts.append("1rtt")
        case .zeroRTT: parts.append("0rtt")
        }
        if !padding.isEmpty {
            parts.append(padding)
        }
        for key in publicKeys {
            parts.append(key.base64URLEncodedString())
        }
        return parts.joined(separator: ".")
    }
}
