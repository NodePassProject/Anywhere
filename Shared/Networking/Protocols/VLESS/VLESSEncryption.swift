//
//  VLESSEncryption.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/10/26.
//

import Foundation

/// Parsed form of a VLESS `encryption` (client) field as defined by Xray-core's
/// `mlkem768x25519plus` scheme.
///
/// Wire format:
/// ```
/// mlkem768x25519plus.<xor>.<rtt>[.<padSeg>...].<base64Key>[.<base64Key>...]
/// ```
/// where:
///  - `<xor>` ∈ `{native, xorpub, random}`
///  - `<rtt>` ∈ `{1rtt, 0rtt}`
///  - `<padSeg>` is a short (length < 20) hyphen-triple like `100-111-1111`,
///    alternating between length specs and gap specs
///  - `<base64Key>` is base64url-encoded; 32 bytes = X25519 public key,
///    1184 bytes = ML-KEM-768 encapsulation key. Multiple keys form an
///    NFS relay chain in the order written.
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
    /// Raw padding spec (e.g. `"100-111-1111.50-0-3333"`) preserved verbatim
    /// for re-serialization. Empty when none was specified, in which case
    /// the runtime falls back to its built-in default schedule.
    let padding: String
    /// One or more public keys in NFS-relay order. Each is either 32 bytes
    /// (X25519) or 1184 bytes (ML-KEM-768 encapsulation key).
    let publicKeys: [Data]

    /// `Account.Seconds` value (0 for 1-RTT, 1 for 0-RTT) used by the
    /// outbound handshake. The actual ticket lifetime is decided by the
    /// server; the client only signals "I want 0-RTT".
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

    /// Parse the `encryption` field of a VLESS account.
    ///
    /// Returns `nil` for the `"none"` and empty-string sentinels (no
    /// encryption layer). Throws ``ParseError`` for any other malformed
    /// value so the caller can surface a precise error to the user instead
    /// of silently downgrading to plaintext.
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

        // Segments after rtt are padding (length < 20) followed by base64url
        // public keys (length >= 20). Matches Xray-core's `len(r) < 20`
        // heuristic in infra/conf/vless.go.
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

    /// Re-encode this config as the canonical `mlkem768x25519plus...` string.
    /// Round-trips with ``parse(_:)`` for any value produced by ``parse(_:)``.
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
