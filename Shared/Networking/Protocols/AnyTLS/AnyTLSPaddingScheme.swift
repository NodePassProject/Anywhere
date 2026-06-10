//
//  AnyTLSPaddingScheme.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import CommonCrypto
import Security

/// Parsed AnyTLS padding scheme: `key=value` lines where numeric keys map to
/// comma-separated `min-max` ranges or the literal `c` (checkpoint).
final class AnyTLSPaddingScheme {

    /// Sentinel for the `c` (checkpoint) marker: break if no payload remains, else continue.
    static let checkMark: Int = -1

    let rawBytes: Data

    /// MD5(rawBytes) hex (lowercase); sent in cmdSettings as `padding-md5=…`.
    let md5Hex: String

    /// Padding is applied to the first `stop` packets only (default: 8).
    let stop: UInt32

    /// `key → raw value string` (e.g. `"2" → "400-500,c,500-1000"`).
    private let scheme: [String: String]

    private init(rawBytes: Data, md5Hex: String, stop: UInt32, scheme: [String: String]) {
        self.rawBytes = rawBytes
        self.md5Hex = md5Hex
        self.stop = stop
        self.scheme = scheme
    }

    /// Verbatim copy of Go's `padding.DefaultPaddingScheme` so the server's `padding-md5` check passes.
    static let `default`: AnyTLSPaddingScheme = {
        let raw = Data("""
        stop=8
        0=30-30
        1=100-400
        2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
        3=9-9,500-1000
        4=500-1000
        5=500-1000
        6=500-1000
        7=500-1000
        """.utf8)
        return parse(raw) ?? AnyTLSPaddingScheme(
            rawBytes: raw,
            md5Hex: md5Hex(of: raw),
            stop: 0,
            scheme: [:]
        )
    }()

    /// Returns `nil` when `stop` is missing or non-numeric — matches Go's `NewPaddingFactory`.
    static func parse(_ raw: Data) -> AnyTLSPaddingScheme? {
        let map = AnyTLSProtocol.decodeStringMap(raw)
        guard let stopString = map["stop"], let stop = UInt32(stopString) else {
            return nil
        }
        var scheme = map
        scheme.removeValue(forKey: "stop")
        return AnyTLSPaddingScheme(
            rawBytes: raw,
            md5Hex: md5Hex(of: raw),
            stop: stop,
            scheme: scheme
        )
    }

    /// Schedule for `packet`: ranges resolved via CSPRNG, `c` becomes `checkMark`.
    func generateRecordPayloadSizes(packet: UInt32) -> [Int] {
        guard let value = scheme[String(packet)] else { return [] }
        var out: [Int] = []
        for raw in value.split(separator: ",") {
            let token = raw.trimmingCharacters(in: .whitespaces)
            if token == "c" {
                out.append(AnyTLSPaddingScheme.checkMark)
                continue
            }
            let parts = token.split(separator: "-")
            guard parts.count == 2,
                  var lo = Int(parts[0]),
                  var hi = Int(parts[1]) else { continue }
            if lo > hi { swap(&lo, &hi) }
            guard lo > 0, hi > 0 else { continue }
            if lo == hi {
                out.append(lo)
            } else {
                out.append(Self.randomInRange(lo: lo, hi: hi))
            }
        }
        return out
    }

    /// CSPRNG draw in `[lo, hi)` — matches `crypto/rand.Int(reader, big.NewInt(hi-lo))` then `+lo`.
    private static func randomInRange(lo: Int, hi: Int) -> Int {
        let span = UInt64(hi - lo)
        guard span > 0 else { return lo }
        var raw: UInt64 = 0
        let status = withUnsafeMutableBytes(of: &raw) { buf -> Int32 in
            SecRandomCopyBytes(kSecRandomDefault, buf.count, buf.baseAddress!)
        }
        if status != errSecSuccess {
            // Fallback keeps padding non-deterministic without aborting the connection.
            raw = UInt64(arc4random()) << 32 | UInt64(arc4random())
        }
        return lo + Int(raw % span)
    }

    /// MD5 is required for wire compatibility (`padding-md5` check), not security.
    private static func md5Hex(of data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes { ptr in
            if let base = ptr.baseAddress {
                _ = CC_MD5(base, CC_LONG(data.count), &digest)
            }
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
