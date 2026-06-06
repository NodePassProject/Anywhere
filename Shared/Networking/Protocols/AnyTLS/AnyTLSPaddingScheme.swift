//
//  AnyTLSPaddingScheme.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import CommonCrypto
import Security

/// Parsed AnyTLS padding scheme.
///
/// The on-the-wire scheme is a `key=value`-line text blob; the value for each
/// numeric key is a comma-separated list of `min-max` ranges or the literal
/// `c` ("checkpoint" — keep going only if more payload remains). Per outgoing
/// packet the session picks the entry for `pktCounter`, generates a concrete
/// list of byte-counts, and slices the outbound stream accordingly. After
/// `stop` packets the session stops applying padding.
final class AnyTLSPaddingScheme {

    /// Sentinel for the literal `c` marker — `Session.writeConn` treats it as
    /// "if no more payload remains, break; otherwise continue to next size".
    static let checkMark: Int = -1

    /// The exact bytes the server hashes when it compares the client's
    /// `padding-md5` setting. Stored verbatim so a re-export round-trips.
    let rawBytes: Data

    /// MD5(rawBytes) hex (lowercase). Sent in cmdSettings as `padding-md5=…`.
    let md5Hex: String

    /// After `stop` packets, the writer sets `sendPadding = false` and stops
    /// invoking the schedule. From sing-anytls's default this is 8.
    let stop: UInt32

    /// `key → raw value string` (e.g. `"2" → "400-500,c,500-1000"`).
    private let scheme: [String: String]

    private init(rawBytes: Data, md5Hex: String, stop: UInt32, scheme: [String: String]) {
        self.rawBytes = rawBytes
        self.md5Hex = md5Hex
        self.stop = stop
        self.scheme = scheme
    }

    /// Verbatim copy of `padding.DefaultPaddingScheme` — the bytes the
    /// server expects so cmdSettings's `padding-md5` matches without
    /// triggering a cmdUpdatePaddingScheme.
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

    /// Parses a raw scheme blob. Returns `nil` when `stop` is missing or
    /// non-numeric — matches Go's `NewPaddingFactory`.
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

    /// Returns the size schedule for `packet`. Entries of `checkMark` (-1)
    /// represent the `c` marker; positive ints are concrete byte counts.
    /// `min-max` ranges are resolved with a CSPRNG draw exactly as
    /// `crypto/rand.Int` does in the Go reference, so each call returns a
    /// fresh schedule.
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
            // Crypto-grade entropy failed; falling back keeps padding
            // non-deterministic without aborting the connection.
            raw = UInt64(arc4random()) << 32 | UInt64(arc4random())
        }
        return lo + Int(raw % span)
    }

    /// MD5 is required for wire compatibility — anytls servers compare the
    /// hex digest against `padding-md5` from cmdSettings. Not used for any
    /// security-relevant purpose.
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
