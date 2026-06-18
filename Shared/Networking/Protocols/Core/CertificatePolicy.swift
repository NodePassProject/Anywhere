//
//  CertificatePolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import CryptoKit
import Security

nonisolated enum CertificatePolicy {
    private static let lock = UnfairLock()
    private static var _allowInsecure = AWCore.getAllowInsecure()
    private static var _trustedFingerprints = AWCore.getTrustedCertificateFingerprints()

    private static var observerRegistered = false

    /// Registers the Darwin notification observer; idempotent.
    static func startObserving() {
        lock.lock()
        defer { lock.unlock() }
        guard !observerRegistered else { return }
        observerRegistered = true

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            nil,
            { _, _, _, _, _ in
                CertificatePolicy.reload()
            },
            AWCore.Notification.certificatePolicyChanged,
            nil,
            .deliverImmediately
        )
    }

    /// Re-reads policy values from UserDefaults.
    static func reload() {
        lock.lock()
        defer { lock.unlock() }
        _allowInsecure = AWCore.getAllowInsecure()
        _trustedFingerprints = AWCore.getTrustedCertificateFingerprints()
    }

    /// Whether the user has opted into accepting all certificates.
    static var allowInsecure: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _allowInsecure
    }

    /// SHA-256 fingerprints the user has explicitly trusted.
    private static var trustedFingerprints: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _trustedFingerprints
    }

    // MARK: - Verification
    
    enum Verification {
        case trusted
        case rejected(reason: String)
    }

    /// Evaluates a server certificate `chain` (leaf first) presented for `serverName`
    /// against the active policy.
    ///
    /// Order of precedence:
    /// 1. `allowInsecure` — accept everything.
    /// 2. A user-pinned leaf SHA-256 match — **verification is complete**: an explicit pin
    ///    is the user's full trust decision, so no chain-of-trust, hostname/SAN, or
    ///    validity-period checks are performed.
    /// 3. Standard system trust evaluation under the SSL policy for `serverName`
    ///    (enforces chain of trust, hostname/SAN match, and validity period).
    static func verify(chain: [SecCertificate], serverName: String) -> Verification {
        if allowInsecure {
            return .trusted
        }

        guard let leaf = chain.first else {
            return .rejected(reason: "No server certificates received")
        }

        // A matching user-pinned fingerprint short-circuits every other check.
        if isPinned(leaf) {
            return .trusted
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, serverName as CFString)
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess,
              let trust else {
            return .rejected(reason: "Failed to create trust object")
        }

        var cfError: CFError?
        if SecTrustEvaluateWithError(trust, &cfError) {
            return .trusted
        }

        let message = (cfError as Error?)?.localizedDescription ?? "Certificate evaluation failed"
        return .rejected(reason: message)
    }

    /// Whether `leaf`'s SHA-256 fingerprint is one the user has explicitly pinned.
    private static func isPinned(_ leaf: SecCertificate) -> Bool {
        let trusted = trustedFingerprints
        guard !trusted.isEmpty else { return false }
        let certData = SecCertificateCopyData(leaf) as Data
        let sha256 = SHA256.hash(data: certData).map { String(format: "%02x", $0) }.joined()
        return trusted.contains(sha256)
    }
}
