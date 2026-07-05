//
//  CertificatePolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import CryptoKit
import Security
import Synchronization

nonisolated enum CertificatePolicy {
    private struct State {
        var allowInsecure = AWCore.getAllowInsecure()
        var trustedFingerprints = AWCore.getTrustedCertificateFingerprints()
        var observerRegistered = false
    }

    private static let state = Mutex(State())

    /// Idempotent.
    static func startObserving() {
        state.withLock { state in
            guard !state.observerRegistered else { return }
            state.observerRegistered = true

            CFNotificationCenterAddObserver(
                CFNotificationCenterGetDarwinNotifyCenter(),
                nil,
                { _, _, _, _, _ in
                    CertificatePolicy.reload()
                },
                AWNotificationCenter.Notification.certificatePolicyChanged,
                nil,
                .deliverImmediately
            )
        }
    }

    static func reload() {
        state.withLock { state in
            state.allowInsecure = AWCore.getAllowInsecure()
            state.trustedFingerprints = AWCore.getTrustedCertificateFingerprints()
        }
    }

    static var allowInsecure: Bool {
        state.withLock { $0.allowInsecure }
    }

    /// SHA-256 fingerprints.
    private static var trustedFingerprints: [String] {
        state.withLock { $0.trustedFingerprints }
    }

    // MARK: - Verification
    
    enum Verification {
        case trusted
        case rejected(reason: String)
    }

    /// `chain` is leaf-first. A user-pinned leaf SHA-256 match short-circuits all other
    /// checks: the pin is the user's full trust decision, so chain-of-trust, hostname/SAN,
    /// and validity-period are not verified. Otherwise standard system SSL trust evaluation.
    static func verify(chain: [SecCertificate], serverName: String) -> Verification {
        if allowInsecure {
            return .trusted
        }

        guard let leaf = chain.first else {
            return .rejected(reason: "No server certificates received")
        }

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

    private static func isPinned(_ leaf: SecCertificate) -> Bool {
        let trusted = trustedFingerprints
        guard !trusted.isEmpty else { return false }
        let certData = SecCertificateCopyData(leaf) as Data
        let sha256 = SHA256.hash(data: certData).map { String(format: "%02x", $0) }.joined()
        return trusted.contains(sha256)
    }
}
