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
    
    private static var trustedFingerprints: [String] {
        state.withLock { $0.trustedFingerprints }
    }

    // MARK: - Verification
    
    enum Verification {
        case trusted
        case rejected(reason: String)
    }
    
    static func verify(chain: [SecCertificate], serverName: String) async -> Verification {
        switch prepare(chain: chain, serverName: serverName) {
        case .decided(let verification):
            return verification
        case .evaluate(let trust):
            let handoff = TrustHandoff(trust: trust)
            let resumed = OneShotLatch()
            return await withCheckedContinuation { continuation in
                evaluationQueue.async {
                    let status = SecTrustEvaluateAsyncWithError(handoff.trust, evaluationQueue) { _, trusted, error in
                        guard resumed.claim() else { return }
                        continuation.resume(returning: outcome(trusted: trusted, error: error))
                    }
                    if status != errSecSuccess, resumed.claim() {
                        continuation.resume(returning: .rejected(reason: "Certificate evaluation could not start (\(status))"))
                    }
                }
            }
        }
    }

    private static let evaluationQueue = DispatchQueue(
        label: "com.argsment.Anywhere.CertificatePolicy",
        qos: .userInitiated
    )
    
    private struct TrustHandoff: @unchecked Sendable {
        let trust: SecTrust
    }

    private enum Preparation {
        case decided(Verification)
        case evaluate(SecTrust)
    }

    private static func prepare(chain: [SecCertificate], serverName: String) -> Preparation {
        if allowInsecure {
            return .decided(.trusted)
        }

        guard let leaf = chain.first else {
            return .decided(.rejected(reason: "No server certificates received"))
        }

        if isPinned(leaf) {
            return .decided(.trusted)
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, serverName as CFString)
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess,
              let trust else {
            return .decided(.rejected(reason: "Failed to create trust object"))
        }
        return .evaluate(trust)
    }

    private static func outcome(trusted: Bool, error: CFError?) -> Verification {
        if trusted {
            return .trusted
        }
        let message = (error as Error?)?.localizedDescription ?? "Certificate evaluation failed"
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
