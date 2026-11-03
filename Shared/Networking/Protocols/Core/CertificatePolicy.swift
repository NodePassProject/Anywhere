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
        verifiedChains.withLock { $0.removeAll() }
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
        case .evaluate(let trust, let key):
            let handoff = TrustHandoff(trust: trust)
            let resumed = OneShotLatch()
            let verification: Verification = await withCheckedContinuation { continuation in
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
            if case .trusted = verification {
                rememberTrusted(key, chain: chain)
            }
            return verification
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
        case evaluate(SecTrust, VerifiedChainKey)
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

        let key = VerifiedChainKey(chain: chain, serverName: serverName)
        if isRecentlyTrusted(key) {
            return .decided(.trusted)
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, serverName as CFString)
        guard SecTrustCreateWithCertificates(chain as CFArray, policy, &trust) == errSecSuccess,
              let trust else {
            return .decided(.rejected(reason: "Failed to create trust object"))
        }
        return .evaluate(trust, key)
    }

    // MARK: - Verified-chain cache

    private struct VerifiedChainKey: Hashable, Sendable {
        let serverName: String
        let digest: SHA256.Digest

        init(chain: [SecCertificate], serverName: String) {
            var hasher = SHA256()
            for certificate in chain {
                let der = SecCertificateCopyData(certificate) as Data
                withUnsafeBytes(of: UInt32(der.count).bigEndian) { hasher.update(bufferPointer: $0) }
                hasher.update(data: der)
            }
            self.serverName = serverName.lowercased()
            self.digest = hasher.finalize()
        }
    }

    private struct VerifiedChain: Sendable {
        let cachedAt: TimeInterval
        let expiresAt: TimeInterval
        let notAfter: Date
    }

    private static let verifiedChainTTL: TimeInterval = 10 * 60
    private static let maxVerifiedChains = 256
    private static let verifiedChains = Mutex<[VerifiedChainKey: VerifiedChain]>([:])

    private static func isRecentlyTrusted(_ key: VerifiedChainKey) -> Bool {
        let now = MonotonicClock.now
        let wallNow = Date()
        return verifiedChains.withLock { chains in
            guard let entry = chains[key] else { return false }
            guard now < entry.expiresAt, wallNow < entry.notAfter else {
                chains.removeValue(forKey: key)
                return false
            }
            return true
        }
    }

    private static func rememberTrusted(_ key: VerifiedChainKey, chain: [SecCertificate]) {
        var notAfter = Date.distantFuture
        for certificate in chain {
            guard let date = SecCertificateCopyNotValidAfterDate(certificate) as Date? else { return }
            notAfter = min(notAfter, date)
        }
        let now = MonotonicClock.now
        let entry = VerifiedChain(cachedAt: now, expiresAt: now + verifiedChainTTL, notAfter: notAfter)
        verifiedChains.withLock { chains in
            chains[key] = entry
            guard chains.count > maxVerifiedChains else { return }
            chains = chains.filter { $0.value.expiresAt > now }
            while chains.count > maxVerifiedChains,
                  let oldest = chains.min(by: { $0.value.cachedAt < $1.value.cachedAt })?.key {
                chains.removeValue(forKey: oldest)
            }
        }
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
