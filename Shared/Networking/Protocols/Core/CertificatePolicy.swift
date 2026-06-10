//
//  CertificatePolicy.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation

/// Shared certificate-policy cache; values are refreshed when the
/// `certificatePolicyChanged` Darwin notification fires.
enum CertificatePolicy {
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
    static var trustedFingerprints: [String] {
        lock.lock()
        defer { lock.unlock() }
        return _trustedFingerprints
    }
}
