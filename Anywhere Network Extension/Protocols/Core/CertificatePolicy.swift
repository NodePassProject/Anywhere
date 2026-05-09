//
//  CertificatePolicy.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

/// Both ``TLSClient`` and ``QUICTLSHandler`` call into this instead of
/// constructing a new `UserDefaults` instance on every validation.
/// Values are refreshed when the `certificatePolicyChanged` Darwin notification fires.
enum CertificatePolicy {
    private static let lock = UnfairLock()
    private static var _allowInsecure = AWCore.getAllowInsecure()
    private static var _trustedFingerprints = AWCore.getTrustedCertificateFingerprints()

    /// One-time observer registration (called via `startObserving()`).
    private static var observerRegistered = false

    /// Registers a Darwin notification observer for `certificatePolicyChanged`.
    /// Safe to call multiple times — only the first call has effect.
    static func startObserving() {
        lock.lock()
        defer { lock.unlock() }
        guard !observerRegistered else { return }
        observerRegistered = true

        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            nil, // no instance context needed
            { _, _, _, _, _ in
                CertificatePolicy.reload()
            },
            AWCore.Notification.certificatePolicyChanged,
            nil,
            .deliverImmediately
        )
    }

    /// Re-reads both values from UserDefaults.
    /// Called automatically on `certificatePolicyChanged`; can also be called manually.
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
