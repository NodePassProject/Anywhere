//
//  CertificateStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/10/26.
//

import Foundation
import Combine
import SwiftUI

/// Manages user-trusted certificate SHA-256 fingerprints.
///
/// Fingerprints are stored in App Group UserDefaults so both the main app
/// and the Network Extension can access them. TLSClient checks these
/// when system trust evaluation fails.
@MainActor
final class CertificateStore: ObservableObject {
    static let shared = CertificateStore()

    @Published private(set) var fingerprints: [String] = []

    private init() {
        fingerprints = AWCore.getTrustedCertificateFingerprints()
    }

    /// Adds a SHA-256 fingerprint (hex string, case-insensitive).
    /// Returns `false` if the fingerprint is invalid or already exists.
    @discardableResult
    func add(_ fingerprint: String) -> Bool {
        let normalized = Self.normalize(fingerprint)
        guard normalized.count == 64, normalized.allSatisfy(\.isHexDigit) else { return false }
        guard !fingerprints.contains(normalized) else { return false }
        fingerprints.append(normalized)
        save()
        return true
    }

    /// Removes a fingerprint by value.
    func remove(_ fingerprint: String) {
        let normalized = Self.normalize(fingerprint)
        fingerprints.removeAll { $0 == normalized }
        save()
    }

    /// Removes fingerprints at the given offsets.
    func remove(atOffsets offsets: IndexSet) {
        fingerprints.remove(atOffsets: offsets)
        save()
    }

    // MARK: - Private

    private func save() {
        AWCore.setTrustedCertificateFingerprints(fingerprints)
        AWCore.notifyCertificatePolicyChanged()
    }

    private static func normalize(_ fingerprint: String) -> String {
        fingerprint
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: " ", with: "")
            .lowercased()
    }
}
