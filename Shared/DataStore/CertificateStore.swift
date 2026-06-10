//
//  CertificateStore.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import Foundation
import Observation
import SwiftUI

/// User-trusted certificate SHA-256 fingerprints, stored in App Group
/// UserDefaults so both the main app and the Network Extension can read them.
@MainActor
@Observable
final class CertificateStore {
    static let shared = CertificateStore()

    private(set) var fingerprints: [String] = []

    private init() {
        fingerprints = AWCore.getTrustedCertificateFingerprints()
    }

    /// Adds a SHA-256 fingerprint (hex, case-insensitive); false if invalid or already present.
    @discardableResult
    func add(_ fingerprint: String) -> Bool {
        let normalized = Self.normalize(fingerprint)
        guard normalized.count == 64, normalized.allSatisfy(\.isHexDigit) else { return false }
        guard !fingerprints.contains(normalized) else { return false }
        fingerprints.append(normalized)
        save()
        return true
    }

    func remove(_ fingerprint: String) {
        let normalized = Self.normalize(fingerprint)
        fingerprints.removeAll { $0 == normalized }
        save()
    }

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
