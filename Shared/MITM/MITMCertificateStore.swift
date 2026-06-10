//
//  MITMCertificateStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Security

enum MITMCertificateStoreError: Error {
    case keyGenerationFailed(String)
    case keychainWriteFailed(OSStatus)
    case keychainReadFailed(OSStatus)
    case certificateBuildFailed(Error)
    case missingCAComponents
}

/// Thread-safe helper around the App Group keychain entries used for MITM.
final class MITMCertificateStore {

    // MARK: - Configuration

    /// Keychain access group shared by the app target and the Network Extension.
    private let accessGroup: String

    /// Scopes all MITM keychain items so delete/regenerate touches nothing else.
    private static let service = "com.argsment.Anywhere.MITM"

    private static let privateKeyTag = "\(service).caPrivateKey".data(using: .utf8)!
    private static let certAccount = "\(service).caCertificate"
    private static let serialAccount = "\(service).caSerial"

    private static let caSubjectCN = "Anywhere Root Certificate"
    private static let caOrganization = "Anywhere"

    private let lock = NSLock()

    // MARK: - Init

    init(accessGroup: String = "\(AWCore.Identifier.appGroupSuite)") {
        self.accessGroup = accessGroup
    }

    // MARK: - CA Lifecycle

    /// Returns the persisted CA cert + private key, generating them on first use.
    func loadOrCreateCA() throws -> (privateKey: SecKey, certificateDER: Data) {
        lock.lock()
        defer { lock.unlock() }

        if let existing = try? loadCAUnlocked() {
            return existing
        }
        do {
            return try generateCAUnlocked()
        } catch {
            // The App Group keychain is shared with the extension (NSLock is
            // intra-process): either the other process won the race (re-read), or
            // an orphaned key from a failed cert write hit errSecDuplicateItem (drop it).
            if let existing = try? loadCAUnlocked() {
                return existing
            }
            // Non-duplicate failures leave no key, so surface the real error.
            guard (try? readPrivateKeyUnlocked()) != nil else { throw error }
            deletePrivateKey()
            return try generateCAUnlocked()
        }
    }

    /// Returns the persisted CA cert + private key, or `nil` if not yet generated.
    func loadCA() -> (privateKey: SecKey, certificateDER: Data)? {
        lock.lock()
        defer { lock.unlock() }
        return try? loadCAUnlocked()
    }

    /// Wipes the persisted CA and generates a fresh one, invalidating any installed root profile.
    @discardableResult
    func regenerate() throws -> (privateKey: SecKey, certificateDER: Data) {
        lock.lock()
        defer { lock.unlock() }
        deleteUnlocked()
        return try generateCAUnlocked()
    }

    /// Wipes the persisted CA without regenerating.
    func delete() {
        lock.lock()
        defer { lock.unlock() }
        deleteUnlocked()
    }

    // MARK: - Trust State

    /// Whether the persisted CA is trusted by the system SSL policy.
    func isCATrusted() -> Bool {
        guard let (caKey, caCertDER) = loadCA() else {
            return false
        }

        let testHost = "anywhere-mitm-trust-check.invalid"
        let leafKey = P256.Signing.PrivateKey()
        let now = Date()

        let leafDER: Data
        do {
            leafDER = try X509Builder.buildLeafCertificate(
                leafPublicKey: leafKey.publicKey,
                caPrivateKey: caKey,
                caCertificateDER: caCertDER,
                hostname: testHost,
                serial: randomSerial(),
                notBefore: now.addingTimeInterval(-60),
                notAfter: now.addingTimeInterval(60 * 60)
            )
        } catch {
            return false
        }

        guard let leafCert = SecCertificateCreateWithData(nil, leafDER as CFData),
              let caCert = SecCertificateCreateWithData(nil, caCertDER as CFData) else {
            return false
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, testHost as CFString)
        let chain: [SecCertificate] = [leafCert, caCert]
        let status = SecTrustCreateWithCertificates(chain as CFArray, policy, &trust)
        guard status == errSecSuccess, let trust else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }

    // MARK: - Export

    func exportCertificateDER() -> Data? {
        loadCA()?.certificateDER
    }

    /// Builds a `.mobileconfig` profile wrapping the CA cert; rebuilt every call, never persisted.
    func exportMobileConfig() -> Data? {
        guard let certDER = exportCertificateDER() else { return nil }

        let identifier = "com.argsment.Anywhere.mitm.root"
        let payloadIdentifier = "\(identifier).payload"
        let payloadUUID = UUID().uuidString
        let outerUUID = UUID().uuidString

        let plist: [String: Any] = [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": identifier,
            "PayloadUUID": outerUUID,
            "PayloadDisplayName": "Anywhere Root Certificate",
            "PayloadDescription": "Installs Anywhere Root Certificate.",
            "PayloadOrganization": "Anywhere",
            "PayloadContent": [
                [
                    "PayloadType": "com.apple.security.root",
                    "PayloadVersion": 1,
                    "PayloadIdentifier": payloadIdentifier,
                    "PayloadUUID": payloadUUID,
                    "PayloadDisplayName": "Anywhere Root Certificate",
                    "PayloadDescription": "The CA is used in Anywhere app.",
                    "PayloadCertificateFileName": "AnywhereRootCertificate.cer",
                    "PayloadContent": certDER,
                ]
            ]
        ]

        return try? PropertyListSerialization.data(
            fromPropertyList: plist,
            format: .xml,
            options: 0
        )
    }

    // MARK: - Leaf Signing Inputs

    /// Returns a fresh 16-byte random serial. Randomness, not a shared counter:
    /// two App Group processes could mint duplicates (RFC 5280 §4.1.2.2).
    func nextSerial() -> Data {
        return randomSerial()
    }

    // MARK: - Private — CA load / generate / delete

    private func loadCAUnlocked() throws -> (privateKey: SecKey, certificateDER: Data) {
        let cert = try readCertificateUnlocked()
        let key = try readPrivateKeyUnlocked()
        return (key, cert)
    }

    private func generateCAUnlocked() throws -> (privateKey: SecKey, certificateDER: Data) {
        let privateKey = try generatePrivateKey()
        let now = Date()
        let notAfter = Calendar(identifier: .gregorian).date(byAdding: .year, value: 10, to: now) ?? now.addingTimeInterval(60 * 60 * 24 * 365 * 10)
        let serial = randomSerial()

        do {
            let certDER = try X509Builder.buildCACertificate(
                privateKey: privateKey,
                subjectCN: Self.caSubjectCN,
                organization: Self.caOrganization,
                serial: serial,
                notBefore: now.addingTimeInterval(-60 * 60),
                notAfter: notAfter
            )
            try writeCertificateUnlocked(certDER)
            return (privateKey, certDER)
        } catch {
            // The key was already persisted (kSecAttrIsPermanent); delete it or
            // the next call hits errSecDuplicateItem on the same tag.
            deletePrivateKey()
            throw MITMCertificateStoreError.certificateBuildFailed(error)
        }
    }

    private func deleteUnlocked() {
        deletePrivateKey()
        deleteCertificate()
        deleteSerial()
    }

    // MARK: - Private — Keychain (Private Key)

    private func generatePrivateKey() throws -> SecKey {
        if let key = tryGenerateSecureEnclaveKey() {
            return key
        }
        return try generateSoftwareKey()
    }

    private func tryGenerateSecureEnclaveKey() -> SecKey? {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &error
        ) else {
            return nil
        }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: access,
                kSecAttrApplicationTag as String: Self.privateKeyTag,
                kSecAttrAccessGroup as String: accessGroup,
            ]
        ]
        var err: Unmanaged<CFError>?
        return SecKeyCreateRandomKey(attrs as CFDictionary, &err)
    }

    private func generateSoftwareKey() throws -> SecKey {
        // Fallback when the Secure Enclave is unavailable (simulator, older devices).
        // Non-extractable, non-synchronizable, ThisDeviceOnly: the CA key signs every
        // MITM leaf, so it must never leave the device.
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrIsExtractable as String: false,
                kSecAttrSynchronizable as String: false,
                kSecAttrApplicationTag as String: Self.privateKeyTag,
                kSecAttrAccessGroup as String: accessGroup,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            let message = (err?.takeRetainedValue()).flatMap { CFErrorCopyDescription($0) as String? } ?? "unknown"
            throw MITMCertificateStoreError.keyGenerationFailed(message)
        }
        return key
    }

    private func readPrivateKeyUnlocked() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.privateKeyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw MITMCertificateStoreError.keychainReadFailed(status)
        }
        return item as! SecKey
    }

    private func deletePrivateKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.privateKeyTag,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Private — Keychain (Certificate)

    private func writeCertificateUnlocked(_ data: Data) throws {
        deleteCertificate()
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.certAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw MITMCertificateStoreError.keychainWriteFailed(status)
        }
    }

    private func readCertificateUnlocked() throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.certAccount,
            kSecReturnData as String: true,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            throw MITMCertificateStoreError.keychainReadFailed(status)
        }
        return data
    }

    private func deleteCertificate() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.certAccount,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Private — Keychain (Legacy serial item)

    /// Purges the legacy monotonic-counter item left behind by old installs.
    private func deleteSerial() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.serialAccount,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Helpers

    private func randomSerial() -> Data {
        for _ in 0..<3 {
            var bytes = Data(count: 16)
            let status = bytes.withUnsafeMutableBytes { ptr in
                SecRandomCopyBytes(kSecRandomDefault, 16, ptr.baseAddress!)
            }
            if status == errSecSuccess {
                return bytes
            }
        }
        // SecRandomCopyBytes failed repeatedly (extremely rare); a zero buffer would
        // collapse every serial to 1. A v4 UUID gives 122 random bits, never all-zero.
        return withUnsafeBytes(of: UUID().uuid) { Data($0) }
    }
}
