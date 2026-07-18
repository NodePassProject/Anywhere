//
//  MITMCertificateStore.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation
import CryptoKit
import Security
import Synchronization

nonisolated enum MITMCertificateStoreError: Error {
    case keyGenerationFailed(String)
    case keychainWriteFailed(OSStatus)
    case keychainReadFailed(OSStatus)
    case certificateBuildFailed(Error)
    case missingCAComponents
}

nonisolated final class MITMCertificateStore: Sendable {

    // MARK: - Configuration
    
    private static let accessGroup = AWCore.Identifier.appGroupSuite
    
    private static let service = "com.argsment.Anywhere.MITM"

    private static let privateKeyTag = "\(service).caPrivateKey".data(using: .utf8)!
    private static let certAccount = "\(service).caCertificate"
    private static let serialAccount = "\(service).caSerial"

    private static let caSubjectCN = "Anywhere Root Certificate"
    private static let caOrganization = "Anywhere"
    
    typealias CA = (privateKey: SecKey, certificateDER: Data)
    
    private let cachedCA = Mutex<CA?>(nil)

    // MARK: - CA Lifecycle

    func loadOrCreateCA() throws -> CA {
        try cachedCA.withLock { cache in
            if let existing = try? loadCACachedUnlocked(&cache) {
                return existing
            }
            do {
                return try generateCAUnlocked(&cache)
            } catch {
                // The App Group keychain is shared with the extension (the lock is
                // intra-process): either the other process won the race (re-read), or
                // an orphaned key from a failed cert write hit errSecDuplicateItem (drop it).
                if let existing = try? loadCACachedUnlocked(&cache) {
                    return existing
                }
                // Non-duplicate failures leave no key, so surface the real error.
                guard (try? readPrivateKeyUnlocked()) != nil else { throw error }
                deletePrivateKey()
                return try generateCAUnlocked(&cache)
            }
        }
    }

    func loadCA() -> CA? {
        cachedCA.withLock { cache in try? loadCACachedUnlocked(&cache) }
    }
    
    @discardableResult
    func regenerate() throws -> CA {
        try cachedCA.withLock { cache in
            deleteUnlocked(&cache)
            return try generateCAUnlocked(&cache)
        }
    }

    func delete() {
        cachedCA.withLock { cache in deleteUnlocked(&cache) }
    }

    // MARK: - Trust State

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
    
    func exportMobileConfig() -> Data? {
        guard let (caKey, certDER) = loadCA() else { return nil }

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

        guard let profileData = try? PropertyListSerialization.data(
            fromPropertyList: plist,
            format: .xml,
            options: 0
        ) else {
            return nil
        }
        
        return (try? signProfile(profileData, caKey: caKey, caCertificateDER: certDER)) ?? profileData
    }
    
    private func signProfile(_ profileData: Data, caKey: SecKey, caCertificateDER: Data) throws -> Data {
        let signingKey = try makeEphemeralSigningKey()
        let now = Date()
        let notAfter = Calendar(identifier: .gregorian).date(byAdding: .year, value: 1, to: now)
            ?? now.addingTimeInterval(60 * 60 * 24 * 365)

        let leafDER = try X509Builder.buildSigningCertificate(
            signingKey: signingKey,
            caPrivateKey: caKey,
            caCertificateDER: caCertificateDER,
            commonName: "Anywhere Profile Signing",
            serial: randomSerial(),
            notBefore: now.addingTimeInterval(-60 * 60),
            notAfter: notAfter
        )

        return try X509Builder.buildSignedProfile(
            profileData: profileData,
            signerPrivateKey: signingKey,
            signerCertificateDER: leafDER,
            certificates: [leafDER, caCertificateDER]
        )
    }
    
    private func makeEphemeralSigningKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let message = (error?.takeRetainedValue()).flatMap { CFErrorCopyDescription($0) as String? } ?? "unknown"
            throw MITMCertificateStoreError.keyGenerationFailed(message)
        }
        return key
    }

    // MARK: - Leaf Signing Inputs

    /// Returns a fresh 16-byte random serial. Randomness, not a shared counter:
    /// two App Group processes could mint duplicates (RFC 5280 §4.1.2.2).
    func nextSerial() -> Data {
        return randomSerial()
    }

    // MARK: - Private — CA load / generate / delete
    
    private func loadCACachedUnlocked(_ cache: inout CA?) throws -> CA {
        if let cache { return cache }
        let loaded = try loadCAUnlocked()
        cache = loaded
        return loaded
    }

    private func loadCAUnlocked() throws -> CA {
        let cert = try readCertificateUnlocked()
        let key = try readPrivateKeyUnlocked()
        return (key, cert)
    }

    private func generateCAUnlocked(_ cache: inout CA?) throws -> CA {
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
            let ca: CA = (privateKey: privateKey, certificateDER: certDER)
            cache = ca
            return ca
        } catch {
            // The key was already persisted (kSecAttrIsPermanent); delete it or
            // the next call hits errSecDuplicateItem on the same tag.
            deletePrivateKey()
            throw MITMCertificateStoreError.certificateBuildFailed(error)
        }
    }

    private func deleteUnlocked(_ cache: inout CA?) {
        cache = nil
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
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: access,
                kSecAttrApplicationTag as String: Self.privateKeyTag,
                kSecAttrAccessGroup as String: Self.accessGroup,
            ]
        ]
        var err: Unmanaged<CFError>?
        return SecKeyCreateRandomKey(attributes as CFDictionary, &err)
    }

    private func generateSoftwareKey() throws -> SecKey {
        // Fallback when the Secure Enclave is unavailable (simulator, older devices).
        // Non-extractable, non-synchronizable, ThisDeviceOnly: the CA key signs every
        // MITM leaf, so it must never leave the device.
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrIsExtractable as String: false,
                kSecAttrSynchronizable as String: false,
                kSecAttrApplicationTag as String: Self.privateKeyTag,
                kSecAttrAccessGroup as String: Self.accessGroup,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let message = (error?.takeRetainedValue()).flatMap { CFErrorCopyDescription($0) as String? } ?? "unknown"
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
            kSecAttrAccessGroup as String: Self.accessGroup,
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
            kSecAttrAccessGroup as String: Self.accessGroup,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Private — Keychain (Certificate)

    private func writeCertificateUnlocked(_ data: Data) throws {
        deleteCertificate()
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.certAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: Self.accessGroup,
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
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
            kSecAttrAccessGroup as String: Self.accessGroup,
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
            kSecAttrAccessGroup as String: Self.accessGroup,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Private — Keychain (Legacy serial item)

    /// Purges the legacy monotonic-counter serial item left behind by old installs; serials are now random.
    private func deleteSerial() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.serialAccount,
            kSecAttrAccessGroup as String: Self.accessGroup,
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Helpers

    private func randomSerial() -> Data {
        for _ in 0..<3 {
            var bytes = Data(count: 16)
            let status = bytes.withUnsafeMutableBytes { pointer in
                SecRandomCopyBytes(kSecRandomDefault, 16, pointer.baseAddress!)
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
