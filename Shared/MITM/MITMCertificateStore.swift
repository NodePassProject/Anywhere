//
//  MITMCertificateStore.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
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

    /// App Group identifier used as the keychain access group. The same
    /// value is used by both the app target and the Network Extension via
    /// the ``keychain-access-groups`` entitlement.
    private let accessGroup: String

    /// Service tag for keychain queries. All MITM keychain items share
    /// this service so deleting / regenerating only affects MITM data.
    private static let service = "com.argsment.Anywhere.MITM"

    private static let privateKeyTag = "\(service).caPrivateKey".data(using: .utf8)!
    private static let certAccount = "\(service).caCertificate"
    private static let serialAccount = "\(service).caSerial"

    private static let caSubjectCN = "Anywhere MITM Root"
    private static let caOrganization = "Anywhere"

    private let lock = NSLock()

    // MARK: - Init

    init(accessGroup: String = "\(AWCore.Identifier.appGroupSuite)") {
        self.accessGroup = accessGroup
    }

    // MARK: - CA Lifecycle

    /// Returns the persisted CA cert + private key, generating them on first
    /// use. Generation tries the Secure Enclave first and silently falls
    /// back to a software key when the device or sandbox doesn't allow it.
    func loadOrCreateCA() throws -> (privateKey: SecKey, certificateDER: Data) {
        lock.lock()
        defer { lock.unlock() }

        if let existing = try? loadCAUnlocked() {
            return existing
        }
        return try generateCAUnlocked()
    }

    /// Returns the persisted CA cert + private key, or `nil` if neither has
    /// been generated yet. Read-only; safe to call from the Network
    /// Extension at connect time.
    func loadCA() -> (privateKey: SecKey, certificateDER: Data)? {
        lock.lock()
        defer { lock.unlock() }
        return try? loadCAUnlocked()
    }

    /// Wipes the persisted CA and generates a fresh one. Any previously
    /// installed root profile is invalidated by this operation.
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

    /// Whether the system trust store evaluates the persisted CA cert as
    /// trusted (i.e., the user installed and enabled the profile).
    func isCATrusted() -> Bool {
        guard let (_, certDER) = loadCA(),
              let secCert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            return false
        }
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let status = SecTrustCreateWithCertificates(secCert, policy, &trust)
        guard status == errSecSuccess, let trust else { return false }
        var error: CFError?
        return SecTrustEvaluateWithError(trust, &error)
    }

    // MARK: - Export

    /// DER-encoded CA certificate, suitable for ``SecCertificateCreateWithData``.
    func exportCertificateDER() -> Data? {
        loadCA()?.certificateDER
    }

    /// Builds a `.mobileconfig` profile that wraps the CA cert. Lets the
    /// user install the root via Safari/AirDrop without a third-party tool.
    /// The profile is rebuilt every call — never persisted.
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
            "PayloadDisplayName": "Anywhere MITM Root",
            "PayloadDescription": "Installs the Anywhere MITM root certificate.",
            "PayloadOrganization": "Anywhere",
            "PayloadContent": [
                [
                    "PayloadType": "com.apple.security.root",
                    "PayloadVersion": 1,
                    "PayloadIdentifier": payloadIdentifier,
                    "PayloadUUID": payloadUUID,
                    "PayloadDisplayName": "Anywhere MITM Root Certificate",
                    "PayloadDescription": "The CA used to terminate TLS for MITM-listed hostnames.",
                    "PayloadCertificateFileName": "AnywhereMITMRoot.cer",
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

    /// Returns a fresh 16-byte serial. Stored monotonically in the keychain
    /// so leaf certs minted across extension restarts don't collide.
    func nextSerial() -> Data {
        lock.lock()
        defer { lock.unlock() }

        var counter = readSerialUnlocked()
        counter &+= 1
        writeSerialUnlocked(counter)

        var bytes = Data(count: 16)
        // Random high 8 bytes mixed with monotonic low 8 bytes.
        bytes.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 8, ptr.baseAddress!)
        }
        for i in 0..<8 {
            bytes[8 + i] = UInt8((counter >> ((7 - i) * 8)) & 0xFF)
        }
        return bytes
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

        let certDER: Data
        do {
            certDER = try X509Builder.buildCACertificate(
                privateKey: privateKey,
                subjectCN: Self.caSubjectCN,
                organization: Self.caOrganization,
                serial: serial,
                notBefore: now.addingTimeInterval(-60 * 60),
                notAfter: notAfter
            )
        } catch {
            // Leave the keychain item alone — caller can retry.
            throw MITMCertificateStoreError.certificateBuildFailed(error)
        }

        try writeCertificateUnlocked(certDER)
        // Reset the serial counter when the CA itself is rebuilt.
        writeSerialUnlocked(0)
        return (privateKey, certDER)
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
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
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

    // MARK: - Private — Keychain (Serial counter)

    private func readSerialUnlocked() -> UInt64 {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.serialAccount,
            kSecReturnData as String: true,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data, data.count >= 8 else {
            return 0
        }
        var value: UInt64 = 0
        for i in 0..<8 {
            value = (value << 8) | UInt64(data[data.startIndex + i])
        }
        return value
    }

    private func writeSerialUnlocked(_ value: UInt64) {
        var bytes = Data(count: 8)
        for i in 0..<8 {
            bytes[i] = UInt8((value >> ((7 - i) * 8)) & 0xFF)
        }
        deleteSerial()
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.serialAccount,
            kSecValueData as String: bytes,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrAccessGroup as String: accessGroup,
        ]
        SecItemAdd(attrs as CFDictionary, nil)
    }

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
        var bytes = Data(count: 16)
        bytes.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 16, ptr.baseAddress!)
        }
        return bytes
    }
}
