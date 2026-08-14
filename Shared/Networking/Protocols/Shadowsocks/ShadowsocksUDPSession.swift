//
//  ShadowsocksUDPSession.swift
//  Anywhere
//
//  Created by NodePassProject on 4/23/26.
//

import Foundation
import CryptoKit
import CommonCrypto
import Security
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "ShadowsocksUDPSession")

actor ShadowsocksUDPSession {

    // MARK: - Mode

    enum Mode {
        case legacy(cipher: ShadowsocksCipher, masterKey: Data)
        case ss2022AES(cipher: ShadowsocksCipher, pskList: [Data])
        case ss2022ChaCha(psk: Data)
    }

    // MARK: - Registration

    typealias Token = UInt64

    private final class Registration {
        let token: Token
        let port: UInt16
        var responseHosts: Set<String>
        var hasLearnedSource: Bool
        let inbox: AsyncThrowingStream<Data, Error>.Continuation

        init(token: Token, port: UInt16, responseHosts: Set<String>,
             hasLearnedSource: Bool, inbox: AsyncThrowingStream<Data, Error>.Continuation) {
            self.token = token
            self.port = port
            self.responseHosts = responseHosts
            self.hasLearnedSource = hasLearnedSource
            self.inbox = inbox
        }
    }

    private struct ResponseKey: Hashable {
        let host: String
        let port: UInt16
    }

    private enum Phase: PhaseTransitionable {
        case idle
        case connecting
        case ready
        case failed(Error)
        case cancelled

        var isTerminal: Bool {
            switch self {
            case .failed, .cancelled: true
            case .idle, .connecting, .ready: false
            }
        }

        var isCancelled: Bool {
            if case .cancelled = self { true } else { false }
        }

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .ready):
                return true
            case (_, .failed):
                return !old.isTerminal
            case (_, .cancelled):
                return !old.isCancelled
            default:
                return false
            }
        }
    }

    // MARK: - Immutable configuration

    private let mode: Mode
    private let serverHost: String
    private let serverPort: UInt16

    // MARK: - Mutable state

    private let asyncTransport: UDPTransport

    private let _isUsable = Atomic<Bool>(true)
    private var phase: Phase = .idle

    @discardableResult
    private func transition(to new: Phase) -> Bool {
        guard Phase.transition(&phase, to: new) else { return false }
        switch new {
        case .idle, .connecting, .ready: _isUsable.store(true, ordering: .relaxed)
        case .failed, .cancelled: _isUsable.store(false, ordering: .relaxed)
        }
        return true
    }

    private var readyTask: Task<Void, Error>?

    private var receiveTask: Task<Void, Never>?

    private var nextToken: Token = 0
    private var registrations: [Token: Registration] = [:]
    private var tokensByResponse: [ResponseKey: [Token]] = [:]
    private var tokensByPort: [UInt16: [Token]] = [:]

    private var sessionID: UInt64 = 0
    private var packetIDCounter: UInt64 = 0
    private var outboundCipherKey: Data?

    private var remoteSessionID: UInt64 = 0
    private var remoteCipherKey: Data?

    private let pskHashes: [Data]

    // MARK: - Init

    init(mode: Mode,
         serverHost: String,
         serverPort: UInt16) {
        self.mode = mode
        self.serverHost = serverHost
        self.serverPort = serverPort

        let asyncTransport = UDPTransport(host: serverHost, port: serverPort, resolvesViaProxyDNS: true)
        self.asyncTransport = asyncTransport

        switch mode {
        case .ss2022AES(let cipher, let pskList):
            var sid: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &sid) { pointer in
                SecRandomCopyBytes(kSecRandomDefault, 8, pointer.baseAddress!)
            }
            self.sessionID = sid
            var sidBE = sid.bigEndian
            let sidData = Data(bytes: &sidBE, count: 8)
            self.outboundCipherKey = ShadowsocksKeyDerivation.deriveSessionKey(
                psk: pskList.last!, salt: sidData, keySize: cipher.keySize)

            var hashes: [Data] = []
            if pskList.count >= 2 {
                for i in 1..<pskList.count {
                    hashes.append(ShadowsocksKeyDerivation.blake3Hash16(pskList[i]))
                }
            }
            self.pskHashes = hashes

        case .ss2022ChaCha:
            var sid: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &sid) { pointer in
                SecRandomCopyBytes(kSecRandomDefault, 8, pointer.baseAddress!)
            }
            self.sessionID = sid
            self.pskHashes = []

        case .legacy:
            self.pskHashes = []
        }
    }

    // MARK: - Public API

    nonisolated var isUsable: Bool {
        _isUsable.load(ordering: .relaxed)
    }

    func register(
        dstHost: String,
        dstPort: UInt16,
        responseHostHints: [String] = []
    ) -> (token: Token, stream: AsyncThrowingStream<Data, Error>) {
        nextToken += 1
        let token = nextToken

        var hosts: Set<String> = [dstHost]
        for hint in responseHostHints { hosts.insert(hint) }

        let pinned = hosts.count > 1

        let (stream, continuation) = AsyncThrowingStream.makeStream(of: Data.self)
        let registration = Registration(
            token: token,
            port: dstPort,
            responseHosts: hosts,
            hasLearnedSource: pinned,
            inbox: continuation
        )
        registrations[token] = registration
        for host in hosts {
            tokensByResponse[ResponseKey(host: host, port: dstPort), default: []].append(token)
        }
        tokensByPort[dstPort, default: []].append(token)

        if case .idle = phase {
            startConnectIfNeeded()
        }
        return (token, stream)
    }

    func addResponseHints(token: Token, hints: [String]) {
        guard let registration = registrations[token] else { return }
        var inserted = false
        for hint in hints where registration.responseHosts.insert(hint).inserted {
            tokensByResponse[ResponseKey(host: hint, port: registration.port), default: []].append(token)
            inserted = true
        }
        if inserted {
            registration.hasLearnedSource = true
        }
    }

    func unregister(token: Token) {
        guard let registration = registrations.removeValue(forKey: token) else { return }
        for host in registration.responseHosts {
            removeToken(token, from: &tokensByResponse, key: ResponseKey(host: host, port: registration.port))
        }
        removeToken(token, from: &tokensByPort, key: registration.port)
        registration.inbox.finish()
    }

    func send(
        token: Token,
        dstHost: String,
        dstPort: UInt16,
        payload: Data
    ) async throws {
        guard registrations[token] != nil else {
            throw AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "invalid address header"))
        }
        try await ensureReadyForSend()
        let encrypted = try encryptPacket(payload: payload, dstHost: dstHost, dstPort: dstPort)
        try await asyncTransport.send(encrypted)
    }

    deinit {
        asyncTransport.cancel()
    }

    nonisolated func cancel() {
        _isUsable.store(false, ordering: .relaxed)
        asyncTransport.cancel()
        Task { await self.performCancel() }
    }

    private func performCancel() {
        if case .cancelled = phase { return }
        transition(to: .cancelled)
        notifyAllFlows(error: AnywhereError.transport(.terminated))
        readyTask?.cancel()
        readyTask = nil
        receiveTask?.cancel()
        receiveTask = nil
        registrations.removeAll()
        tokensByResponse.removeAll()
        tokensByPort.removeAll()
    }

    // MARK: - Connect

    private func ensureReadyForSend() async throws {
        switch phase {
        case .ready:
            return
        case .failed(let error):
            throw error
        case .cancelled:
            throw AnywhereError.transport(.terminated)
        case .idle, .connecting:
            guard let task = startConnectIfNeeded() else { return }
            try await task.value
        }
    }

    @discardableResult
    private func startConnectIfNeeded() -> Task<Void, Error>? {
        switch phase {
        case .ready, .failed, .cancelled:
            return nil
        case .idle, .connecting:
            if let existing = readyTask { return existing }
            let task = Task<Void, Error> { [weak self] in
                guard let self else { throw AnywhereError.transport(.terminated) }
                try await self.performConnect()
            }
            readyTask = task
            return task
        }
    }

    private func performConnect() async throws {
        transition(to: .connecting)
        do {
            try await asyncTransport.connect()
        } catch {
            if case .cancelled = phase { throw AnywhereError.transport(.terminated) }
            transition(to: .failed(error))
            asyncTransport.cancel()
            notifyAllFlows(error: error)
            throw error
        }
        guard transition(to: .ready) else {
            throw AnywhereError.transport(.terminated)
        }
        startReceiveLoop()
    }

    private func handleTransportError(_ error: Error) {
        guard transition(to: .failed(error)) else { return }
        asyncTransport.cancel()
        notifyAllFlows(error: error)
    }

    private func startReceiveLoop() {
        let asyncTransport = self.asyncTransport
        receiveTask = Task { [weak self] in
            do {
                while true {
                    let datagram = try await asyncTransport.receive()
                    await self?.handleReceivedDatagram(datagram)
                }
            } catch {
                await self?.handleTransportError(error)
            }
        }
    }

    private func notifyAllFlows(error: Error) {
        for registration in registrations.values {
            registration.inbox.finish(throwing: error)
        }
    }


    // MARK: - Receive & Route

    private func handleReceivedDatagram(_ data: Data) {
        let decoded: (host: String, port: UInt16, payload: Data)
        do {
            decoded = try decryptPacket(data)
        } catch {
            logger.debug("[SS-UDP] Decrypt error: \(error.localizedDescription)")
            return
        }

        let key = ResponseKey(host: decoded.host, port: decoded.port)

        if let tokens = tokensByResponse[key],
           let registration = firstRegistration(in: tokens) {
            registration.inbox.yield(decoded.payload)
            return
        }

        if let tokens = tokensByPort[decoded.port] {
            let target = firstRegistration(in: tokens, where: { !$0.hasLearnedSource })
                ?? firstRegistration(in: tokens)
            if let target {
                if !target.responseHosts.contains(decoded.host) {
                    target.responseHosts.insert(decoded.host)
                    tokensByResponse[key, default: []].append(target.token)
                }
                target.hasLearnedSource = true
                target.inbox.yield(decoded.payload)
                return
            }
        }
        logger.debug("[SS-UDP] No flow for reply from \(decoded.host):\(decoded.port); dropped")
    }

    private func firstRegistration(in tokens: [Token]) -> Registration? {
        for token in tokens {
            if let registration = registrations[token] { return registration }
        }
        return nil
    }

    private func firstRegistration(in tokens: [Token],
                                   where predicate: (Registration) -> Bool) -> Registration? {
        for token in tokens {
            if let registration = registrations[token], predicate(registration) { return registration }
        }
        return nil
    }

    // MARK: - Crypto

    private func nextPacketID() -> UInt64 {
        packetIDCounter += 1
        return packetIDCounter
    }

    private func encryptPacket(payload: Data, dstHost: String, dstPort: UInt16) throws -> Data {
        switch mode {
        case .legacy(let cipher, let masterKey):
            let packet = ShadowsocksProtocol.encodeUDPPacket(host: dstHost, port: dstPort, payload: payload)
            return try ShadowsocksUDPCrypto.encrypt(cipher: cipher, masterKey: masterKey, payload: packet)

        case .ss2022AES(let cipher, let pskList):
            return try encryptSS2022AES(payload: payload, dstHost: dstHost, dstPort: dstPort, cipher: cipher, pskList: pskList)

        case .ss2022ChaCha(let psk):
            return try encryptSS2022ChaCha(payload: payload, dstHost: dstHost, dstPort: dstPort, psk: psk)
        }
    }

    private func encryptSS2022AES(
        payload: Data,
        dstHost: String,
        dstPort: UInt16,
        cipher: ShadowsocksCipher,
        pskList: [Data]
    ) throws -> Data {
        guard let sessionKey = outboundCipherKey else { throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed)) }

        // 16-byte packet header: sessionID(8) + packetID(8), both big-endian.
        var header = Data(capacity: 16)
        var sidBE = sessionID.bigEndian
        withUnsafeBytes(of: &sidBE) { header.append(contentsOf: $0) }
        var pidBE = nextPacketID().bigEndian
        withUnsafeBytes(of: &pidBE) { header.append(contentsOf: $0) }

        // Multi-PSK identity headers (skipped when only one PSK is configured).
        var identityData = Data()
        if pskList.count >= 2 {
            for i in 0..<(pskList.count - 1) {
                let hash = pskHashes[i]
                var xored = Data(count: 16)
                for j in 0..<16 { xored[j] = hash[j] ^ header[j] }
                let encrypted = try ssAESECBEncryptBlock(key: pskList[i], block: xored)
                identityData.append(encrypted)
            }
        }

        // AEAD body: type(0) + ts(8) + paddingLen(2) + padding + addr + payload.
        let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: dstHost, port: dstPort)
        let paddingLen = (dstPort == 53 && payload.count < 900)
            ? Int.random(in: 1...(900 - payload.count))
            : 0

        var body = Data()
        body.append(0) // HeaderTypeClient
        var timestamp = UInt64(Date().timeIntervalSince1970).bigEndian
        withUnsafeBytes(of: &timestamp) { body.append(contentsOf: $0) }
        var paddingLenBE = UInt16(paddingLen).bigEndian
        withUnsafeBytes(of: &paddingLenBE) { body.append(contentsOf: $0) }
        if paddingLen > 0 {
            body.append(Data(repeating: 0, count: paddingLen))
        }
        body.append(addressHeader)
        body.append(payload)

        // AEAD nonce = last 12 bytes of the 16-byte header.
        let nonce = Data(header[4..<16])
        let sealedBody = try ShadowsocksAEADCrypto.seal(
            cipher: cipher, key: sessionKey, nonce: nonce, plaintext: body)

        // Header is AES-ECB encrypted with pskList[0]: the iPSK, or the user PSK when single.
        let encryptedHeader = try ssAESECBEncryptBlock(key: pskList.first!, block: header)

        var packet = Data(capacity: encryptedHeader.count + identityData.count + sealedBody.count)
        packet.append(encryptedHeader)
        packet.append(identityData)
        packet.append(sealedBody)
        return packet
    }

    private func encryptSS2022ChaCha(
        payload: Data,
        dstHost: String,
        dstPort: UInt16,
        psk: Data
    ) throws -> Data {
        // 24-byte random nonce prepended as cleartext.
        var nonceBytes = [UInt8](repeating: 0, count: 24)
        _ = SecRandomCopyBytes(kSecRandomDefault, 24, &nonceBytes)
        let nonce = Data(nonceBytes)

        let addressHeader = ShadowsocksProtocol.buildAddressHeader(host: dstHost, port: dstPort)
        let paddingLen = (dstPort == 53 && payload.count < 900)
            ? Int.random(in: 1...(900 - payload.count))
            : 0

        var body = Data()
        var sidBE = sessionID.bigEndian
        withUnsafeBytes(of: &sidBE) { body.append(contentsOf: $0) }
        var pidBE = nextPacketID().bigEndian
        withUnsafeBytes(of: &pidBE) { body.append(contentsOf: $0) }
        body.append(0) // HeaderTypeClient
        var timestamp = UInt64(Date().timeIntervalSince1970).bigEndian
        withUnsafeBytes(of: &timestamp) { body.append(contentsOf: $0) }
        var paddingLenBE = UInt16(paddingLen).bigEndian
        withUnsafeBytes(of: &paddingLenBE) { body.append(contentsOf: $0) }
        if paddingLen > 0 {
            body.append(Data(repeating: 0, count: paddingLen))
        }
        body.append(addressHeader)
        body.append(payload)

        let sealed = try XChaCha20Poly1305.seal(key: psk, nonce: nonce, plaintext: body)

        var packet = Data(capacity: nonce.count + sealed.count)
        packet.append(nonce)
        packet.append(sealed)
        return packet
    }

    private func decryptPacket(_ data: Data) throws -> (host: String, port: UInt16, payload: Data) {
        switch mode {
        case .legacy(let cipher, let masterKey):
            let decrypted = try ShadowsocksUDPCrypto.decrypt(cipher: cipher, masterKey: masterKey, data: data)
            guard let parsed = ShadowsocksProtocol.decodeUDPPacket(data: decrypted) else {
                throw AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "invalid address header"))
            }
            return parsed

        case .ss2022AES(let cipher, let pskList):
            guard data.count >= 16 + 16 else { throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed)) }

            // Header AES-ECB decrypt uses the user PSK (pskList.last).
            let header = try ssAESECBDecryptBlock(key: pskList.last!, block: Data(data.prefix(16)))

            var sidBE: UInt64 = 0
            _ = withUnsafeMutableBytes(of: &sidBE) { pointer in
                header[0..<8].copyBytes(to: pointer)
            }
            let serverSession = UInt64(bigEndian: sidBE)

            let cipherKey: Data
            if serverSession == remoteSessionID, let cached = remoteCipherKey {
                cipherKey = cached
            } else {
                var rsBE = serverSession.bigEndian
                let rsData = Data(bytes: &rsBE, count: 8)
                cipherKey = ShadowsocksKeyDerivation.deriveSessionKey(
                    psk: pskList.last!, salt: rsData, keySize: cipher.keySize)
                remoteSessionID = serverSession
                remoteCipherKey = cipherKey
            }

            let nonce = Data(header[4..<16])
            let sealedBody = Data(data.suffix(from: data.startIndex + 16))
            let body = try ShadowsocksAEADCrypto.open(
                cipher: cipher, key: cipherKey, nonce: nonce, ciphertext: sealedBody)

            return try parseServerUDPBody(body)

        case .ss2022ChaCha(let psk):
            guard data.count >= 24 + 16 else { throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed)) }

            let nonce = Data(data.prefix(24))
            let ciphertext = Data(data.suffix(from: data.startIndex + 24))
            let body = try XChaCha20Poly1305.open(key: psk, nonce: nonce, ciphertext: ciphertext)

            // Body: sessionID(8) + packetID(8) + standard server body.
            guard body.count >= 16 else { throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed)) }
            let innerBody = Data(body.suffix(from: body.startIndex + 16))
            return try parseServerUDPBody(innerBody)
        }
    }

    private func parseServerUDPBody(_ body: Data) throws -> (host: String, port: UInt16, payload: Data) {
        guard body.count >= 1 + 8 + 8 + 2 else {
            throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed))
        }

        var offset = body.startIndex
        let headerType = body[offset]
        offset += 1
        guard headerType == 1 else { throw AnywhereError.proxy(.shadowsocks, .cipher(.malformedHeader)) }

        var epochBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &epochBE) { pointer in
            body[offset..<offset+8].copyBytes(to: pointer)
        }
        let epoch = Int64(UInt64(bigEndian: epochBE))
        let now = Int64(Date().timeIntervalSince1970)
        if abs(now - epoch) > 30 {
            throw AnywhereError.proxy(.shadowsocks, .cipher(.staleTimestamp))
        }
        offset += 8

        var clientSidBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &clientSidBE) { pointer in
            body[offset..<offset+8].copyBytes(to: pointer)
        }
        let clientSid = UInt64(bigEndian: clientSidBE)
        guard clientSid == sessionID else {
            throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed))
        }
        offset += 8

        guard body.endIndex - offset >= 2 else { throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed)) }
        let paddingLen = Int(UInt16(body[offset]) << 8 | UInt16(body[offset + 1]))
        offset += 2
        offset += paddingLen

        guard let parsed = ShadowsocksProtocol.decodeUDPPacket(data: Data(body[offset...])) else {
            throw AnywhereError.proxy(.shadowsocks, .protocolViolation(detail: "invalid address header"))
        }
        return parsed
    }

    // MARK: - Helpers

    private func removeToken<Key: Hashable>(_ token: Token, from map: inout [Key: [Token]], key: Key) {
        guard var tokens = map[key] else { return }
        tokens.removeAll { $0 == token }
        if tokens.isEmpty {
            map.removeValue(forKey: key)
        } else {
            map[key] = tokens
        }
    }
}

// MARK: - AES-ECB Single Block

private nonisolated func ssAESECBEncryptBlock(key: Data, block: Data) throws -> Data {
    guard block.count == 16 else { throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed)) }
    var outBytes = [UInt8](repeating: 0, count: 16 + kCCBlockSizeAES128)
    var outLen: Int = 0
    let status = key.withUnsafeBytes { keyPtr in
        block.withUnsafeBytes { blockPtr in
            CCCrypt(
                CCOperation(kCCEncrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                keyPtr.baseAddress!, key.count,
                nil,
                blockPtr.baseAddress!, 16,
                &outBytes, outBytes.count,
                &outLen
            )
        }
    }
    guard status == kCCSuccess else { throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed)) }
    return Data(outBytes.prefix(16))
}

private nonisolated func ssAESECBDecryptBlock(key: Data, block: Data) throws -> Data {
    guard block.count == 16 else { throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed)) }
    var outBytes = [UInt8](repeating: 0, count: 16 + kCCBlockSizeAES128)
    var outLen: Int = 0
    let status = key.withUnsafeBytes { keyPtr in
        block.withUnsafeBytes { blockPtr in
            CCCrypt(
                CCOperation(kCCDecrypt),
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionECBMode),
                keyPtr.baseAddress!, key.count,
                nil,
                blockPtr.baseAddress!, 16,
                &outBytes, outBytes.count,
                &outLen
            )
        }
    }
    guard status == kCCSuccess else { throw AnywhereError.proxy(.shadowsocks, .cipher(.decryptionFailed)) }
    return Data(outBytes.prefix(16))
}
