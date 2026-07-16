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
        /// Legacy SS: per-packet salt + AEAD(address || payload); no session state.
        case legacy(cipher: ShadowsocksCipher, masterKey: Data)
        /// SS 2022 AES variant: AES-ECB 16-byte packet header + per-session AEAD body; multi-PSK via identity headers.
        case ss2022AES(cipher: ShadowsocksCipher, pskList: [Data])
        /// SS 2022 ChaCha variant: XChaCha20-Poly1305 with 24-byte random nonce; single PSK only.
        case ss2022ChaCha(psk: Data)
    }

    // MARK: - Registration

    typealias Token = UInt64

    private final class Registration {
        let token: Token
        let port: UInt16
        /// Reply hosts matching this flow: destination host, owner hints, and hosts learned via port-only fallback.
        var responseHosts: Set<String>
        /// True once a reply source is pinned; port-only fallback prefers unpinned flows.
        var hasLearnedSource: Bool
        /// Inbound datagrams for this flow; failed on transport error / session teardown,
        /// EOF'd (`cancel()`) on unregister so the flow's reader unwinds cleanly.
        let inbox = AsyncByteChannel()

        init(token: Token, port: UInt16, responseHosts: Set<String>,
             hasLearnedSource: Bool) {
            self.token = token
            self.port = port
            self.responseHosts = responseHosts
            self.hasLearnedSource = hasLearnedSource
        }
    }

    private struct ResponseKey: Hashable {
        let host: String
        let port: UInt16
    }

    private enum State {
        case idle
        case connecting
        case ready
        case failed(Error)  // terminal — notified all flows, refuses new sends
        case cancelled
    }

    // MARK: - Immutable configuration

    private let mode: Mode
    private let serverHost: String
    private let serverPort: UInt16

    // MARK: - Mutable state (actor-isolated)

    /// The async-native datagram transport; `connect()` is awaited in `beginConnect`.
    private let asyncTransport: UDPTransport

    /// Readiness mirror: `true` while idle/connecting/ready, `false` once failed/cancelled.
    /// Lets the owning stack poll `isUsable` without hopping onto the actor.
    private let _isUsable = Atomic<Bool>(true)
    private var _state: State = .idle
    private var state: State {
        get { _state }
        set {
            _state = newValue
            switch newValue {
            case .idle, .connecting, .ready: _isUsable.store(true, ordering: .relaxed)
            case .failed, .cancelled: _isUsable.store(false, ordering: .relaxed)
            }
        }
    }

    /// Awaiting `send` calls parked while the transport dials; resumed (or thrown) once
    /// `finishConnect` lands. Replaces the old ordered `pendingSends` buffer.
    private var readyWaiters: [CheckedContinuation<Void, Error>] = []

    private var nextToken: Token = 0
    private var registrations: [Token: Registration] = [:]
    private var tokensByResponse: [ResponseKey: [Token]] = [:]
    private var tokensByPort: [UInt16: [Token]] = [:]

    // SS 2022 session state — sessionwide, not per-flow.
    private var sessionID: UInt64 = 0
    private var packetIDCounter: UInt64 = 0
    /// Outbound AEAD key for the AES variant, derived once from sessionID + user PSK.
    private var outboundCipherKey: Data?

    /// Last seen server sessionID + derived inbound key; re-derived only when the server rotates.
    private var remoteSessionID: UInt64 = 0
    private var remoteCipherKey: Data?

    /// First 16 BLAKE3 bytes of each `pskList[i]` for i >= 1, for multi-PSK identity headers.
    private let pskHashes: [Data]

    // MARK: - Init

    init(mode: Mode,
         serverHost: String,
         serverPort: UInt16) {
        self.mode = mode
        self.serverHost = serverHost
        self.serverPort = serverPort

        let asyncTransport = UDPTransport(host: serverHost, port: serverPort)
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

    /// Nonisolated readiness poll for the owning stack (no actor hop). Mirrors `state`.
    nonisolated var isUsable: Bool {
        _isUsable.load(ordering: .relaxed)
    }

    /// Registers interest in UDP replies matching `(dstHost, dstPort)` or any hint.
    /// Servers typically reply with the resolved IP, so pass known IPs as hints for
    /// exact demultiplexing; otherwise delivery falls back to port-only. Returns the
    /// flow's token and its inbound datagram channel (drained by the caller).
    func register(dstHost: String,
                  dstPort: UInt16,
                  responseHostHints: [String] = []) -> (token: Token, inbox: AsyncByteChannel) {
        nextToken += 1
        let token = nextToken

        var hosts: Set<String> = [dstHost]
        for hint in responseHostHints { hosts.insert(hint) }

        // Pre-supplied hints count as a pinned source; `dstHost` alone does not.
        let pinned = hosts.count > 1

        let registration = Registration(token: token, port: dstPort,
                               responseHosts: hosts,
                               hasLearnedSource: pinned)
        registrations[token] = registration
        for host in hosts {
            tokensByResponse[ResponseKey(host: host, port: dstPort), default: []].append(token)
        }
        tokensByPort[dstPort, default: []].append(token)

        if case .idle = state {
            beginConnect()
        }
        return (token, registration.inbox)
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

    /// Idempotent; no-ops if the token is unknown.
    func unregister(token: Token) {
        guard let registration = registrations.removeValue(forKey: token) else { return }
        for host in registration.responseHosts {
            removeToken(token, from: &tokensByResponse, key: ResponseKey(host: host, port: registration.port))
        }
        removeToken(token, from: &tokensByPort, key: registration.port)
        // EOF the flow's reader so its receive loop unwinds without surfacing an error.
        registration.inbox.cancel()
    }

    /// Awaits transport readiness (parking if still dialing), then encrypts and sends.
    /// PacketID allocation happens synchronously before the wire `await`, so IDs stay unique.
    func send(token: Token,
              dstHost: String,
              dstPort: UInt16,
              payload: Data) async throws {
        guard registrations[token] != nil else {
            throw ShadowsocksError.invalidAddress
        }
        try await ensureReadyForSend()
        // Synchronous, actor-isolated: allocate packetID + encrypt before releasing the actor.
        let encrypted = try encryptPacket(payload: payload,
                                          dstHost: dstHost,
                                          dstPort: dstPort)
        // UDP datagrams are independent — the actor is free to service other sends across
        // this await; each already holds its own unique packetID.
        try await asyncTransport.send(encrypted)
    }

    deinit {
        asyncTransport.cancel()
    }

    /// Nonisolated so a synchronous purge can cancel without `await`. Flips the readiness
    /// mirror and tears the socket down immediately; the actor-isolated teardown (notifying
    /// flows, clearing maps) is scheduled after.
    nonisolated func cancel() {
        _isUsable.store(false, ordering: .relaxed)
        asyncTransport.cancel()
        Task { await self.performCancel() }
    }

    private func performCancel() {
        if case .cancelled = state { return }
        state = .cancelled
        notifyAllFlows(error: ProxyError.connectionFailed("Session cancelled"))
        resumeReadyWaiters(throwing: ProxyError.connectionFailed("Session cancelled"))
        registrations.removeAll()
        tokensByResponse.removeAll()
        tokensByPort.removeAll()
    }

    // MARK: - Connect

    /// Parks the caller until the transport is ready; kicks off the dial on first use.
    private func ensureReadyForSend() async throws {
        switch state {
        case .ready:
            return
        case .failed(let error):
            throw error
        case .cancelled:
            throw ProxyError.connectionFailed("Session cancelled")
        case .idle:
            beginConnect()
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                readyWaiters.append(c)
            }
        case .connecting:
            try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                readyWaiters.append(c)
            }
        }
    }

    private func beginConnect() {
        guard case .idle = state else { return }
        state = .connecting
        let asyncTransport = self.asyncTransport
        Task { [weak self] in
            let connectResult: Result<Void, Error>
            do {
                try await asyncTransport.connect()
                connectResult = .success(())
            } catch {
                connectResult = .failure(error)
            }
            await self?.finishConnect(connectResult)
        }
    }

    /// Completes the dial: arms the receive loop and releases parked senders, or fails the session.
    private func finishConnect(_ result: Result<Void, Error>) {
        if case .cancelled = state { return }

        if case .failure(let error) = result {
            state = .failed(error)
            asyncTransport.cancel()
            notifyAllFlows(error: error)
            resumeReadyWaiters(throwing: error)
            return
        }

        state = .ready
        startReceiveLoop()
        resumeReadyWaiters(throwing: nil)
    }

    private func handleTransportError(_ error: Error) {
        switch state {
        case .cancelled, .failed: return
        default: break
        }
        state = .failed(error)
        asyncTransport.cancel()
        notifyAllFlows(error: error)
        resumeReadyWaiters(throwing: error)
    }

    /// Drives the datagram downlink into the actor. The loop is unstored: it never retains
    /// the session and dies when `asyncTransport.cancel()` errors its pending receive.
    private func startReceiveLoop() {
        let asyncTransport = self.asyncTransport
        Task { [weak self] in
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

    /// Fails every registered flow's inbox (transport error / teardown).
    private func notifyAllFlows(error: Error) {
        for registration in registrations.values {
            registration.inbox.fail(error)
        }
    }

    /// Resumes every parked sender exactly once — with success (`nil`) or the given error.
    private func resumeReadyWaiters(throwing error: Error?) {
        let waiters = readyWaiters
        readyWaiters.removeAll()
        for continuation in waiters {
            if let error {
                continuation.resume(throwing: error)
            } else {
                continuation.resume()
            }
        }
    }

    // MARK: - Receive & Route

    private func handleReceivedDatagram(_ data: Data) {
        let decoded: (host: String, port: UInt16, payload: Data)
        do {
            decoded = try decryptPacket(data)
        } catch {
            // Drop corrupt/stale datagrams; don't tear down the session on one bad packet.
            logger.debug("[SS-UDP] Decrypt error: \(error.localizedDescription)")
            return
        }

        let key = ResponseKey(host: decoded.host, port: decoded.port)

        if let tokens = tokensByResponse[key],
           let registration = firstRegistration(in: tokens) {
            registration.inbox.yield(decoded.payload)
            return
        }

        // Port-only fallback: multiple flows may share a port; prefer one that
        // hasn't pinned a reply source (a pinned flow would have matched exactly).
        if let tokens = tokensByPort[decoded.port] {
            let target = firstRegistration(in: tokens, where: { !$0.hasLearnedSource })
                ?? firstRegistration(in: tokens)
            if let target {
                // Pin this reply address so future packets from the same peer route exactly.
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
            return try encryptSS2022AES(payload: payload, dstHost: dstHost, dstPort: dstPort,
                                        cipher: cipher, pskList: pskList)

        case .ss2022ChaCha(let psk):
            return try encryptSS2022ChaCha(payload: payload, dstHost: dstHost,
                                           dstPort: dstPort, psk: psk)
        }
    }

    private func encryptSS2022AES(payload: Data,
                                  dstHost: String,
                                  dstPort: UInt16,
                                  cipher: ShadowsocksCipher,
                                  pskList: [Data]) throws -> Data {
        guard let sessionKey = outboundCipherKey else { throw ShadowsocksError.decryptionFailed }

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

    private func encryptSS2022ChaCha(payload: Data,
                                     dstHost: String,
                                     dstPort: UInt16,
                                     psk: Data) throws -> Data {
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
                throw ShadowsocksError.invalidAddress
            }
            return parsed

        case .ss2022AES(let cipher, let pskList):
            guard data.count >= 16 + 16 else { throw ShadowsocksError.decryptionFailed }

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
            guard data.count >= 24 + 16 else { throw ShadowsocksError.decryptionFailed }

            let nonce = Data(data.prefix(24))
            let ciphertext = Data(data.suffix(from: data.startIndex + 24))
            let body = try XChaCha20Poly1305.open(key: psk, nonce: nonce, ciphertext: ciphertext)

            // Body: sessionID(8) + packetID(8) + standard server body. No sliding-window
            // validation — the AEAD tag + timestamp already gate acceptance.
            guard body.count >= 16 else { throw ShadowsocksError.decryptionFailed }
            let innerBody = Data(body.suffix(from: body.startIndex + 16))
            return try parseServerUDPBody(innerBody)
        }
    }

    /// Parses a decrypted SS 2022 server UDP body:
    /// `type(1) + timestamp(8) + clientSessionID(8) + paddingLen(2) + padding + socksaddr + payload`
    private func parseServerUDPBody(_ body: Data) throws -> (host: String, port: UInt16, payload: Data) {
        guard body.count >= 1 + 8 + 8 + 2 else {
            throw ShadowsocksError.decryptionFailed
        }

        var offset = body.startIndex
        let headerType = body[offset]
        offset += 1
        guard headerType == 1 else { throw ShadowsocksError.badHeaderType }

        var epochBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &epochBE) { pointer in
            body[offset..<offset+8].copyBytes(to: pointer)
        }
        let epoch = Int64(UInt64(bigEndian: epochBE))
        let now = Int64(Date().timeIntervalSince1970)
        if abs(now - epoch) > 30 {
            throw ShadowsocksError.badTimestamp
        }
        offset += 8

        var clientSidBE: UInt64 = 0
        _ = withUnsafeMutableBytes(of: &clientSidBE) { pointer in
            body[offset..<offset+8].copyBytes(to: pointer)
        }
        let clientSid = UInt64(bigEndian: clientSidBE)
        guard clientSid == sessionID else {
            throw ShadowsocksError.decryptionFailed
        }
        offset += 8

        guard body.endIndex - offset >= 2 else { throw ShadowsocksError.decryptionFailed }
        let paddingLen = Int(UInt16(body[offset]) << 8 | UInt16(body[offset + 1]))
        offset += 2
        offset += paddingLen

        guard let parsed = ShadowsocksProtocol.decodeUDPPacket(data: Data(body[offset...])) else {
            throw ShadowsocksError.invalidAddress
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

private func ssAESECBEncryptBlock(key: Data, block: Data) throws -> Data {
    guard block.count == 16 else { throw ShadowsocksError.decryptionFailed }
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
    guard status == kCCSuccess else { throw ShadowsocksError.decryptionFailed }
    return Data(outBytes.prefix(16))
}

private func ssAESECBDecryptBlock(key: Data, block: Data) throws -> Data {
    guard block.count == 16 else { throw ShadowsocksError.decryptionFailed }
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
    guard status == kCCSuccess else { throw ShadowsocksError.decryptionFailed }
    return Data(outBytes.prefix(16))
}
