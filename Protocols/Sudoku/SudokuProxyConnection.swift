//
//  SudokuProxyConnection.swift
//  Anywhere
//
//  Native Swift Sudoku outbound. Transport, HTTPMask, KIP, record AEAD, UoT,
//  mux, table codecs, and key recovery are implemented with platform crypto
//  and the existing Anywhere TLS stack.
//

import Foundation
import Darwin
import CryptoKit
import Security

private let sudokuLogger = AnywhereLogger(category: "Sudoku")
private let sudokuObfsReadChunkSize = 128 * 1024
private let sudokuTCPReceiveChunkSize = 64 * 1024
private let sudokuHTTPMaskMaxQueueBytes = 4 * 1024 * 1024
private let sudokuHTTPMaskMaxPollLineBytes = 256 * 1024
private let sudokuMuxMaxQueueBytes = 4 * 1024 * 1024

private enum SudokuHTTPMaskAuth {
    static func token(key: String, mode: String, method: String, path: String) -> String {
        var keyMaterial = Data("sudoku-httpmask-auth-v1:".utf8)
        keyMaterial.append(Data(key.utf8))
        let authKey = SudokuNativeCrypto.sha256(keyMaterial)
        var ts = UInt64(Date().timeIntervalSince1970).bigEndian
        let tsData = Data(bytes: &ts, count: 8)
        let zero = Data([0])
        let mac = SudokuNativeCrypto.hmacSHA256(
            key: authKey,
            parts: [Data(mode.utf8), zero, Data(method.utf8), zero, Data(path.utf8), zero, tsData]
        )
        var payload = tsData
        payload.append(mac.prefix(16))
        return payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

private struct SudokuDataQueue {
    private var storage = Data()
    private var offset = 0

    var count: Int { storage.count - offset }
    var isEmpty: Bool { count == 0 }

    mutating func append(_ data: Data) {
        guard !data.isEmpty else { return }
        compactBeforeAppend(additionalCount: data.count)
        storage.append(data)
    }

    mutating func read(max: Int) -> Data {
        let n = min(max, count)
        guard n > 0 else { return Data() }
        let start = offset
        offset += n
        let out = storage.subdata(in: start..<(start + n))
        compactAfterRead()
        return out
    }

    mutating func removeAll(keepingCapacity: Bool = false) {
        storage.removeAll(keepingCapacity: keepingCapacity)
        offset = 0
    }

    private mutating func compactBeforeAppend(additionalCount: Int) {
        if offset == 0 { return }
        if offset == storage.count {
            storage.removeAll(keepingCapacity: true)
            offset = 0
            return
        }
        if offset > 256 * 1024 || offset + additionalCount > storage.count {
            storage.removeSubrange(0..<offset)
            offset = 0
        }
    }

    private mutating func compactAfterRead() {
        if offset == storage.count {
            storage.removeAll(keepingCapacity: true)
            offset = 0
        } else if offset > 512 * 1024 && offset * 2 > storage.count {
            storage.removeSubrange(0..<offset)
            offset = 0
        }
    }
}

enum SudokuNativeError: Error, LocalizedError {
    case invalidConfiguration(String)
    case connectionFailed(String)
    case protocolError(String)
    case closed

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let message): return "Invalid Sudoku configuration: \(message)"
        case .connectionFailed(let message): return "Sudoku connection failed: \(message)"
        case .protocolError(let message): return "Sudoku protocol error: \(message)"
        case .closed: return "Sudoku connection closed"
        }
    }
}

private enum SudokuNativeCrypto {
    static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw SudokuNativeError.connectionFailed("random generator failed") }
        return data
    }

    static func randomNonZeroUInt32() throws -> UInt32 {
        while true {
            let bytes = [UInt8](try randomData(count: 4))
            let value = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            if value != 0 && value != UInt32.max { return value }
        }
    }

    static func randomNonZeroUInt64() throws -> UInt64 {
        while true {
            let bytes = [UInt8](try randomData(count: 8))
            let value = bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            if value != 0 && value != UInt64.max { return value }
        }
    }

    static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }
    static func sha256(_ string: String) -> Data { sha256(Data(string.utf8)) }

    static func hmacSHA256(key: Data, parts: [Data]) -> Data {
        var auth = HMAC<SHA256>(key: SymmetricKey(data: key))
        for part in parts { auth.update(data: part) }
        return Data(auth.finalize())
    }

    static func hkdfExpand(prk: Data, info: String, count: Int) -> Data {
        var produced = Data()
        var t = Data()
        var counter: UInt8 = 1
        while produced.count < count {
            var parts: [Data] = []
            if !t.isEmpty { parts.append(t) }
            parts.append(Data(info.utf8))
            parts.append(Data([counter]))
            t = hmacSHA256(key: prk, parts: parts)
            produced.append(t.prefix(count - produced.count))
            counter &+= 1
        }
        return produced
    }

    static func hkdfExtract(salt: Data, ikm: Data) -> Data {
        hmacSHA256(key: salt, parts: [ikm])
    }

    static func pskBases(_ psk: String) -> (c2s: Data, s2c: Data) {
        let sum = sha256(psk)
        return (
            hkdfExpand(prk: sum, info: "sudoku-psk-c2s", count: 32),
            hkdfExpand(prk: sum, info: "sudoku-psk-s2c", count: 32)
        )
    }

    static func sessionBases(psk: String, shared: Data, nonce: Data) -> (c2s: Data, s2c: Data) {
        let salt = sha256(psk)
        var ikm = Data()
        ikm.append(shared)
        ikm.append(nonce)
        let prk = hkdfExtract(salt: salt, ikm: ikm)
        return (
            hkdfExpand(prk: prk, info: "sudoku-session-c2s", count: 32),
            hkdfExpand(prk: prk, info: "sudoku-session-s2c", count: 32)
        )
    }

    static func recordEpochKey(base: Data, method: SudokuAEADMethod, epoch: UInt32) -> Data {
        var epochBE = epoch.bigEndian
        let epochData = Data(bytes: &epochBE, count: 4)
        let methodName = method == .aes128GCM ? "aes-128-gcm" : "chacha20-poly1305"
        return hmacSHA256(key: base, parts: [Data("sudoku-record:".utf8), Data(methodName.utf8), epochData])
    }

    static func seal(method: SudokuAEADMethod, key: Data, nonce: Data, plaintext: Data, aad: Data) throws -> Data {
        switch method {
        case .aes128GCM:
            let box = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: key.prefix(16)),
                nonce: AES.GCM.Nonce(data: nonce),
                authenticating: aad
            )
            var out = Data(box.ciphertext)
            out.append(box.tag)
            return out
        case .chacha20Poly1305:
            let box = try ChaChaPoly.seal(
                plaintext,
                using: SymmetricKey(data: key.prefix(32)),
                nonce: ChaChaPoly.Nonce(data: nonce),
                authenticating: aad
            )
            var out = Data(box.ciphertext)
            out.append(box.tag)
            return out
        case .none:
            return plaintext
        }
    }

    static func open(method: SudokuAEADMethod, key: Data, nonce: Data, ciphertext: Data, aad: Data) throws -> Data {
        switch method {
        case .aes128GCM:
            guard ciphertext.count >= 16 else { throw SudokuNativeError.protocolError("short AES-GCM frame") }
            let split = ciphertext.count - 16
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext.prefix(split),
                tag: ciphertext.suffix(16)
            )
            return try AES.GCM.open(box, using: SymmetricKey(data: key.prefix(16)), authenticating: aad)
        case .chacha20Poly1305:
            guard ciphertext.count >= 16 else { throw SudokuNativeError.protocolError("short ChaCha20-Poly1305 frame") }
            let split = ciphertext.count - 16
            let box = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: nonce),
                ciphertext: ciphertext.prefix(split),
                tag: ciphertext.suffix(16)
            )
            return try ChaChaPoly.open(box, using: SymmetricKey(data: key.prefix(32)), authenticating: aad)
        case .none:
            return ciphertext
        }
    }
}

final class SudokuNativeConfig {
    let serverHost: String
    let serverPort: UInt16
    let key: String
    let privateKey: Data?
    let aeadMethod: SudokuAEADMethod
    let paddingMin: Int32
    let paddingMax: Int32
    let asciiMode: String
    let customTables: [String]
    let selectedCustomTable: String
    let sendsTableHint: Bool
    let pureDownlink: Bool
    let httpMask: SudokuHTTPMaskConfiguration

    init(configuration: ProxyConfiguration) throws {
        guard let sudoku = configuration.sudoku else {
            throw SudokuNativeError.invalidConfiguration("missing protocol settings")
        }
        self.serverHost = configuration.serverAddress
        self.serverPort = configuration.serverPort
        self.aeadMethod = sudoku.aeadMethod
        self.paddingMin = Int32(sudoku.paddingMin)
        self.paddingMax = Int32(sudoku.paddingMax)
        self.asciiMode = sudoku.asciiMode.rawValue
        self.customTables = sudoku.customTables
        if sudoku.customTables.isEmpty {
            self.selectedCustomTable = ""
            self.sendsTableHint = false
        } else {
            let index: Int
            if sudoku.customTables.count == 1 {
                index = 0
            } else {
                index = Int(try SudokuNativeCrypto.randomData(count: 1)[0]) % sudoku.customTables.count
            }
            self.selectedCustomTable = sudoku.customTables[index]
            self.sendsTableHint = sudoku.customTables.count > 1
        }
        self.pureDownlink = sudoku.enablePureDownlink
        self.httpMask = sudoku.httpMask

        if let raw = Data(hexString: sudoku.key), raw.count == 32 || raw.count == 64 {
            self.privateKey = raw
        } else {
            self.privateKey = nil
        }
        self.key = SudokuKeyRecovery.recoverPublicKeyHex(sudoku.key) ?? sudoku.key
    }

    var nativeMuxEnabled: Bool {
        // Native Sudoku mux currently corrupts or closes large downlink
        // streams on some servers. Keep parsing/exporting the setting, but
        // route app TCP through the regular Sudoku TCP command until the mux
        // record path is reliable under sustained traffic.
        false
    }
}

private struct SudokuTableCacheKey: Hashable {
    let key: String
    let asciiMode: String
    let customTable: String
}

private enum SudokuTableCache {
    private static let lock = UnfairLock()
    private static let maxEntries = 8
    private static var pairs: [SudokuTableCacheKey: SudokuTablePair] = [:]
    private static var accessOrder: [SudokuTableCacheKey] = []

    static func pair(for config: SudokuNativeConfig) throws -> SudokuTablePair {
        let cacheKey = SudokuTableCacheKey(
            key: config.key,
            asciiMode: config.asciiMode,
            customTable: config.selectedCustomTable
        )
        return try lock.withLock {
            if let pair = pairs[cacheKey] {
                touch(cacheKey)
                return pair
            }

            let pair = try SudokuTablePair(
                key: config.key,
                asciiMode: config.asciiMode,
                customUplink: config.selectedCustomTable,
                customDownlink: config.selectedCustomTable
            )
            pairs[cacheKey] = pair
            touch(cacheKey)
            trimIfNeeded()
            return pair
        }
    }

    private static func touch(_ key: SudokuTableCacheKey) {
        accessOrder.removeAll { $0 == key }
        accessOrder.append(key)
    }

    private static func trimIfNeeded() {
        while accessOrder.count > maxEntries, let evicted = accessOrder.first {
            accessOrder.removeFirst()
            pairs.removeValue(forKey: evicted)
        }
    }
}

final class SudokuTables {
    private let pair: SudokuTablePair
    private let lock = UnfairLock()
    let sendsTableHint: Bool

    init(config: SudokuNativeConfig) throws {
        sendsTableHint = config.sendsTableHint
        pair = try SudokuTableCache.pair(for: config)
    }

    func withUplink<T>(_ body: (SudokuTable) throws -> T) rethrows -> T {
        try lock.withLock { try body(pair.uplink) }
    }

    func withDownlink<T>(_ body: (SudokuTable) throws -> T) rethrows -> T {
        try lock.withLock { try body(pair.downlink) }
    }

    var hint: UInt32 { lock.withLock { pair.uplink.hint } }
}

final class BlockingProxyStream {
    private let connection: ProxyConnection
    private let stateLock = UnfairLock()
    private let readLock = UnfairLock()
    private let writeLock = UnfairLock()
    private var pending = SudokuDataQueue()
    private var closed = false

    init(connection: ProxyConnection) { self.connection = connection }

    func sendAll(_ data: Data) throws {
        if data.isEmpty { return }
        try writeLock.withLock {
            if isClosed { throw SudokuNativeError.closed }
            let sema = DispatchSemaphore(value: 0)
            var sentError: Error?
            connection.sendRaw(data: data) { error in
                sentError = error
                sema.signal()
            }
            sema.wait()
            if let sentError { throw sentError }
        }
    }

    func readSome(max: Int) throws -> Data {
        try readLock.withLock {
            if !pending.isEmpty {
                return pending.read(max: max)
            }
            if isClosed { throw SudokuNativeError.closed }
            let sema = DispatchSemaphore(value: 0)
            var resultData: Data?
            var resultError: Error?
            connection.receiveRaw { data, error in
                resultData = data
                resultError = error
                sema.signal()
            }
            sema.wait()
            if let resultError { throw resultError }
            guard let data = resultData, !data.isEmpty else {
                markClosed()
                throw SudokuNativeError.closed
            }
            if data.count > max {
                pending.append(data.dropFirst(max))
                return Data(data.prefix(max))
            }
            return data
        }
    }

    func readExact(_ count: Int) throws -> Data {
        var out = Data(capacity: count)
        while out.count < count {
            out.append(try readSome(max: count - out.count))
        }
        return out
    }

    func cancel() {
        markClosed()
        connection.cancel()
    }

    private var isClosed: Bool {
        stateLock.withLock { closed }
    }

    private func markClosed() {
        stateLock.withLock { closed = true }
    }
}

final class SudokuConnectionFactory {
    private let configuration: ProxyConfiguration
    private let directDialHost: String
    private let stateLock = UnfairLock()
    private var initialTunnel: ProxyConnection?
    private var retainedClients: [ProxyClient] = []
    private var retainedTLSClients: [TLSClient] = []
    private var retainedRawSockets: [RawTCPSocket] = []
    private var connections: [ProxyConnection] = []
    private var closed = false

    init(configuration: ProxyConfiguration, initialTunnel: ProxyConnection?, directDialHost: String) {
        self.configuration = configuration
        self.initialTunnel = initialTunnel
        self.directDialHost = directDialHost
    }

    func open(host: String, port: UInt16, useTLS: Bool, serverName: String?) throws -> BlockingProxyStream {
        if stateLock.withLock({ closed }) { throw SudokuNativeError.closed }
        let sema = DispatchSemaphore(value: 0)
        var result: Result<ProxyConnection, Error>!
        openProxyConnection(host: host, port: port, useTLS: useTLS, serverName: serverName) { openResult in
            result = openResult
            sema.signal()
        }
        if sema.wait(timeout: .now() + 30) == .timedOut {
            throw SudokuNativeError.connectionFailed("timeout opening transport")
        }
        let connection = try result.get()
        guard retainConnection(connection) else {
            connection.cancel()
            throw SudokuNativeError.closed
        }
        return BlockingProxyStream(connection: connection)
    }

    func openWebSocket(
        host: String,
        port: UInt16,
        useTLS: Bool,
        serverName: String?,
        hostHeader: String,
        path: String,
        headers: [String: String]
    ) throws -> BlockingProxyStream {
        if stateLock.withLock({ closed }) { throw SudokuNativeError.closed }
        let sema = DispatchSemaphore(value: 0)
        var result: Result<ProxyConnection, Error>!
        openProxyConnection(host: host, port: port, useTLS: useTLS, serverName: serverName) { openResult in
            result = openResult
            sema.signal()
        }
        if sema.wait(timeout: .now() + 30) == .timedOut {
            throw SudokuNativeError.connectionFailed("timeout opening WebSocket transport")
        }
        let base = try result.get()
        guard retainConnection(base) else {
            base.cancel()
            throw SudokuNativeError.closed
        }
        let ws = WebSocketConnection(
            tunnel: base,
            configuration: WebSocketConfiguration(
                host: hostHeader,
                path: path,
                headers: headers,
                heartbeatPeriod: 30
            )
        )
        let upgrade = DispatchSemaphore(value: 0)
        var upgradeError: Error?
        ws.performUpgrade { error in
            upgradeError = error
            upgrade.signal()
        }
        if upgrade.wait(timeout: .now() + 30) == .timedOut {
            releaseConnection(base)
            base.cancel()
            throw SudokuNativeError.connectionFailed("timeout upgrading WebSocket transport")
        }
        if let upgradeError {
            releaseConnection(base)
            base.cancel()
            throw upgradeError
        }
        let connection = WebSocketProxyConnection(wsConnection: ws)
        guard replaceConnection(base, with: connection) else {
            connection.cancel()
            throw SudokuNativeError.closed
        }
        return BlockingProxyStream(connection: connection)
    }

    func closeAll() {
        let toClose: [ProxyConnection]
        let clients: [ProxyClient]
        let tlsClients: [TLSClient]
        let rawSockets: [RawTCPSocket]
        stateLock.lock()
        if closed {
            stateLock.unlock()
            return
        }
        closed = true
        toClose = connections + (initialTunnel.map { [$0] } ?? [])
        clients = retainedClients
        tlsClients = retainedTLSClients
        rawSockets = retainedRawSockets
        connections.removeAll()
        retainedClients.removeAll()
        retainedTLSClients.removeAll()
        retainedRawSockets.removeAll()
        initialTunnel = nil
        stateLock.unlock()
        for connection in toClose { connection.cancel() }
        for client in clients { client.cancel() }
        for client in tlsClients { client.cancel() }
        for socket in rawSockets { socket.forceCancel() }
    }

    private func openProxyConnection(
        host: String,
        port: UInt16,
        useTLS: Bool,
        serverName: String?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if let tunnel = stateLock.withLock({ () -> ProxyConnection? in
            let current = initialTunnel
            initialTunnel = nil
            return current
        }) {
            completion(.success(tunnel))
            return
        }

        if let chain = configuration.chain, !chain.isEmpty {
            buildChainTunnel(chain: chain, index: 0, currentTunnel: nil, targetHost: host, targetPort: port, completion: completion)
            return
        }

        if useTLS {
            let tls = TLSClient(configuration: TLSConfiguration(serverName: serverName ?? host, alpn: ["http/1.1"]))
            guard retainTLSClient(tls) else {
                completion(.failure(SudokuNativeError.closed))
                return
            }
            tls.connect(host: directDialHost, port: port) { result in
                self.releaseTLSClient(tls)
                switch result {
                case .success(let conn): completion(.success(TLSProxyConnection(tlsConnection: conn)))
                case .failure(let error): completion(.failure(error))
                }
            }
            return
        }

        let socket = RawTCPSocket()
        guard retainRawSocket(socket) else {
            completion(.failure(SudokuNativeError.closed))
            return
        }
        socket.connect(host: directDialHost, port: port) { error in
            self.releaseRawSocket(socket)
            if let error { completion(.failure(error)) }
            else { completion(.success(DirectProxyConnection(connection: socket))) }
        }
    }

    private func buildChainTunnel(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        targetHost: String,
        targetPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let chainConfig = chain[index]
        let nextHost: String
        let nextPort: UInt16
        if index + 1 < chain.count {
            nextHost = chain[index + 1].serverAddress
            nextPort = chain[index + 1].serverPort
        } else {
            nextHost = targetHost
            nextPort = targetPort
        }

        let client = ProxyClient(configuration: chainConfig, tunnel: currentTunnel)
        guard retainClient(client) else {
            currentTunnel?.cancel()
            completion(.failure(SudokuNativeError.closed))
            return
        }
        client.connect(to: nextHost, port: nextPort) { [weak self] result in
            switch result {
            case .success(let connection):
                if index + 1 < chain.count {
                    self?.buildChainTunnel(chain: chain, index: index + 1, currentTunnel: connection, targetHost: targetHost, targetPort: targetPort, completion: completion)
                } else {
                    completion(.success(connection))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }

    private func retainClient(_ client: ProxyClient) -> Bool {
        stateLock.withLock {
            guard !closed else { return false }
            retainedClients.append(client)
            return true
        }
    }

    private func retainTLSClient(_ client: TLSClient) -> Bool {
        stateLock.withLock {
            guard !closed else { return false }
            retainedTLSClients.append(client)
            return true
        }
    }

    private func releaseTLSClient(_ client: TLSClient) {
        stateLock.withLock {
            retainedTLSClients.removeAll { $0 === client }
        }
    }

    private func retainRawSocket(_ socket: RawTCPSocket) -> Bool {
        stateLock.withLock {
            guard !closed else { return false }
            retainedRawSockets.append(socket)
            return true
        }
    }

    private func releaseRawSocket(_ socket: RawTCPSocket) {
        stateLock.withLock {
            retainedRawSockets.removeAll { $0 === socket }
        }
    }

    private func retainConnection(_ connection: ProxyConnection) -> Bool {
        stateLock.withLock {
            guard !closed else { return false }
            connections.append(connection)
            return true
        }
    }

    private func replaceConnection(_ old: ProxyConnection, with new: ProxyConnection) -> Bool {
        stateLock.withLock {
            connections.removeAll { $0 === old }
            guard !closed else { return false }
            connections.append(new)
            return true
        }
    }

    private func releaseConnection(_ connection: ProxyConnection) {
        stateLock.withLock {
            connections.removeAll { $0 === connection }
        }
    }
}

private final class SudokuHTTPBodyReader {
    let stream: BlockingProxyStream
    let status: Int
    let chunked: Bool
    let closeDelimited: Bool
    var contentRemaining: Int
    var chunkRemaining = 0
    var done = false

    init(stream: BlockingProxyStream, status: Int, chunked: Bool, contentLength: Int?) {
        self.stream = stream
        self.status = status
        self.chunked = chunked
        self.contentRemaining = contentLength ?? 0
        self.closeDelimited = !chunked && contentLength == nil
    }

    func readSome(max: Int = 32 * 1024) throws -> Data {
        if done { return Data() }
        if chunked {
            while chunkRemaining == 0 {
                let line = try readLine()
                let lenText = line.split(separator: ";", maxSplits: 1).first.map(String.init) ?? line
                guard let len = Int(lenText.trimmingCharacters(in: .whitespacesAndNewlines), radix: 16) else {
                    throw SudokuNativeError.protocolError("bad chunk length")
                }
                if len == 0 {
                    repeat { if try readLine().isEmpty { break } } while true
                    done = true
                    return Data()
                }
                chunkRemaining = len
            }
            let n = min(max, chunkRemaining)
            let data = try stream.readExact(n)
            chunkRemaining -= n
            if chunkRemaining == 0 { _ = try stream.readExact(2) }
            return data
        }
        if !closeDelimited {
            if contentRemaining == 0 {
                done = true
                return Data()
            }
            let n = min(max, contentRemaining)
            let data = try stream.readExact(n)
            contentRemaining -= n
            if contentRemaining == 0 { done = true }
            return data
        }
        do { return try stream.readSome(max: max) }
        catch { done = true; return Data() }
    }

    func readAll(limit: Int) throws -> Data {
        var out = Data()
        while out.count < limit {
            let part = try readSome(max: min(4096, limit - out.count))
            if part.isEmpty { break }
            out.append(part)
        }
        return out
    }

    private func readLine() throws -> String {
        var data = Data()
        while true {
            let b = try stream.readExact(1)[0]
            if b == 0x0a { break }
            if b != 0x0d { data.append(b) }
            if data.count > 8192 { throw SudokuNativeError.protocolError("HTTP line too long") }
        }
        return String(data: data, encoding: .utf8) ?? ""
    }
}

final class SudokuHTTPMaskTransport {
    private let config: SudokuNativeConfig
    private let factory: SudokuConnectionFactory
    private let mode: SudokuHTTPMaskMode
    private let condition = NSCondition()
    private var rxQueue = SudokuDataQueue()
    private var txQueue = SudokuDataQueue()
    private var closed = false
    private var fatal = false
    private var token = ""
    private var pullPath = ""
    private var pushPath = ""
    private var closePath = ""
    private let earlyRequestPayload: Data?
    private(set) var earlyResponsePayload = Data()

    init(config: SudokuNativeConfig, factory: SudokuConnectionFactory, mode: SudokuHTTPMaskMode, earlyRequestPayload: Data? = nil) throws {
        self.config = config
        self.factory = factory
        self.mode = mode
        self.earlyRequestPayload = earlyRequestPayload?.isEmpty == false ? earlyRequestPayload : nil
        try authorize()
        DispatchQueue.global(qos: .userInitiated).async { self.pullLoop() }
        DispatchQueue.global(qos: .userInitiated).async { self.pushLoop() }
    }

    func send(_ data: Data) throws {
        condition.lock()
        defer { condition.unlock() }
        if closed { throw SudokuNativeError.closed }
        let queueLimit = max(sudokuHTTPMaskMaxQueueBytes, data.count)
        while txQueue.count + data.count > queueLimit && !closed {
            condition.wait()
        }
        if closed { throw SudokuNativeError.closed }
        txQueue.append(data)
        condition.signal()
    }

    func receive(max: Int) throws -> Data {
        condition.lock()
        defer { condition.unlock() }
        while rxQueue.isEmpty && !closed { condition.wait() }
        if rxQueue.isEmpty && closed { throw fatal ? SudokuNativeError.connectionFailed("HTTPMask closed") : SudokuNativeError.closed }
        let out = rxQueue.read(max: max)
        if rxQueue.isEmpty { rxQueue.removeAll(keepingCapacity: false) }
        condition.signal()
        return out
    }

    func close() {
        markClosed(fatal: false)
        if !closePath.isEmpty, let opened = try? request(method: "POST", requestPath: closePath, authPath: "/api/v1/upload", body: Data()) {
            _ = try? opened.body.readAll(limit: 256)
        }
    }

    private var hostHeader: String {
        let host = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
        if (config.httpMask.tls && config.serverPort == 443) || (!config.httpMask.tls && config.serverPort == 80) { return host }
        return "\(host):\(config.serverPort)"
    }

    private func applyPathRoot(_ path: String) -> String {
        let clean = config.httpMask.pathRoot.filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
        return clean.isEmpty ? path : "/\(clean)\(path)"
    }

    private func authToken(mode: String, method: String, path: String) -> String {
        SudokuHTTPMaskAuth.token(key: config.key, mode: mode, method: method, path: path)
    }

    private func appendAuth(_ path: String, token: String) -> String {
        path + (path.contains("?") ? "&" : "?") + "auth=\(token)"
    }

    private func appendEarlyData(_ path: String, payload: Data?) -> String {
        guard let payload, !payload.isEmpty else { return path }
        let encoded = payload.base64URLEncodedString()
        return path + (path.contains("?") ? "&" : "?") + "ed=\(encoded)"
    }

    private func request(method: String, requestPath: String, authPath: String, contentType: String? = nil, body: Data) throws -> (stream: BlockingProxyStream, body: SudokuHTTPBodyReader) {
        let stream = try factory.open(host: config.serverHost, port: config.serverPort, useTLS: config.httpMask.tls, serverName: config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host)
        let modeName = mode == .poll ? "poll" : "stream"
        let auth = authToken(mode: modeName, method: method, path: authPath)
        let path = appendAuth(requestPath, token: auth)
        var req = "\(method) \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\nUser-Agent: \(ProxyUserAgent.chrome)\r\nAccept: */*\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: close\r\nX-Sudoku-Tunnel: \(modeName)\r\nAuthorization: Bearer \(auth)\r\n"
        if let contentType { req += "Content-Type: \(contentType)\r\n" }
        req += "Content-Length: \(body.count)\r\n\r\n"
        var data = Data(req.utf8)
        data.append(body)
        try stream.sendAll(data)
        let reader = try readHeaders(stream: stream)
        return (stream, reader)
    }

    private func readHeaders(stream: BlockingProxyStream) throws -> SudokuHTTPBodyReader {
        func line() throws -> String {
            var data = Data()
            while true {
                let b = try stream.readExact(1)[0]
                if b == 0x0a { break }
                if b != 0x0d { data.append(b) }
            }
            return String(data: data, encoding: .utf8) ?? ""
        }
        let statusLine = try line()
        let parts = statusLine.split(separator: " ")
        guard parts.count >= 2, let status = Int(parts[1]) else { throw SudokuNativeError.protocolError("bad HTTP response") }
        var chunked = false
        var contentLength: Int?
        while true {
            let header = try line()
            if header.isEmpty { break }
            let lower = header.lowercased()
            if lower.hasPrefix("transfer-encoding:") && lower.contains("chunked") { chunked = true }
            if lower.hasPrefix("content-length:"), let value = Int(header.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)) { contentLength = value }
        }
        return SudokuHTTPBodyReader(stream: stream, status: status, chunked: chunked, contentLength: contentLength)
    }

    private func authorize() throws {
        let sessionPath = applyPathRoot("/session")
        let opened = try request(method: "GET", requestPath: appendEarlyData(sessionPath, payload: earlyRequestPayload), authPath: "/session", body: Data())
        guard opened.body.status == 200 else { throw SudokuNativeError.connectionFailed("HTTPMask authorize status \(opened.body.status)") }
        let body = try opened.body.readAll(limit: 4096)
        guard let text = String(data: body, encoding: .utf8), let range = text.range(of: "token=") else {
            throw SudokuNativeError.connectionFailed("HTTPMask authorize missing token")
        }
        let tail = text[range.upperBound...]
        token = String(tail.prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
        guard !token.isEmpty else { throw SudokuNativeError.connectionFailed("HTTPMask empty token") }
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.hasPrefix("ed=") else { continue }
            let encoded = String(trimmed.dropFirst(3))
            if let decoded = Data(base64URLEncoded: encoded) {
                earlyResponsePayload = decoded
            }
            break
        }
        let streamPath = applyPathRoot("/stream")
        let uploadPath = applyPathRoot("/api/v1/upload")
        pullPath = "\(streamPath)?token=\(token)"
        pushPath = "\(uploadPath)?token=\(token)"
        closePath = "\(pushPath)&close=1"
    }

    private func markClosed(fatal: Bool) {
        condition.lock()
        self.fatal = self.fatal || fatal
        closed = true
        condition.broadcast()
        condition.unlock()
    }

    private func pullLoop() {
        while true {
            condition.lock(); let shouldStop = closed; condition.unlock()
            if shouldStop { return }
            do {
                let opened = try request(method: "GET", requestPath: pullPath, authPath: "/stream", body: Data())
                guard opened.body.status == 200 else { throw SudokuNativeError.connectionFailed("HTTPMask pull status \(opened.body.status)") }
                var sawAny = false
                var pollLine = Data()
                while true {
                    let data = try opened.body.readSome()
                    if data.isEmpty { break }
                    sawAny = true
                    if mode == .poll {
                        for byte in data where byte != 0x0d {
                            if byte == 0x0a {
                                if !pollLine.isEmpty {
                                    if let decoded = Data(base64Encoded: String(data: pollLine, encoding: .ascii) ?? "") { enqueueRX(decoded) }
                                    pollLine.removeAll()
                                }
                            } else {
                                pollLine.append(byte)
                                if pollLine.count > sudokuHTTPMaskMaxPollLineBytes {
                                    throw SudokuNativeError.protocolError("HTTPMask poll line too long")
                                }
                            }
                        }
                    } else {
                        enqueueRX(data)
                    }
                }
                if !sawAny { usleep(25_000) }
            } catch {
                markClosed(fatal: true)
                return
            }
        }
    }

    private func enqueueRX(_ data: Data) {
        condition.lock()
        let queueLimit = max(sudokuHTTPMaskMaxQueueBytes, data.count)
        while rxQueue.count + data.count > queueLimit && !closed {
            condition.wait()
        }
        if !closed {
            rxQueue.append(data)
            condition.signal()
        }
        condition.unlock()
    }

    private func pushLoop() {
        let cap = mode == .poll ? 49_152 : 262_144
        while true {
            let batch: Data
            condition.lock()
            while txQueue.isEmpty && !closed {
                condition.wait(until: Date().addingTimeInterval(0.005))
                if !txQueue.isEmpty || closed { break }
            }
            if txQueue.isEmpty && closed { condition.unlock(); return }
            let n = min(cap, txQueue.count)
            batch = txQueue.read(max: n)
            if txQueue.isEmpty { txQueue.removeAll(keepingCapacity: false) }
            condition.signal()
            condition.unlock()

            do {
                let body: Data
                let contentType: String
                if mode == .poll {
                    var encoded = Data(batch.base64EncodedString().utf8)
                    encoded.append(0x0a)
                    body = encoded
                    contentType = "text/plain"
                } else {
                    body = batch
                    contentType = "application/octet-stream"
                }
                let opened = try request(method: "POST", requestPath: pushPath, authPath: "/api/v1/upload", contentType: contentType, body: body)
                _ = try opened.body.readAll(limit: 256)
                guard opened.body.status == 200 else { throw SudokuNativeError.connectionFailed("HTTPMask push status \(opened.body.status)") }
            } catch {
                markClosed(fatal: true)
                return
            }
        }
    }
}

final class SudokuObfsTransport {
    enum Wire {
        case stream(BlockingProxyStream)
        case httpMask(SudokuHTTPMaskTransport)
    }

    private let wire: Wire
    private let tables: SudokuTables
    private var rng: SudokuSplitMix64
    private var threshold: UInt64 = 0
    private var pureDecoder = SudokuPureDecoder()
    private var packedDecoder: SudokuPackedDecoder
    private let pureDownlink: Bool
    private var plainBuffer = SudokuDataQueue()
    private let readLock = UnfairLock()
    private let writeLock = UnfairLock()

    init(wire: Wire, tables: SudokuTables, config: SudokuNativeConfig) throws {
        self.wire = wire
        self.tables = tables
        self.pureDownlink = config.pureDownlink
        let seedBytes = [UInt8](try SudokuNativeCrypto.randomData(count: 8))
        let seed = Int64(bitPattern: seedBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) })
        var seeded = SudokuSplitMix64(seed: seed)
        threshold = seeded.pickPaddingThreshold(min: config.paddingMin, max: config.paddingMax)
        rng = seeded
        packedDecoder = tables.withDownlink { SudokuPackedDecoder(table: $0) }
    }

    func send(_ data: Data) throws {
        try writeLock.withLock {
            let encoded = tables.withUplink { $0.encode(data, rng: &rng, paddingThreshold: threshold) }
            try sendWire(encoded)
        }
    }

    func receive(max: Int) throws -> Data {
        try readLock.withLock {
            if !plainBuffer.isEmpty {
                return plainBuffer.read(max: max)
            }
            let pending = try drainDecoderPending(max: max)
            if !pending.isEmpty {
                return pending
            }
            while true {
                let wireData = try receiveWire(max: sudokuObfsReadChunkSize)
                let out = try tables.withDownlink { table -> Data in
                    if pureDownlink {
                        return try pureDecoder.decode(wireData, table: table, limit: 65536)
                    }
                    return try packedDecoder.decode(wireData, table: table, limit: 65536)
                }
                if out.isEmpty { continue }
                if out.count > max {
                    plainBuffer.append(out.dropFirst(max))
                    return Data(out.prefix(max))
                }
                return out
            }
        }
    }

    func readExact(_ count: Int) throws -> Data {
        var out = Data(capacity: count)
        while out.count < count { out.append(try receive(max: count - out.count)) }
        return out
    }

    func close() {
        switch wire {
        case .stream(let stream): stream.cancel()
        case .httpMask(let mask): mask.close()
        }
    }

    private func sendWire(_ data: Data) throws {
        switch wire {
        case .stream(let stream): try stream.sendAll(data)
        case .httpMask(let mask): try mask.send(data)
        }
    }

    private func receiveWire(max: Int) throws -> Data {
        switch wire {
        case .stream(let stream): return try stream.readSome(max: max)
        case .httpMask(let mask): return try mask.receive(max: max)
        }
    }

    private func drainDecoderPending(max: Int) throws -> Data {
        try tables.withDownlink { table -> Data in
            if pureDownlink {
                return try pureDecoder.decode(Data(), table: table, limit: max)
            }
            return try packedDecoder.decode(Data(), table: table, limit: max)
        }
    }
}

final class SudokuRecordStream {
    private let transport: SudokuObfsTransport
    private var method: SudokuAEADMethod
    private var baseSend: Data
    private var baseRecv: Data
    private var sendEpoch: UInt32
    private var sendSeq: UInt64
    private var sendBytes: Int64 = 0
    private var sendEpochUpdates: UInt32 = 0
    private var recvEpoch: UInt32 = 0
    private var recvSeq: UInt64 = 0
    private var recvInitialized = false
    private var readBuffer = SudokuDataQueue()
    private let readLock = UnfairLock()
    private let writeLock = UnfairLock()

    init(transport: SudokuObfsTransport, method: SudokuAEADMethod, baseSend: Data, baseRecv: Data) throws {
        self.transport = transport
        self.method = method
        self.baseSend = baseSend
        self.baseRecv = baseRecv
        self.sendEpoch = try SudokuNativeCrypto.randomNonZeroUInt32()
        self.sendSeq = try SudokuNativeCrypto.randomNonZeroUInt64()
    }

    func rekey(send: Data, recv: Data) throws {
        try writeLock.withLock {
            try readLock.withLock {
                baseSend = send
                baseRecv = recv
                sendEpoch = try SudokuNativeCrypto.randomNonZeroUInt32()
                sendSeq = try SudokuNativeCrypto.randomNonZeroUInt64()
                sendBytes = 0
                sendEpochUpdates = 0
                recvEpoch = 0
                recvSeq = 0
                recvInitialized = false
                readBuffer.removeAll()
            }
        }
    }

    func send(_ data: Data) throws {
        if data.isEmpty { return }
        try writeLock.withLock {
            if method == .none {
                try transport.send(data)
                return
            }
            var offset = 0
            while offset < data.count {
                let maxPlain = 65535 - 12 - 16
                let count = min(maxPlain, data.count - offset)
                let chunk = data.subdata(in: offset..<(offset + count))
                var header = Data()
                var epochBE = sendEpoch.bigEndian
                var seqBE = sendSeq.bigEndian
                header.append(Data(bytes: &epochBE, count: 4))
                header.append(Data(bytes: &seqBE, count: 8))
                sendSeq &+= 1
                let key = SudokuNativeCrypto.recordEpochKey(base: baseSend, method: method, epoch: sendEpoch)
                let cipher = try SudokuNativeCrypto.seal(method: method, key: key, nonce: header, plaintext: chunk, aad: header)
                var bodyLen = UInt16(header.count + cipher.count).bigEndian
                var frame = Data(bytes: &bodyLen, count: 2)
                frame.append(header)
                frame.append(cipher)
                try transport.send(frame)
                offset += count
                try maybeBumpSendEpoch(added: count)
            }
        }
    }

    func receive(max: Int) throws -> Data {
        try readLock.withLock {
            if !readBuffer.isEmpty {
                return readBuffer.read(max: max)
            }
            if method == .none { return try transport.receive(max: max) }
            while true {
                let lenData = try transport.readExact(2)
                let bodyLen = Int(UInt16(lenData[0]) << 8 | UInt16(lenData[1]))
                guard bodyLen >= 12 && bodyLen <= 65535 else { throw SudokuNativeError.protocolError("bad record length") }
                let body = try transport.readExact(bodyLen)
                let header = body.prefix(12)
                let ciphertext = body.dropFirst(12)
                let epoch = header.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                let seq = header.dropFirst(4).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
                if recvInitialized {
                    if epoch < recvEpoch { throw SudokuNativeError.protocolError("replayed record epoch") }
                    if epoch == recvEpoch && seq != recvSeq { throw SudokuNativeError.protocolError("out of order record") }
                    if epoch > recvEpoch && epoch - recvEpoch > 8 { throw SudokuNativeError.protocolError("record epoch jump") }
                }
                let key = SudokuNativeCrypto.recordEpochKey(base: baseRecv, method: method, epoch: epoch)
                let plain = try SudokuNativeCrypto.open(method: method, key: key, nonce: Data(header), ciphertext: Data(ciphertext), aad: Data(header))
                recvEpoch = epoch
                recvSeq = seq + 1
                recvInitialized = true
                if plain.isEmpty { continue }
                if plain.count > max {
                    readBuffer.append(plain.dropFirst(max))
                    return Data(plain.prefix(max))
                }
                return plain
            }
        }
    }

    func readExact(_ count: Int) throws -> Data {
        var out = Data(capacity: count)
        while out.count < count { out.append(try receive(max: count - out.count)) }
        return out
    }

    func close() { transport.close() }

    private func maybeBumpSendEpoch(added: Int) throws {
        guard method != .none else { return }
        sendBytes += Int64(added)
        let threshold = Int64(32 << 20) * Int64(sendEpochUpdates + 1)
        guard sendBytes >= threshold else { return }
        sendEpoch &+= 1
        sendEpochUpdates &+= 1
        sendSeq = try SudokuNativeCrypto.randomNonZeroUInt64()
    }
}

private struct SudokuKIPClientState {
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    let nonce: Data
}

final class SudokuNativeClient {
    private let config: SudokuNativeConfig
    private let factory: SudokuConnectionFactory
    private let tables: SudokuTables

    init(configuration: ProxyConfiguration, factory: SudokuConnectionFactory) throws {
        self.config = try SudokuNativeConfig(configuration: configuration)
        self.factory = factory
        self.tables = try SudokuTables(config: config)
    }

    var shouldUseNativeMux: Bool { config.nativeMuxEnabled }

    func openTCP(host: String, port: UInt16) throws -> SudokuRecordStream {
        let record = try connectBase()
        try writeKIP(record: record, type: 0x10, payload: SudokuAddress.encode(host: host, port: port))
        return record
    }

    func openUoT() throws -> SudokuRecordStream {
        let record = try connectBase()
        try writeKIP(record: record, type: 0x12, payload: Data())
        return record
    }

    func openMux() throws -> SudokuMuxClient {
        let record = try connectBase()
        try writeKIP(record: record, type: 0x11, payload: Data())
        return SudokuMuxClient(record: record)
    }

    private func connectBase() throws -> SudokuRecordStream {
        let wire: SudokuObfsTransport.Wire
        if !config.httpMask.disable && config.httpMask.mode == .ws {
            wire = .stream(try openHTTPMaskWebSocket())
        } else if !config.httpMask.disable && [SudokuHTTPMaskMode.stream, .poll, .auto].contains(config.httpMask.mode) {
            let early = try buildEarlyHandshakePayload()
            let mask: SudokuHTTPMaskTransport
            if config.httpMask.mode == .poll {
                mask = try SudokuHTTPMaskTransport(config: config, factory: factory, mode: .poll, earlyRequestPayload: early.request)
            } else if config.httpMask.mode == .stream {
                mask = try SudokuHTTPMaskTransport(config: config, factory: factory, mode: .stream, earlyRequestPayload: early.request)
            } else {
                do {
                    mask = try SudokuHTTPMaskTransport(config: config, factory: factory, mode: .stream, earlyRequestPayload: early.request)
                } catch {
                    mask = try SudokuHTTPMaskTransport(config: config, factory: factory, mode: .poll, earlyRequestPayload: early.request)
                }
            }
            wire = .httpMask(mask)
            let transport = try SudokuObfsTransport(wire: wire, tables: tables, config: config)
            if !mask.earlyResponsePayload.isEmpty {
                let session = try completeEarlyHandshake(state: early.state, response: mask.earlyResponsePayload)
                return try SudokuRecordStream(transport: transport, method: config.aeadMethod, baseSend: session.c2s, baseRecv: session.s2c)
            }
            let bases = SudokuNativeCrypto.pskBases(config.key)
            let record = try SudokuRecordStream(transport: transport, method: config.aeadMethod, baseSend: bases.c2s, baseRecv: bases.s2c)
            try performKIP(record: record)
            return record
        } else {
            let stream = try factory.open(host: config.serverHost, port: config.serverPort, useTLS: false, serverName: nil)
            if !config.httpMask.disable && config.httpMask.mode == .legacy {
                let path = config.httpMask.pathRoot.isEmpty ? "/api" : "/\(config.httpMask.pathRoot)/api"
                let host = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
                let req = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 1048576\r\n\r\n"
                try stream.sendAll(Data(req.utf8))
            }
            wire = .stream(stream)
        }

        let transport = try SudokuObfsTransport(wire: wire, tables: tables, config: config)
        let bases = SudokuNativeCrypto.pskBases(config.key)
        let record = try SudokuRecordStream(transport: transport, method: config.aeadMethod, baseSend: bases.c2s, baseRecv: bases.s2c)
        try performKIP(record: record)
        return record
    }

    private func buildEarlyHandshakePayload() throws -> (request: Data, state: SudokuKIPClientState) {
        let (state, payload) = try makeKIPClientHelloPayload()
        let kipFrame = encodeKIP(type: 0x01, payload: payload)
        let bases = SudokuNativeCrypto.pskBases(config.key)
        let recordFrame = try encodeEarlyRecord(plaintext: kipFrame, base: bases.c2s)
        return (try encodeEarlyObfs(recordFrame), state)
    }

    private func completeEarlyHandshake(state: SudokuKIPClientState, response: Data) throws -> (c2s: Data, s2c: Data) {
        let recordData = try decodeEarlyObfs(response)
        let plain = try decodeEarlyRecord(recordData, base: SudokuNativeCrypto.pskBases(config.key).s2c)
        let msg = try parseKIP(plain)
        guard msg.type == 0x02 else { throw SudokuNativeError.protocolError("bad early KIP server hello") }
        return try finishKIP(state: state, message: msg)
    }

    private func encodeEarlyObfs(_ data: Data) throws -> Data {
        let seedBytes = [UInt8](try SudokuNativeCrypto.randomData(count: 8))
        let seed = Int64(bitPattern: seedBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) })
        var rng = SudokuSplitMix64(seed: seed)
        let threshold = rng.pickPaddingThreshold(min: config.paddingMin, max: config.paddingMax)
        return tables.withUplink { $0.encode(data, rng: &rng, paddingThreshold: threshold) }
    }

    private func decodeEarlyObfs(_ data: Data) throws -> Data {
        try tables.withDownlink { table in
            if config.pureDownlink {
                var decoder = SudokuPureDecoder()
                return try decoder.decode(data, table: table, limit: 65536)
            }
            var decoder = SudokuPackedDecoder(table: table)
            return try decoder.decode(data, table: table, limit: 65536)
        }
    }

    private func encodeEarlyRecord(plaintext: Data, base: Data) throws -> Data {
        guard config.aeadMethod != .none else { return plaintext }
        var header = Data()
        var epoch = try SudokuNativeCrypto.randomNonZeroUInt32().bigEndian
        var seq = try SudokuNativeCrypto.randomNonZeroUInt64().bigEndian
        header.append(Data(bytes: &epoch, count: 4))
        header.append(Data(bytes: &seq, count: 8))
        let epochValue = UInt32(bigEndian: epoch)
        let key = SudokuNativeCrypto.recordEpochKey(base: base, method: config.aeadMethod, epoch: epochValue)
        let cipher = try SudokuNativeCrypto.seal(method: config.aeadMethod, key: key, nonce: header, plaintext: plaintext, aad: header)
        var bodyLen = UInt16(header.count + cipher.count).bigEndian
        var out = Data(bytes: &bodyLen, count: 2)
        out.append(header)
        out.append(cipher)
        return out
    }

    private func decodeEarlyRecord(_ data: Data, base: Data) throws -> Data {
        guard config.aeadMethod != .none else { return data }
        var offset = 0
        var out = Data()
        while offset + 2 <= data.count {
            let bodyLen = Int(UInt16(data[offset]) << 8 | UInt16(data[offset + 1]))
            guard bodyLen >= 12 && offset + 2 + bodyLen <= data.count else {
                if out.isEmpty { throw SudokuNativeError.protocolError("bad early record length") }
                break
            }
            let body = data.subdata(in: (offset + 2)..<(offset + 2 + bodyLen))
            let header = body.prefix(12)
            let ciphertext = body.dropFirst(12)
            let epoch = header.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            let key = SudokuNativeCrypto.recordEpochKey(base: base, method: config.aeadMethod, epoch: epoch)
            out.append(try SudokuNativeCrypto.open(method: config.aeadMethod, key: key, nonce: Data(header), ciphertext: Data(ciphertext), aad: Data(header)))
            offset += 2 + bodyLen
            if out.count >= 6 {
                let kipLen = Int(UInt16(out[4]) << 8 | UInt16(out[5]))
                if out.count >= 6 + kipLen { break }
            }
        }
        guard !out.isEmpty else { throw SudokuNativeError.protocolError("short early record") }
        return out
    }

    private func openHTTPMaskWebSocket() throws -> BlockingProxyStream {
        let host = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
        let defaultPort = config.httpMask.tls ? UInt16(443) : UInt16(80)
        let hostHeader = config.serverPort == defaultPort ? host : "\(host):\(config.serverPort)"
        let auth = httpMaskAuthToken(mode: "ws", method: "GET", path: "/ws")
        let path = appendHTTPMaskAuth(applyHTTPMaskPathRoot("/ws"), token: auth)
        return try factory.openWebSocket(
            host: config.serverHost,
            port: config.serverPort,
            useTLS: config.httpMask.tls,
            serverName: host,
            hostHeader: hostHeader,
            path: path,
            headers: [
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "X-Sudoku-Tunnel": "ws",
                "Authorization": "Bearer \(auth)"
            ]
        )
    }

    private func applyHTTPMaskPathRoot(_ path: String) -> String {
        let clean = config.httpMask.pathRoot.filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
        return clean.isEmpty ? path : "/\(clean)\(path)"
    }

    private func appendHTTPMaskAuth(_ path: String, token: String) -> String {
        path + (path.contains("?") ? "&" : "?") + "auth=\(token)"
    }

    private func httpMaskAuthToken(mode: String, method: String, path: String) -> String {
        SudokuHTTPMaskAuth.token(key: config.key, mode: mode, method: method, path: path)
    }

    private func performKIP(record: SudokuRecordStream) throws {
        let (state, payload) = try makeKIPClientHelloPayload()
        try writeKIP(record: record, type: 0x01, payload: payload)
        let msg = try readKIP(record: record)
        let session = try finishKIP(state: state, message: msg)
        try record.rekey(send: session.c2s, recv: session.s2c)
    }

    private func makeKIPClientHelloPayload() throws -> (SudokuKIPClientState, Data) {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let clientPub = privateKey.publicKey.rawRepresentation
        let nonce = try SudokuNativeCrypto.randomData(count: 16)
        let ts = UInt64(Date().timeIntervalSince1970).bigEndian
        var timestamp = ts
        var payload = Data(bytes: &timestamp, count: 8)
        let hashSource = config.privateKey ?? Data(config.key.utf8)
        payload.append(SudokuNativeCrypto.sha256(hashSource).prefix(8))
        payload.append(nonce)
        payload.append(clientPub)
        var feats = UInt32(0x1f).bigEndian
        payload.append(Data(bytes: &feats, count: 4))
        if tables.sendsTableHint {
            var hint = tables.hint.bigEndian
            payload.append(Data(bytes: &hint, count: 4))
        }
        return (SudokuKIPClientState(privateKey: privateKey, nonce: nonce), payload)
    }

    private func finishKIP(state: SudokuKIPClientState, message msg: (type: UInt8, payload: Data)) throws -> (c2s: Data, s2c: Data) {
        guard msg.type == 0x02, msg.payload.count == 52 else { throw SudokuNativeError.protocolError("bad KIP server hello") }
        guard msg.payload.prefix(16) == state.nonce else { throw SudokuNativeError.protocolError("KIP nonce mismatch") }
        let serverPub = msg.payload.subdata(in: 16..<48)
        let shared = try state.privateKey.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPub)).withUnsafeBytes { Data($0) }
        return SudokuNativeCrypto.sessionBases(psk: config.key, shared: shared, nonce: state.nonce)
    }

    private func writeKIP(record: SudokuRecordStream, type: UInt8, payload: Data) throws {
        try record.send(encodeKIP(type: type, payload: payload))
    }

    private func encodeKIP(type: UInt8, payload: Data) -> Data {
        var frame = Data([0x6b, 0x69, 0x70, type, UInt8(payload.count >> 8), UInt8(payload.count & 0xff)])
        frame.append(payload)
        return frame
    }

    private func readKIP(record: SudokuRecordStream) throws -> (type: UInt8, payload: Data) {
        let header = try record.readExact(6)
        guard header[0] == 0x6b, header[1] == 0x69, header[2] == 0x70 else { throw SudokuNativeError.protocolError("bad KIP magic") }
        let length = Int(UInt16(header[4]) << 8 | UInt16(header[5]))
        return (header[3], try record.readExact(length))
    }

    private func parseKIP(_ data: Data) throws -> (type: UInt8, payload: Data) {
        guard data.count >= 6 else { throw SudokuNativeError.protocolError("short KIP frame") }
        guard data[0] == 0x6b, data[1] == 0x69, data[2] == 0x70 else { throw SudokuNativeError.protocolError("bad KIP magic") }
        let length = Int(UInt16(data[4]) << 8 | UInt16(data[5]))
        guard data.count >= 6 + length else { throw SudokuNativeError.protocolError("truncated KIP frame \(data.count)/\(6 + length)") }
        return (data[3], data.subdata(in: 6..<(6 + length)))
    }
}

private enum SudokuAddress {
    static func encode(host: String, port: UInt16) throws -> Data {
        var out = Data()
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        if host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            out.append(0x01)
            withUnsafeBytes(of: ipv4.s_addr) { out.append(contentsOf: $0) }
        } else if host.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            out.append(0x04)
            withUnsafeBytes(of: ipv6) { out.append(contentsOf: $0) }
        } else {
            let bytes = Array(host.utf8)
            guard bytes.count <= 255 else { throw SudokuNativeError.invalidConfiguration("domain too long") }
            out.append(0x03)
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(UInt8(port >> 8))
        out.append(UInt8(port & 0xff))
        return out
    }
}

final class SudokuMuxClient {
    private let record: SudokuRecordStream
    private let condition = NSCondition()
    private var streams: [UInt32: SudokuMuxStream] = [:]
    private var nextStreamID: UInt32 = 0
    private var closed = false

    init(record: SudokuRecordStream) {
        self.record = record
        DispatchQueue.global(qos: .userInitiated).async { self.readerLoop() }
    }

    func dialTCP(host: String, port: UInt16) throws -> SudokuMuxStream {
        let stream = SudokuMuxStream(client: self, id: allocateStreamID())
        condition.lock(); streams[stream.id] = stream; condition.unlock()
        try sendFrame(type: 0x01, streamID: stream.id, payload: SudokuAddress.encode(host: host, port: port))
        return stream
    }

    func sendFrame(type: UInt8, streamID: UInt32, payload: Data) throws {
        guard payload.count <= 256 * 1024 else { throw SudokuNativeError.protocolError("mux frame too large") }
        var frame = Data([type])
        var sid = streamID.bigEndian
        var len = UInt32(payload.count).bigEndian
        frame.append(Data(bytes: &sid, count: 4))
        frame.append(Data(bytes: &len, count: 4))
        frame.append(payload)
        try record.send(frame)
    }

    func close(stream: SudokuMuxStream) {
        condition.lock()
        let shouldSend = streams.removeValue(forKey: stream.id) != nil && !closed
        condition.unlock()
        if shouldSend { try? sendFrame(type: 0x03, streamID: stream.id, payload: Data()) }
        stream.markClosed()
    }

    func close() {
        condition.lock()
        closed = true
        let all = Array(streams.values)
        streams.removeAll()
        condition.unlock()
        for stream in all { stream.markClosed() }
        record.close()
    }

    private func allocateStreamID() -> UInt32 {
        condition.lock(); defer { condition.unlock() }
        repeat { nextStreamID &+= 1 } while nextStreamID == 0
        return nextStreamID
    }

    private func readerLoop() {
        while true {
            do {
                let hdr = try record.readExact(9)
                let type = hdr[0]
                let streamID = hdr[1..<5].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
                let length = Int(hdr[5..<9].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
                guard length <= 256 * 1024 else { throw SudokuNativeError.protocolError("mux frame too large") }
                let payload = try record.readExact(length)
                condition.lock(); let stream = streams[streamID]; if type == 0x03 || type == 0x04 { streams.removeValue(forKey: streamID) }; condition.unlock()
                switch type {
                case 0x02:
                    if let stream, !stream.enqueue(payload) {
                        sudokuLogger.warning("[Sudoku-Mux] stream \(streamID) receive queue overflow, resetting stream")
                        condition.lock()
                        let shouldReset = streams.removeValue(forKey: streamID) != nil && !closed
                        condition.unlock()
                        if shouldReset {
                            try? sendFrame(type: 0x04, streamID: streamID, payload: Data())
                        }
                    }
                case 0x03, 0x04: stream?.markClosed()
                default: throw SudokuNativeError.protocolError("bad mux frame")
                }
            } catch SudokuNativeError.closed {
                close()
                return
            } catch {
                sudokuLogger.error("[Sudoku-Mux] reader failed: \(error.localizedDescription)")
                close()
                return
            }
        }
    }
}

final class SudokuMuxStream {
    let id: UInt32
    private weak var client: SudokuMuxClient?
    private let condition = NSCondition()
    private var queue = SudokuDataQueue()
    private var closed = false

    init(client: SudokuMuxClient, id: UInt32) { self.client = client; self.id = id }

    func send(_ data: Data) throws {
        guard let client else { throw SudokuNativeError.closed }
        var offset = 0
        while offset < data.count {
            let count = min(128 * 1024, data.count - offset)
            try client.sendFrame(type: 0x02, streamID: id, payload: data.subdata(in: offset..<(offset + count)))
            offset += count
        }
    }

    func receive(max: Int) throws -> Data {
        condition.lock(); defer { condition.unlock() }
        while queue.isEmpty && !closed { condition.wait() }
        if queue.isEmpty && closed { throw SudokuNativeError.closed }
        let out = queue.read(max: max)
        condition.signal()
        return out
    }

    func enqueue(_ data: Data) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard !closed else { return false }
        let queueLimit = max(sudokuMuxMaxQueueBytes, data.count)
        guard queue.count + data.count <= queueLimit else {
            closed = true
            queue.removeAll(keepingCapacity: false)
            condition.broadcast()
            return false
        }
        queue.append(data)
        condition.signal()
        return true
    }

    func close() { client?.close(stream: self) }
    func markClosed() {
        condition.lock()
        closed = true
        queue.removeAll(keepingCapacity: false)
        condition.broadcast()
        condition.unlock()
    }
}

final class SudokuTCPProxyConnection: ProxyConnection {
    private let stream: SudokuRecordStream
    private let readQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.tcp.read", qos: .userInitiated)
    private let writeQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.tcp.write", qos: .userInitiated)
    private var closed = false

    init(stream: SudokuRecordStream) { self.stream = stream; super.init() }
    override var isConnected: Bool { !lock.withLock { closed } }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        writeQueue.async {
            do {
                if self.lock.withLock({ self.closed }) { throw SudokuNativeError.closed }
                try self.stream.send(data)
                completion(nil)
            } catch { completion(error) }
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            guard let error else { return }
            if case SudokuNativeError.closed = error { return }
            sudokuLogger.error("[Sudoku] send failed: \(error.localizedDescription)")
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        readQueue.async {
            do {
                if self.lock.withLock({ self.closed }) { throw SudokuNativeError.closed }
                completion(try self.stream.receive(max: sudokuTCPReceiveChunkSize), nil)
            } catch SudokuNativeError.closed { completion(nil, nil) } catch { completion(nil, error) }
        }
    }

    override func cancel() { lock.withLock { closed = true }; stream.close() }
}

final class SudokuMuxTCPProxyConnection: ProxyConnection {
    private let client: SudokuMuxClient
    private let stream: SudokuMuxStream
    private let readQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.mux.read", qos: .userInitiated)
    private let writeQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.mux.write", qos: .userInitiated)
    private var closed = false

    init(client: SudokuMuxClient, stream: SudokuMuxStream) { self.client = client; self.stream = stream; super.init() }
    override var isConnected: Bool { !lock.withLock { closed } }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        writeQueue.async {
            do {
                if self.lock.withLock({ self.closed }) { throw SudokuNativeError.closed }
                try self.stream.send(data)
                completion(nil)
            } catch { completion(error) }
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            guard let error else { return }
            if case SudokuNativeError.closed = error { return }
            sudokuLogger.error("[Sudoku-Mux] send failed: \(error.localizedDescription)")
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        readQueue.async {
            do {
                if self.lock.withLock({ self.closed }) { throw SudokuNativeError.closed }
                completion(try self.stream.receive(max: sudokuTCPReceiveChunkSize), nil)
            } catch SudokuNativeError.closed { completion(nil, nil) } catch { completion(nil, error) }
        }
    }

    override func cancel() { lock.withLock { closed = true }; stream.close(); client.close() }
}

final class SudokuUDPProxyConnection: ProxyConnection {
    private let stream: SudokuRecordStream
    private let destinationHost: String
    private let destinationPort: UInt16
    private let readQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.udp.read", qos: .userInitiated)
    private let writeQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.udp.write", qos: .userInitiated)
    private var closed = false

    init(stream: SudokuRecordStream, destinationHost: String, destinationPort: UInt16) {
        self.stream = stream
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        super.init()
    }

    override var isConnected: Bool { !lock.withLock { closed } }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        writeQueue.async {
            do {
                if self.lock.withLock({ self.closed }) { throw SudokuNativeError.closed }
                let addr = try SudokuAddress.encode(host: self.destinationHost, port: self.destinationPort)
                guard addr.count <= UInt16.max else { throw SudokuNativeError.protocolError("UoT address too large") }
                guard data.count <= UInt16.max else { throw SudokuNativeError.protocolError("UoT payload too large") }
                var frame = Data([UInt8(addr.count >> 8), UInt8(addr.count & 0xff), UInt8(data.count >> 8), UInt8(data.count & 0xff)])
                frame.append(addr)
                frame.append(data)
                try self.stream.send(frame)
                completion(nil)
            } catch { completion(error) }
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            guard let error else { return }
            if case SudokuNativeError.closed = error { return }
            sudokuLogger.error("[Sudoku-UoT] send failed: \(error.localizedDescription)")
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        readQueue.async {
            do {
                if self.lock.withLock({ self.closed }) { throw SudokuNativeError.closed }
                let hdr = try self.stream.readExact(4)
                let addrLen = Int(UInt16(hdr[0]) << 8 | UInt16(hdr[1]))
                let payloadLen = Int(UInt16(hdr[2]) << 8 | UInt16(hdr[3]))
                guard addrLen > 0 && addrLen <= 64 * 1024 else { throw SudokuNativeError.protocolError("bad UoT address length") }
                guard payloadLen <= 64 * 1024 else { throw SudokuNativeError.protocolError("bad UoT payload length") }
                _ = try self.stream.readExact(addrLen)
                completion(try self.stream.readExact(payloadLen), nil)
            } catch SudokuNativeError.closed { completion(nil, nil) } catch { completion(nil, error) }
        }
    }

    override func cancel() { lock.withLock { closed = true }; stream.close() }
}
