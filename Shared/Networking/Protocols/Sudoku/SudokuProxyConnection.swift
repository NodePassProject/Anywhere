//
//  SudokuProxyConnection.swift
//  Anywhere
//
//  Created by saba-futai on 4/23/26.
//

import Foundation
import Darwin
import CryptoKit
import Security
import Synchronization

private let sudokuLogger = AnywhereLogger(category: "SudokuProxyConnection")
private let sudokuObfsReadChunkSize = 128 * 1024
private let sudokuTCPReceiveChunkSize = 64 * 1024
private let sudokuHTTPMaskMaxQueueBytes = 4 * 1024 * 1024
private let sudokuHTTPMaskMaxPollLineBytes = 256 * 1024
private let sudokuMuxMaxQueueBytes = 4 * 1024 * 1024
private let sudokuHTTPMaskStreamEOFHeader = "x-sudoku-stream-eof"

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

private enum SudokuHTTPMaskPathRoot {
    static func apply(_ root: String, to path: String) -> String {
        let clean = normalize(root)
        guard !clean.isEmpty else { return path }
        let suffix = path.hasPrefix("/") ? path : "/\(path)"
        return "/\(clean)\(suffix)"
    }

    private static func normalize(_ root: String) -> String {
        let slashes = CharacterSet(charactersIn: "/")
        let trimmed = root.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: slashes)
        guard !trimmed.isEmpty else { return "" }
        for scalar in trimmed.unicodeScalars {
            switch scalar.value {
            case 48...57, 65...90, 97...122, 45, 95:
                continue
            default:
                return ""
            }
        }
        return trimmed
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

    mutating func append(_ data: Data, from start: Int) {
        guard start > 0 else {
            append(data)
            return
        }
        guard start < data.count else { return }
        compactBeforeAppend(additionalCount: data.count - start)
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            storage.append(base.assumingMemoryBound(to: UInt8.self).advanced(by: start), count: data.count - start)
        }
    }

    mutating func read(max: Int) -> Data {
        let n = min(max, count)
        guard n > 0 else { return Data() }
        let start = offset
        let out = storage.rangeData(offset: start, count: n)
        offset += n
        compactAfterRead()
        return out
    }

    mutating func drain(exact count: Int, into out: inout Data) {
        let n = min(count, self.count)
        guard n > 0 else { return }
        let start = offset
        storage.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            out.append(base.assumingMemoryBound(to: UInt8.self).advanced(by: start), count: n)
        }
        offset += n
        compactAfterRead()
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
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { raw -> OSStatus in
            guard let base = raw.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
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
        var block = Data()
        var counter: UInt8 = 1
        while produced.count < count {
            var parts: [Data] = []
            if !block.isEmpty { parts.append(block) }
            parts.append(Data(info.utf8))
            parts.append(Data([counter]))
            block = hmacSHA256(key: prk, parts: parts)
            produced.append(block.prefix(count - produced.count))
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
            do {
                let box = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: nonce),
                    ciphertext: ciphertext.prefix(split),
                    tag: ciphertext.suffix(16)
                )
                return try AES.GCM.open(box, using: SymmetricKey(data: key.prefix(16)), authenticating: aad)
            } catch {
                throw SudokuNativeError.protocolError("AES-GCM open failed")
            }
        case .chacha20Poly1305:
            guard ciphertext.count >= 16 else { throw SudokuNativeError.protocolError("short ChaCha20-Poly1305 frame") }
            let split = ciphertext.count - 16
            do {
                let box = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonce),
                    ciphertext: ciphertext.prefix(split),
                    tag: ciphertext.suffix(16)
                )
                return try ChaChaPoly.open(box, using: SymmetricKey(data: key.prefix(32)), authenticating: aad)
            } catch {
                throw SudokuNativeError.protocolError("ChaCha20-Poly1305 open failed")
            }
        case .none:
            return ciphertext
        }
    }
}

nonisolated final class SudokuNativeConfig {
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
    let multiplex: SudokuMultiplex
    let httpMask: SudokuHTTPMaskConfiguration

    init(configuration: ProxyConfiguration) throws {
        guard case .sudoku(let sudoku) = configuration.outbound else {
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
        self.multiplex = sudoku.multiplex
        self.httpMask = sudoku.httpMask

        if let raw = Data(hexString: sudoku.key), raw.count == 32 || raw.count == 64 {
            self.privateKey = raw
        } else {
            self.privateKey = nil
        }
        self.key = SudokuKeyRecovery.recoverPublicKeyHex(sudoku.key) ?? sudoku.key
    }

    var nativeMuxEnabled: Bool {
        multiplex == .on
    }
}

private struct SudokuTableCacheKey: Hashable {
    let key: String
    let asciiMode: String
    let customTable: String
}

private enum SudokuTableCache {
    private static let maxEntries = 16

    private struct State {
        var pairs: [SudokuTableCacheKey: SudokuTablePair] = [:]
        var accessOrder: [SudokuTableCacheKey] = []
    }

    private static let state = Mutex(State())

    static func pair(for config: SudokuNativeConfig) throws -> SudokuTablePair {
        let cacheKey = SudokuTableCacheKey(
            key: config.key,
            asciiMode: config.asciiMode,
            customTable: config.selectedCustomTable
        )
        return try state.withLock { (state: inout State) -> SudokuTablePair in
            if let pair = state.pairs[cacheKey] {
                touch(cacheKey, in: &state)
                return pair
            }

            let pair = try SudokuTablePair(
                key: config.key,
                asciiMode: config.asciiMode,
                customUplink: config.selectedCustomTable,
                customDownlink: config.selectedCustomTable
            )
            state.pairs[cacheKey] = pair
            touch(cacheKey, in: &state)
            trimIfNeeded(in: &state)
            return pair
        }
    }

    private static func touch(_ key: SudokuTableCacheKey, in state: inout State) {
        state.accessOrder.removeAll { $0 == key }
        state.accessOrder.append(key)
    }

    private static func trimIfNeeded(in state: inout State) {
        while state.accessOrder.count > maxEntries, let evicted = state.accessOrder.first {
            state.accessOrder.removeFirst()
            state.pairs.removeValue(forKey: evicted)
        }
    }
}

nonisolated final class SudokuTables {
    private let pair: Mutex<SudokuTablePair>
    let sendsTableHint: Bool

    init(config: SudokuNativeConfig) throws {
        sendsTableHint = config.sendsTableHint
        pair = Mutex(try SudokuTableCache.pair(for: config))
    }

    func withUplink<T>(_ body: (SudokuTable) throws -> T) rethrows -> T {
        try pair.withLock { try body($0.uplink) }
    }

    func withDownlink<T>(_ body: (SudokuTable) throws -> T) rethrows -> T {
        try pair.withLock { try body($0.downlink) }
    }

    var hint: UInt32 { pair.withLock { $0.uplink.hint } }
}

/// An async byte stream over a ``ProxyConnection``, with a leftover-read buffer.
///
/// Send is serialized by the caller (the record-layer ``AsyncMutex`` funnels every
/// write, and each per-request HTTPMask stream is used by one task), so this holds no
/// send lock. Receive is single-flight by contract, so `pending` is only touched under
/// a short synchronous `readLock` — never across the wire `await`.
nonisolated final class BlockingProxyStream {
    private let connection: ProxyConnection
    private let stateLock = UnfairLock()
    private let readLock = UnfairLock()
    private var pending = SudokuDataQueue()
    private var closed = false

    init(connection: ProxyConnection) { self.connection = connection }

    func sendAll(_ data: Data) async throws {
        if data.isEmpty { return }
        if isClosed { throw SudokuNativeError.closed }
        try await connection.sendRaw(data)
    }

    func readSome(max: Int) async throws -> Data {
        guard max > 0 else { return Data() }
        if let buffered = readLock.withLock({ pending.isEmpty ? nil : pending.read(max: max) }) {
            return buffered
        }
        if isClosed { throw SudokuNativeError.closed }
        guard let data = try await connection.receiveRaw(), !data.isEmpty else {
            markClosed()
            throw SudokuNativeError.closed
        }
        if data.count > max {
            readLock.withLock { pending.append(data, from: max) }
            return data.prefixData(max)
        }
        return data
    }

    func readExact(_ count: Int) async throws -> Data {
        guard count > 0 else { return Data() }
        var out = Data(capacity: count)
        readLock.withLock {
            if !pending.isEmpty { pending.drain(exact: count, into: &out) }
        }
        while out.count < count {
            if isClosed { throw SudokuNativeError.closed }
            guard let data = try await connection.receiveRaw(), !data.isEmpty else {
                markClosed()
                throw SudokuNativeError.closed
            }
            let need = count - out.count
            if data.count > need {
                out.append(data.prefixData(need))
                readLock.withLock { pending.append(data, from: need) }
            } else {
                out.append(data)
            }
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

private extension Data {
    func prefixData(_ count: Int) -> Data {
        let n = Swift.min(count, self.count)
        guard n > 0 else { return Data() }
        if n == self.count { return self }
        return withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return Data() }
            return Data(bytes: base, count: n)
        }
    }

    func rangeData(offset: Int, count: Int) -> Data {
        guard offset >= 0, count > 0, offset <= self.count, count <= self.count - offset else { return Data() }
        return withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return Data() }
            return Data(bytes: base.advanced(by: offset), count: count)
        }
    }

    func uint32BE(at offset: Int) -> UInt32 {
        withUnsafeBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            return (UInt32(bytes[offset]) << 24) |
                (UInt32(bytes[offset + 1]) << 16) |
                (UInt32(bytes[offset + 2]) << 8) |
                UInt32(bytes[offset + 3])
        }
    }

    func uint64BE(at offset: Int) -> UInt64 {
        withUnsafeBytes { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            var value: UInt64 = 0
            for index in 0..<8 {
                value = (value << 8) | UInt64(bytes[offset + index])
            }
            return value
        }
    }
}

nonisolated final class SudokuConnectionFactory: @unchecked Sendable {
    private struct PreparedKey: Hashable {
        let host: String
        let port: UInt16
        let useTLS: Bool
        let serverName: String
    }

    private final class PreparedConnection: @unchecked Sendable {
        let connection: ProxyConnection

        init(connection: ProxyConnection) {
            self.connection = connection
        }
    }

    private static let preparedConnectionTTL: TimeInterval = 4
    /// A pending preconnection is only a latency optimization. Do not let a
    /// stalled handshake hold an HTTPMask request behind the full dial timeout.
    private static let preparedConnectionWaitTimeout: TimeInterval = 0.25
    private static let preparationRetryInterval: TimeInterval = 0.5
    private let configuration: ProxyConfiguration
    private let directDialHost: String

    /// Fields guarded by `stateLock`.
    private struct State {
        var initialTunnel: ProxyConnection?
        var retainedClients: [ProxyClient] = []
        var retainedTLSClients: [TLSClient] = []
        var retainedTransports: [TCPTransport] = []
        var connections: [ProxyConnection] = []
        var closed = false
    }

    private let stateLock: Mutex<State>
    private let preparedCondition = NSCondition()
    private var preparedConnections: [PreparedKey: [PreparedConnection]] = [:]
    private var pendingPreparations: [PreparedKey: Int] = [:]
    private var maintainedPreparations: [PreparedKey: Int] = [:]
    private var preparedClosed = false

    init(configuration: ProxyConfiguration, initialTunnel: ProxyConnection?, directDialHost: String) {
        self.configuration = configuration
        self.stateLock = Mutex(State(initialTunnel: initialTunnel))
        self.directDialHost = directDialHost
    }

    func open(host: String, port: UInt16, useTLS: Bool, serverName: String?) async throws -> BlockingProxyStream {
        if stateLock.withLock({ $0.closed }) { throw SudokuNativeError.closed }
        let key = preparedKey(host: host, port: port, useTLS: useTLS, serverName: serverName)
        if let prepared = await takePreparedConnection(for: key) {
            return BlockingProxyStream(connection: prepared.connection)
        }
        let connection = try await awaitConnection(timeoutMessage: "timeout opening transport") { completion in
            openProxyConnection(
                host: host,
                port: port,
                useTLS: useTLS,
                serverName: serverName,
                completion: completion
            )
        }
        guard retainConnection(connection) else {
            connection.cancel()
            throw SudokuNativeError.closed
        }
        return BlockingProxyStream(connection: connection)
    }

    func prepare(host: String, port: UInt16, useTLS: Bool, serverName: String?, count: Int) {
        guard count > 0, preparedConnectionsEnabled else {
            return
        }

        let key = preparedKey(host: host, port: port, useTLS: useTLS, serverName: serverName)
        ensurePreparedConnections(for: key, targetCount: count)
    }

    func maintainPreparedConnection(host: String, port: UInt16, useTLS: Bool, serverName: String?) {
        guard preparedConnectionsEnabled else {
            return
        }

        let key = preparedKey(host: host, port: port, useTLS: useTLS, serverName: serverName)
        preparedCondition.lock()
        if preparedClosed {
            preparedCondition.unlock()
            return
        }
        maintainedPreparations[key] = 1
        preparedCondition.unlock()
        ensurePreparedConnections(for: key, targetCount: 1)
    }

    func stopMaintainingPreparedConnection(host: String, port: UInt16, useTLS: Bool, serverName: String?) {
        let key = preparedKey(host: host, port: port, useTLS: useTLS, serverName: serverName)
        preparedCondition.lock()
        maintainedPreparations.removeValue(forKey: key)
        preparedCondition.broadcast()
        preparedCondition.unlock()
    }

    func waitForPreparedConnection(
        host: String,
        port: UInt16,
        useTLS: Bool,
        serverName: String?,
        timeout: TimeInterval
    ) async throws {
        let key = preparedKey(host: host, port: port, useTLS: useTLS, serverName: serverName)
        let deadline = Date().addingTimeInterval(timeout)
        // The prepared-connection pool is fed by async completions off other tasks; poll it
        // (non-blocking) rather than parking a cooperative thread on the NSCondition.
        while true {
            preparedCondition.lock()
            let ready = !(preparedConnections[key]?.isEmpty ?? true)
            let closed = preparedClosed
            preparedCondition.unlock()
            if ready { return }
            if closed { throw SudokuNativeError.closed }
            if Date() >= deadline {
                throw SudokuNativeError.connectionFailed("timeout waiting for prepared HTTPMask upload")
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    private func ensurePreparedConnections(for key: PreparedKey, targetCount: Int) {
        guard targetCount > 0 else { return }
        preparedCondition.lock()
        if preparedClosed {
            preparedCondition.unlock()
            return
        }
        let readyCount = preparedConnections[key]?.count ?? 0
        let pendingCount = pendingPreparations[key] ?? 0
        let needed = max(0, targetCount - readyCount - pendingCount)
        if needed > 0 {
            pendingPreparations[key] = pendingCount + needed
        }
        preparedCondition.unlock()
        guard needed > 0 else { return }

        for _ in 0..<needed {
            openProxyConnection(host: key.host, port: key.port, useTLS: key.useTLS, serverName: key.serverName) { result in
                self.finishPreparation(result, for: key)
            }
        }
    }

    func openWebSocket(
        host: String,
        port: UInt16,
        useTLS: Bool,
        serverName: String?,
        hostHeader: String,
        path: String,
        headers: [String: String]
    ) async throws -> BlockingProxyStream {
        if stateLock.withLock({ $0.closed }) { throw SudokuNativeError.closed }
        let base = try await awaitConnection(timeoutMessage: "timeout opening WebSocket transport") { completion in
            openProxyConnection(
                host: host,
                port: port,
                useTLS: useTLS,
                serverName: serverName,
                completion: completion
            )
        }
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
        do {
            // First of {upgrade completion, 30s deadline} wins; a late completion resolves
            // the already-latched promise and is dropped (no continuation leak).
            let promise = AsyncPromise<Void>()
            ws.performUpgrade { error in
                promise.resolve(error.map { .failure($0) } ?? .success(()))
            }
            try await raceDialDeadline(
                .seconds(30),
                timeout: SudokuNativeError.connectionFailed("timeout upgrading WebSocket transport")
            ) {
                try await promise.value()
            }
        } catch {
            releaseConnection(base)
            ws.cancel()
            base.cancel()
            throw error
        }
        let connection = WebSocketProxyConnection(wsConnection: ws)
        guard replaceConnection(base, with: connection) else {
            connection.cancel()
            throw SudokuNativeError.closed
        }
        return BlockingProxyStream(connection: connection)
    }

    func closeAll() {
        preparedCondition.lock()
        preparedClosed = true
        preparedConnections.removeAll()
        pendingPreparations.removeAll()
        maintainedPreparations.removeAll()
        preparedCondition.broadcast()
        preparedCondition.unlock()

        typealias Drained = (toClose: [ProxyConnection], clients: [ProxyClient],
                             tlsClients: [TLSClient], transports: [TCPTransport])
        let drained: Drained? = stateLock.withLock { (state: inout State) -> Drained? in
            if state.closed {
                return nil
            }
            state.closed = true
            let toClose = state.connections + (state.initialTunnel.map { [$0] } ?? [])
            let clients = state.retainedClients
            let tlsClients = state.retainedTLSClients
            let transports = state.retainedTransports
            state.connections.removeAll()
            state.retainedClients.removeAll()
            state.retainedTLSClients.removeAll()
            state.retainedTransports.removeAll()
            state.initialTunnel = nil
            return (toClose, clients, tlsClients, transports)
        }
        guard let drained else { return }
        // Cancels run outside the lock.
        for connection in drained.toClose { connection.cancel() }
        for client in drained.clients { client.cancel() }
        for client in drained.tlsClients { client.cancel() }
        for transport in drained.transports { transport.cancel() }
    }

    private func awaitConnection(
        timeoutMessage: String,
        start: (@Sendable @escaping (Result<ProxyConnection, Error>) -> Void) -> Void
    ) async throws -> ProxyConnection {
        let promise = AsyncPromise<ProxyConnection>()
        // Atomic "who won" gate: the first of {dial completion, 30s deadline} to flip `settled`
        // resolves the promise; a completion that arrives after the deadline cancels its
        // now-orphaned connection instead (mirrors the old `abandoned` flag — no socket leak).
        let settled = Mutex(false)
        let settle: @Sendable (Result<ProxyConnection, Error>) -> Void = { result in
            let won = settled.withLock { flag -> Bool in
                if flag { return false }
                flag = true
                return true
            }
            if won {
                promise.resolve(result)
            } else if case .success(let connection) = result {
                connection.cancel()
            }
        }
        start { settle($0) }
        return try await raceDialDeadline(
            .seconds(30),
            onExpire: { settle(.failure(SudokuNativeError.connectionFailed(timeoutMessage))) },
            timeout: SudokuNativeError.connectionFailed(timeoutMessage)
        ) {
            try await promise.value()
        }
    }

    private func preparedKey(host: String, port: UInt16, useTLS: Bool, serverName: String?) -> PreparedKey {
        PreparedKey(
            host: host.lowercased(),
            port: port,
            useTLS: useTLS,
            serverName: (serverName ?? host).lowercased()
        )
    }

    private var supportsPreparedConnections: Bool {
        guard configuration.chain?.isEmpty != false else { return false }
        return stateLock.withLock { !$0.closed && $0.initialTunnel == nil }
    }

    fileprivate var preparedConnectionsEnabled: Bool {
        ProcessInfo.processInfo.environment["ANYWHERE_SUDOKU_DISABLE_PRECONNECT"] != "1"
            && supportsPreparedConnections
    }

    private func takePreparedConnection(for key: PreparedKey) async -> PreparedConnection? {
        let deadline = Date().addingTimeInterval(Self.preparedConnectionWaitTimeout)
        while true {
            preparedCondition.lock()
            if var ready = preparedConnections[key], !ready.isEmpty {
                let connection = ready.removeFirst()
                if ready.isEmpty {
                    preparedConnections.removeValue(forKey: key)
                } else {
                    preparedConnections[key] = ready
                }
                let maintainedCount = maintainedPreparations[key]
                preparedCondition.unlock()
                if let maintainedCount {
                    ensurePreparedConnections(for: key, targetCount: maintainedCount)
                }
                return connection
            }
            let shouldWait = !preparedClosed && (pendingPreparations[key] ?? 0) > 0
            preparedCondition.unlock()
            // Briefly poll (non-blocking) for an in-flight preparation to land, rather than
            // parking a cooperative thread on the NSCondition; otherwise dial fresh.
            guard shouldWait, Date() < deadline else { return nil }
            do {
                try await Task.sleep(for: .milliseconds(5))
            } catch {
                return nil
            }
        }
    }

    private func finishPreparation(_ result: Result<ProxyConnection, Error>, for key: PreparedKey) {
        guard case .success(let connection) = result else {
            finishPendingPreparation(for: key)
            scheduleMaintainedPreparationRetry(for: key)
            return
        }

        let retained = retainConnection(connection)
        let prepared = retained ? PreparedConnection(connection: connection) : nil

        preparedCondition.lock()
        decrementPendingPreparationLocked(for: key)
        if let prepared, !preparedClosed {
            preparedConnections[key, default: []].append(prepared)
        }
        let acceptedPrepared = preparedClosed ? nil : prepared
        preparedCondition.broadcast()
        preparedCondition.unlock()

        guard let acceptedPrepared else {
            if retained {
                releaseConnection(connection)
            }
            connection.cancel()
            return
        }
        expirePreparedConnection(acceptedPrepared, for: key)
    }

    private func finishPendingPreparation(for key: PreparedKey) {
        preparedCondition.lock()
        decrementPendingPreparationLocked(for: key)
        preparedCondition.broadcast()
        preparedCondition.unlock()
    }

    private func decrementPendingPreparationLocked(for key: PreparedKey) {
        let remaining = max(0, (pendingPreparations[key] ?? 1) - 1)
        if remaining == 0 {
            pendingPreparations.removeValue(forKey: key)
        } else {
            pendingPreparations[key] = remaining
        }
    }

    private func expirePreparedConnection(_ prepared: PreparedConnection, for key: PreparedKey) {
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + Self.preparedConnectionTTL) {
            var expired = false
            self.preparedCondition.lock()
            if var ready = self.preparedConnections[key],
               let index = ready.firstIndex(where: { $0 === prepared }) {
                ready.remove(at: index)
                if ready.isEmpty {
                    self.preparedConnections.removeValue(forKey: key)
                } else {
                    self.preparedConnections[key] = ready
                }
                expired = true
            }
            self.preparedCondition.unlock()
            if expired {
                self.releaseConnection(prepared.connection)
                prepared.connection.cancel()
                self.refillMaintainedPreparation(for: key)
            }
        }
    }

    private func refillMaintainedPreparation(for key: PreparedKey) {
        preparedCondition.lock()
        let targetCount = maintainedPreparations[key]
        preparedCondition.unlock()
        if let targetCount {
            ensurePreparedConnections(for: key, targetCount: targetCount)
        }
    }

    private func scheduleMaintainedPreparationRetry(for key: PreparedKey) {
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + Self.preparationRetryInterval) {
            self.refillMaintainedPreparation(for: key)
        }
    }

    private func openProxyConnection(
        host: String,
        port: UInt16,
        useTLS: Bool,
        serverName: String?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        if let tunnel = stateLock.withLock({ (state: inout State) -> ProxyConnection? in
            let current = state.initialTunnel
            state.initialTunnel = nil
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
                case .success(let connection): completion(.success(TLSProxyConnection(tlsConnection: connection)))
                case .failure(let error): completion(.failure(error))
                }
            }
            return
        }

        let transport = TCPTransport(host: directDialHost, port: port)
        guard retainTransport(transport) else {
            completion(.failure(SudokuNativeError.closed))
            return
        }
        Task {
            do {
                try await transport.connect()
            } catch {
                self.releaseTransport(transport)
                completion(.failure(error))
                return
            }
            self.releaseTransport(transport)
            completion(.success(DirectProxyConnection(transport: transport)))
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
        Task { [weak self] in
            do {
                let connection = try await client.connect(to: nextHost, port: nextPort)
                if index + 1 < chain.count {
                    self?.buildChainTunnel(chain: chain, index: index + 1, currentTunnel: connection, targetHost: targetHost, targetPort: targetPort, completion: completion)
                } else {
                    completion(.success(connection))
                }
            } catch {
                completion(.failure(error))
            }
        }
    }

    private func retainClient(_ client: ProxyClient) -> Bool {
        stateLock.withLock { state in
            guard !state.closed else { return false }
            state.retainedClients.append(client)
            return true
        }
    }

    private func retainTLSClient(_ client: TLSClient) -> Bool {
        stateLock.withLock { state in
            guard !state.closed else { return false }
            state.retainedTLSClients.append(client)
            return true
        }
    }

    private func releaseTLSClient(_ client: TLSClient) {
        stateLock.withLock { state in
            state.retainedTLSClients.removeAll { $0 === client }
        }
    }

    private func retainTransport(_ transport: TCPTransport) -> Bool {
        stateLock.withLock { state in
            guard !state.closed else { return false }
            state.retainedTransports.append(transport)
            return true
        }
    }

    private func releaseTransport(_ transport: TCPTransport) {
        stateLock.withLock { state in
            state.retainedTransports.removeAll { $0 === transport }
        }
    }

    private func retainConnection(_ connection: ProxyConnection) -> Bool {
        stateLock.withLock { state in
            guard !state.closed else { return false }
            state.connections.append(connection)
            return true
        }
    }

    private func replaceConnection(_ old: ProxyConnection, with new: ProxyConnection) -> Bool {
        stateLock.withLock { state in
            state.connections.removeAll { $0 === old }
            guard !state.closed else { return false }
            state.connections.append(new)
            return true
        }
    }

    private func releaseConnection(_ connection: ProxyConnection) {
        stateLock.withLock { state in
            state.connections.removeAll { $0 === connection }
        }
    }
}

private func sudokuReadHTTPLine(
    from stream: BlockingProxyStream,
    maxBytes: Int = 8 * 1024
) async throws -> String {
    var data = Data()
    while true {
        let byte = try await stream.readExact(1)[0]
        if byte == 0x0a { break }
        if byte != 0x0d { data.append(byte) }
        if data.count > maxBytes {
            throw SudokuNativeError.protocolError("HTTP line too long")
        }
    }
    return String(data: data, encoding: .utf8) ?? ""
}

private final class SudokuHTTPBodyReader {
    private let stream: BlockingProxyStream
    let status: Int
    private let chunked: Bool
    private let closeDelimited: Bool
    private var contentRemaining: Int
    private var chunkRemaining = 0
    private var done = false
    private(set) var streamEOF = false

    init(stream: BlockingProxyStream, status: Int, chunked: Bool, contentLength: Int?) {
        self.stream = stream
        self.status = status
        self.chunked = chunked
        self.contentRemaining = contentLength ?? 0
        self.closeDelimited = !chunked && contentLength == nil
    }

    func readSome(max: Int = 32 * 1024) async throws -> Data {
        if done { return Data() }
        if chunked {
            while chunkRemaining == 0 {
                let line = try await sudokuReadHTTPLine(from: stream)
                let lenText = line.split(separator: ";", maxSplits: 1).first.map(String.init) ?? line
                guard let length = Int(lenText.trimmingCharacters(in: .whitespacesAndNewlines), radix: 16) else {
                    throw SudokuNativeError.protocolError("bad chunk length")
                }
                if length == 0 {
                    while true {
                        let trailer = try await sudokuReadHTTPLine(from: stream)
                        if trailer.isEmpty { break }
                        let parts = trailer.split(separator: ":", maxSplits: 1)
                        guard parts.count == 2 else { continue }
                        if parts[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == sudokuHTTPMaskStreamEOFHeader,
                           parts[1].trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
                            streamEOF = true
                        }
                    }
                    done = true
                    return Data()
                }
                chunkRemaining = length
            }
            let n = min(max, chunkRemaining)
            let data = try await stream.readExact(n)
            chunkRemaining -= n
            if chunkRemaining == 0 { _ = try await stream.readExact(2) }
            return data
        }
        if !closeDelimited {
            if contentRemaining == 0 {
                done = true
                return Data()
            }
            let n = min(max, contentRemaining)
            let data = try await stream.readExact(n)
            contentRemaining -= n
            if contentRemaining == 0 { done = true }
            return data
        }
        do { return try await stream.readSome(max: max) }
        catch SudokuNativeError.closed {
            done = true
            return Data()
        }
    }

    func readAll(limit: Int) async throws -> Data {
        var out = Data()
        while out.count < limit {
            let part = try await readSome(max: min(4096, limit - out.count))
            if part.isEmpty { break }
            out.append(part)
        }
        return out
    }
}

nonisolated final class SudokuHTTPMaskTransport: @unchecked Sendable {
    private let config: SudokuNativeConfig
    private let factory: SudokuConnectionFactory
    private let mode: SudokuHTTPMaskMode
    private let earlyRequestPayload: Data?
    private(set) var earlyResponsePayload = Data()

    /// Set once by `authorize()` (awaited in `init` before the loops start); read-only after.
    private var token = ""
    private var pullPath = ""
    private var pushPath = ""
    private var finPath = ""
    private var closePath = ""

    private var pullTask: Task<Void, Never>?
    private var pushTask: Task<Void, Never>?

    private enum Step<T> {
        case done(T)
        case fail(Error)
        case wait(UInt64)
    }

    /// All mutable, concurrently-touched state under one lock. `generation`/`waiters`
    /// implement a *generation-counted async broadcast*: the faithful async translation
    /// of the single `NSCondition` this replaced — any state change bumps `generation`
    /// and wakes every waiter, which re-checks its own predicate and re-suspends if unmet.
    private struct State {
        var rxQueue = SudokuDataQueue()
        var txQueue = SudokuDataQueue()
        var closed = false
        var fatal = false
        var readEOF = false
        var writeClosed = false
        var writeDone = false
        var writeError: Error?
        var pullReady = false
        var pushReady = false
        var stoppedPreparedMaintenance = false
        var generation: UInt64 = 0
        var nextWaiterID: UInt64 = 0
        var waiters: [(id: UInt64, cont: CheckedContinuation<Void, Never>)] = []
    }
    private let state = Mutex(State())

    init(config: SudokuNativeConfig, factory: SudokuConnectionFactory, mode: SudokuHTTPMaskMode, earlyRequestPayload: Data? = nil) async throws {
        self.config = config
        self.factory = factory
        self.mode = mode
        self.earlyRequestPayload = earlyRequestPayload?.isEmpty == false ? earlyRequestPayload : nil
        let serverName = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
        factory.prepare(
            host: config.serverHost,
            port: config.serverPort,
            useTLS: config.httpMask.tls,
            serverName: serverName,
            count: config.multiplex == .on ? 4 : 3
        )
        if config.multiplex == .on {
            factory.maintainPreparedConnection(
                host: config.serverHost,
                port: config.serverPort,
                useTLS: config.httpMask.tls,
                serverName: serverName
            )
        }
        try await authorize()
        pullTask = Task { [weak self] in await self?.pullLoop() }
        pushTask = Task { [weak self] in await self?.pushLoop() }
    }

    // MARK: Async broadcast (replaces the single NSCondition)

    /// Bumps `generation` and returns every parked waiter to resume (outside the lock).
    private func drainWaitersLocked(_ s: inout State) -> [CheckedContinuation<Void, Never>] {
        s.generation &+= 1
        let conts = s.waiters.map { $0.cont }
        s.waiters.removeAll(keepingCapacity: true)
        return conts
    }

    /// Suspends until the next broadcast. `observed` is the generation the caller read under
    /// the lock at its decision point, so a broadcast racing in before registration is not
    /// lost (registration re-checks the generation). Cancellation-aware: a cancelled waiter
    /// removes itself and resumes, so it never leaks and racing task groups can't hang.
    private func waitSignal(observed: UInt64) async {
        let id = state.withLock { s -> UInt64 in
            let id = s.nextWaiterID
            s.nextWaiterID &+= 1
            return id
        }
        await withTaskCancellationHandler {
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                let resumeNow = state.withLock { s -> Bool in
                    if s.generation != observed { return true }
                    s.waiters.append((id: id, cont: cont))
                    return false
                }
                if resumeNow { cont.resume() }
            }
        } onCancel: {
            let cont = state.withLock { s -> CheckedContinuation<Void, Never>? in
                guard let index = s.waiters.firstIndex(where: { $0.id == id }) else { return nil }
                return s.waiters.remove(at: index).cont
            }
            cont?.resume()
        }
    }

    /// Suspends until a broadcast or `deadline`, whichever comes first.
    private func waitSignal(observed: UInt64, until deadline: Date) async {
        let interval = deadline.timeIntervalSinceNow
        guard interval > 0 else { return }
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.waitSignal(observed: observed) }
            group.addTask { try? await Task.sleep(for: .seconds(interval)) }
            _ = await group.next()
            group.cancelAll()
        }
    }

    // MARK: Public I/O

    func send(_ data: Data) async throws {
        let queueLimit = max(sudokuHTTPMaskMaxQueueBytes, data.count)
        while true {
            try Task.checkCancellation()
            var toResume: [CheckedContinuation<Void, Never>] = []
            let step: Step<Void> = state.withLock { s in
                if s.closed || s.writeClosed { return .fail(SudokuNativeError.closed) }
                if s.txQueue.count + data.count > queueLimit { return .wait(s.generation) }
                s.txQueue.append(data)
                toResume = drainWaitersLocked(&s)
                return .done(())
            }
            for cont in toResume { cont.resume() }
            switch step {
            case .done: return
            case .fail(let error): throw error
            case .wait(let generation): await waitSignal(observed: generation)
            }
        }
    }

    func receive(max: Int) async throws -> Data {
        while true {
            try Task.checkCancellation()
            var toResume: [CheckedContinuation<Void, Never>] = []
            let step: Step<Data> = state.withLock { s in
                if !s.rxQueue.isEmpty {
                    let out = s.rxQueue.read(max: max)
                    if s.rxQueue.isEmpty { s.rxQueue.removeAll(keepingCapacity: false) }
                    toResume = drainWaitersLocked(&s)
                    return .done(out)
                }
                if s.readEOF { return .fail(SudokuNativeError.closed) }
                if s.closed {
                    return .fail(s.fatal ? SudokuNativeError.connectionFailed("HTTPMask closed") : SudokuNativeError.closed)
                }
                return .wait(s.generation)
            }
            for cont in toResume { cont.resume() }
            switch step {
            case .done(let out): return out
            case .fail(let error): throw error
            case .wait(let generation): await waitSignal(observed: generation)
            }
        }
    }

    func closeWrite() async throws {
        var toResume: [CheckedContinuation<Void, Never>] = []
        let earlyFail: Error? = state.withLock { s in
            if s.closed {
                return s.fatal ? SudokuNativeError.connectionFailed("HTTPMask closed") : SudokuNativeError.closed
            }
            if !s.writeClosed {
                s.writeClosed = true
                toResume = drainWaitersLocked(&s)
            }
            return nil
        }
        for cont in toResume { cont.resume() }
        if let earlyFail { throw earlyFail }
        while true {
            try Task.checkCancellation()
            let step: Step<Void> = state.withLock { s in
                if s.writeDone {
                    if let error = s.writeError { return .fail(error) }
                    return .done(())
                }
                if s.closed {
                    return .fail(s.fatal ? SudokuNativeError.connectionFailed("HTTPMask closed") : SudokuNativeError.closed)
                }
                return .wait(s.generation)
            }
            switch step {
            case .done: return
            case .fail(let error): throw error
            case .wait(let generation): await waitSignal(observed: generation)
            }
        }
    }

    func close() {
        markClosed(fatal: false)
        // Best-effort session-control close frame; the connection is already down for callers.
        let path = closePath
        Task { [weak self] in try? await self?.sendSessionControl(path: path) }
    }

    func waitReady(timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        ready: while true {
            try Task.checkCancellation()
            let step: Step<Void> = state.withLock { s in
                if s.pullReady && s.pushReady { return .done(()) }
                if s.closed { return .fail(SudokuNativeError.connectionFailed("HTTPMask closed before tunnel became ready")) }
                return .wait(s.generation)
            }
            switch step {
            case .done: break ready
            case .fail(let error): throw error
            case .wait(let generation):
                if Date() >= deadline {
                    throw SudokuNativeError.connectionFailed("timeout waiting for HTTPMask tunnel readiness")
                }
                await waitSignal(observed: generation, until: deadline)
            }
        }
        guard config.multiplex == .on, factory.preparedConnectionsEnabled else { return }
        try await factory.waitForPreparedConnection(
            host: config.serverHost,
            port: config.serverPort,
            useTLS: config.httpMask.tls,
            serverName: config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host,
            timeout: max(0, deadline.timeIntervalSinceNow)
        )
    }

    private var hostHeader: String {
        let host = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
        if (config.httpMask.tls && config.serverPort == 443) || (!config.httpMask.tls && config.serverPort == 80) { return host }
        return "\(host):\(config.serverPort)"
    }

    private func applyPathRoot(_ path: String) -> String {
        SudokuHTTPMaskPathRoot.apply(config.httpMask.pathRoot, to: path)
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

    private func request(
        method: String,
        requestPath: String,
        authPath: String,
        contentType: String? = nil,
        body: Data
    ) async throws -> SudokuHTTPBodyReader {
        let stream = try await factory.open(host: config.serverHost, port: config.serverPort, useTLS: config.httpMask.tls, serverName: config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host)
        let modeName = mode == .poll ? "poll" : "stream"
        let auth = authToken(mode: modeName, method: method, path: authPath)
        let path = appendAuth(requestPath, token: auth)
        var requestHead = "\(method) \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\nUser-Agent: \(ProxyUserAgent.chrome)\r\nAccept: */*\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: close\r\nX-Sudoku-Tunnel: \(modeName)\r\nAuthorization: Bearer \(auth)\r\n"
        if let contentType { requestHead += "Content-Type: \(contentType)\r\n" }
        requestHead += "Content-Length: \(body.count)\r\n\r\n"
        var data = Data(requestHead.utf8)
        data.append(body)
        try await stream.sendAll(data)
        return try await readHeaders(stream: stream)
    }

    private func sendSessionControl(path: String) async throws {
        guard !path.isEmpty else {
            throw SudokuNativeError.protocolError("HTTPMask session control path is empty")
        }
        var lastError: Error = SudokuNativeError.connectionFailed("HTTPMask session control failed")
        for attempt in 0..<3 {
            do {
                let opened = try await request(
                    method: "POST",
                    requestPath: path,
                    authPath: "/api/v1/upload",
                    body: Data()
                )
                _ = try await opened.readAll(limit: 256)
                if opened.status == 200 {
                    return
                }
                if attempt > 0, [403, 404, 410].contains(opened.status) {
                    return
                }
                lastError = SudokuNativeError.connectionFailed(
                    "HTTPMask session control status \(opened.status)"
                )
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    private func readHeaders(stream: BlockingProxyStream) async throws -> SudokuHTTPBodyReader {
        let statusLine = try await sudokuReadHTTPLine(from: stream)
        let parts = statusLine.split(separator: " ")
        guard parts.count >= 2, let status = Int(parts[1]) else { throw SudokuNativeError.protocolError("bad HTTP response") }
        var chunked = false
        var contentLength: Int?
        while true {
            let header = try await sudokuReadHTTPLine(from: stream)
            if header.isEmpty { break }
            let lower = header.lowercased()
            if lower.hasPrefix("transfer-encoding:") && lower.contains("chunked") { chunked = true }
            if lower.hasPrefix("content-length:"), let value = Int(header.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces)) { contentLength = value }
        }
        return SudokuHTTPBodyReader(stream: stream, status: status, chunked: chunked, contentLength: contentLength)
    }

    private func authorize() async throws {
        let sessionPath = applyPathRoot("/session")
        let opened = try await request(method: "GET", requestPath: appendEarlyData(sessionPath, payload: earlyRequestPayload), authPath: "/session", body: Data())
        guard opened.status == 200 else { throw SudokuNativeError.connectionFailed("HTTPMask authorize status \(opened.status)") }
        let body = try await opened.readAll(limit: 4096)
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
        finPath = "\(pushPath)&fin=1"
        closePath = "\(pushPath)&close=1"
    }

    private func markReadEOF() {
        let conts = state.withLock { s -> [CheckedContinuation<Void, Never>] in
            guard !s.readEOF else { return [] }
            s.readEOF = true
            return drainWaitersLocked(&s)
        }
        for cont in conts { cont.resume() }
    }

    private func completeWrite(_ error: Error?) {
        let conts = state.withLock { s -> [CheckedContinuation<Void, Never>] in
            guard !s.writeDone else { return [] }
            s.writeError = error
            s.writeDone = true
            return drainWaitersLocked(&s)
        }
        for cont in conts { cont.resume() }
    }

    private func markClosed(fatal: Bool) {
        var stopPreparedMaintenance = false
        let conts = state.withLock { s -> [CheckedContinuation<Void, Never>] in
            s.fatal = s.fatal || fatal
            s.closed = true
            if !s.stoppedPreparedMaintenance {
                s.stoppedPreparedMaintenance = true
                stopPreparedMaintenance = true
            }
            return drainWaitersLocked(&s)
        }
        // Wake every waiter (send/receive/closeWrite/waitReady/the loops), then stop the loops.
        for cont in conts { cont.resume() }
        pullTask?.cancel()
        pushTask?.cancel()
        if stopPreparedMaintenance {
            factory.stopMaintainingPreparedConnection(
                host: config.serverHost,
                port: config.serverPort,
                useTLS: config.httpMask.tls,
                serverName: config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
            )
        }
    }

    private func pullLoop() async {
        var retryCount = 0
        var retryDelayMs = 10
        while true {
            if state.withLock({ $0.closed }) { return }

            let opened: SudokuHTTPBodyReader
            do {
                opened = try await request(method: "GET", requestPath: pullPath, authPath: "/stream", body: Data())
            } catch {
                if state.withLock({ $0.closed }) || retryCount >= 12 {
                    markClosed(fatal: true)
                    return
                }
                retryCount += 1
                try? await Task.sleep(for: .milliseconds(retryDelayMs))
                retryDelayMs = min(retryDelayMs * 2, 250)
                continue
            }

            do {
                guard opened.status == 200 else { throw SudokuNativeError.connectionFailed("HTTPMask pull status \(opened.status)") }
                retryCount = 0
                retryDelayMs = 10
                let conts = state.withLock { s -> [CheckedContinuation<Void, Never>] in
                    s.pullReady = true
                    return drainWaitersLocked(&s)
                }
                for cont in conts { cont.resume() }
                var sawAny = false
                var pollLine = Data()
                while true {
                    let data = try await opened.readSome()
                    if data.isEmpty { break }
                    sawAny = true
                    if mode == .poll {
                        for byte in data where byte != 0x0d {
                            if byte == 0x0a {
                                if !pollLine.isEmpty {
                                    guard let decoded = Data(base64Encoded: pollLine) else {
                                        throw SudokuNativeError.protocolError("invalid HTTPMask poll payload")
                                    }
                                    await enqueueRX(decoded)
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
                        await enqueueRX(data)
                    }
                }
                if opened.streamEOF {
                    markReadEOF()
                    return
                }
                if !sawAny { try? await Task.sleep(for: .milliseconds(25)) }
            } catch {
                markClosed(fatal: true)
                return
            }
        }
    }

    private func enqueueRX(_ data: Data) async {
        let queueLimit = max(sudokuHTTPMaskMaxQueueBytes, data.count)
        while true {
            var toResume: [CheckedContinuation<Void, Never>] = []
            let step: Step<Void> = state.withLock { s in
                if s.closed { return .done(()) }
                if s.rxQueue.count + data.count > queueLimit { return .wait(s.generation) }
                s.rxQueue.append(data)
                toResume = drainWaitersLocked(&s)
                return .done(())
            }
            for cont in toResume { cont.resume() }
            switch step {
            case .done, .fail: return
            case .wait(let generation): await waitSignal(observed: generation)
            }
        }
    }

    private func pushLoop() async {
        let maxBatchBytes = mode == .poll ? 49_152 : 262_144
        let flushInterval: TimeInterval = 0.005
        while true {
            // 1. Wait for data, writeClosed, or closed.
            waitData: while true {
                let step: Step<Void> = state.withLock { s in
                    if s.closed || !s.txQueue.isEmpty || s.writeClosed { return .done(()) }
                    return .wait(s.generation)
                }
                switch step {
                case .done, .fail: break waitData
                case .wait(let generation): await waitSignal(observed: generation)
                }
            }
            if state.withLock({ $0.closed }) { return }

            // 2. Coalesce a batch up to maxBatchBytes, bounded by a short flush deadline.
            let flushDeadline = Date().addingTimeInterval(flushInterval)
            coalesce: while true {
                let step: Step<Void> = state.withLock { s in
                    if s.closed || s.writeClosed || s.txQueue.isEmpty { return .done(()) }
                    if s.txQueue.count >= maxBatchBytes { return .done(()) }
                    return .wait(s.generation)
                }
                switch step {
                case .done, .fail: break coalesce
                case .wait(let generation):
                    if Date() >= flushDeadline { break coalesce }
                    await waitSignal(observed: generation, until: flushDeadline)
                }
            }

            // 3. Read the batch (or determine we should send the FIN).
            var toResume: [CheckedContinuation<Void, Never>] = []
            let (batch, shouldFinishWrite, isClosed): (Data?, Bool, Bool) = state.withLock { s in
                if s.closed { return (nil, false, true) }
                if s.txQueue.isEmpty { return (nil, s.writeClosed, false) }
                let n = min(maxBatchBytes, s.txQueue.count)
                let batch = s.txQueue.read(max: n)
                if s.txQueue.isEmpty { s.txQueue.removeAll(keepingCapacity: false) }
                toResume = drainWaitersLocked(&s)
                return (batch, false, false)
            }
            for cont in toResume { cont.resume() }
            if isClosed { return }

            if shouldFinishWrite {
                do {
                    try await sendSessionControl(path: finPath)
                    completeWrite(nil)
                } catch {
                    completeWrite(error)
                    markClosed(fatal: true)
                }
                return
            }

            guard let batch, !batch.isEmpty else { continue }
            do {
                let body: Data
                let contentType: String
                if mode == .poll {
                    var encoded = batch.base64EncodedData()
                    encoded.append(0x0a)
                    body = encoded
                    contentType = "text/plain"
                } else {
                    body = batch
                    contentType = "application/octet-stream"
                }
                let opened = try await request(method: "POST", requestPath: pushPath, authPath: "/api/v1/upload", contentType: contentType, body: body)
                _ = try await opened.readAll(limit: 256)
                guard opened.status == 200 else { throw SudokuNativeError.connectionFailed("HTTPMask push status \(opened.status)") }
                let conts = state.withLock { s -> [CheckedContinuation<Void, Never>] in
                    s.pushReady = true
                    return drainWaitersLocked(&s)
                }
                for cont in conts { cont.resume() }
            } catch {
                markClosed(fatal: true)
                return
            }
        }
    }
}

nonisolated final class SudokuObfsTransport {
    enum Wire {
        case stream(BlockingProxyStream)
        case httpMask(SudokuHTTPMaskTransport)
    }

    private let wire: Wire
    private let tables: SudokuTables
    private var rng: SudokuXorshift64Star
    private var threshold: UInt64 = 0
    private var pureDecoder = SudokuPureDecoder()
    private var packedDecoder: SudokuPackedDecoder
    private let pureDownlink: Bool
    /// Short synchronous critical section around the decoder state — receive is single-flight
    /// by contract, so this is never held across the wire `await`. Send serialization is
    /// provided by the record-layer ``AsyncMutex`` (obfs `send`/`closeWrite` only ever run
    /// under it), so no send lock lives here.
    private let readLock = UnfairLock()

    init(wire: Wire, tables: SudokuTables, config: SudokuNativeConfig) throws {
        self.wire = wire
        self.tables = tables
        self.pureDownlink = config.pureDownlink
        let seedBytes = [UInt8](try SudokuNativeCrypto.randomData(count: 8))
        let seed = Int64(bitPattern: seedBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) })
        var seeded = SudokuXorshift64Star(seed: seed)
        threshold = seeded.pickPaddingThreshold(min: config.paddingMin, max: config.paddingMax)
        rng = seeded
        packedDecoder = tables.withDownlink { SudokuPackedDecoder(table: $0) }
    }

    func send(_ data: Data) async throws {
        let encoded = tables.withUplink { $0.encode(data, rng: &rng, paddingThreshold: threshold) }
        try await sendWire(encoded)
    }

    func receive(max: Int) async throws -> Data {
        guard max > 0 else { return Data() }
        let pending = try readLock.withLock { try drainDecoderPending(max: max) }
        if !pending.isEmpty { return pending }
        while true {
            let wireData = try await receiveWire(max: sudokuObfsWireReadSize(decodedRemaining: max, pureDownlink: pureDownlink, maxRaw: sudokuObfsReadChunkSize))
            let out = try readLock.withLock {
                try tables.withDownlink { table -> Data in
                    if pureDownlink {
                        return try pureDecoder.decode(wireData, table: table, limit: max)
                    }
                    return try packedDecoder.decode(wireData, table: table, limit: max)
                }
            }
            if out.isEmpty { continue }
            return out
        }
    }

    func readExact(_ count: Int) async throws -> Data {
        guard count > 0 else { return Data() }
        var out = Data(capacity: count)
        while out.count < count { out.append(try await receive(max: count - out.count)) }
        return out
    }

    func readExactAllowingEOF(_ count: Int, what: String) async throws -> Data? {
        guard count > 0 else { return Data() }
        var out = Data(capacity: count)
        while out.count < count {
            do {
                out.append(try await receive(max: count - out.count))
            } catch SudokuNativeError.closed {
                if out.isEmpty { return nil }
                throw SudokuNativeError.protocolError("truncated \(what)")
            }
        }
        return out
    }

    func close() {
        switch wire {
        case .stream(let stream): stream.cancel()
        case .httpMask(let mask): mask.close()
        }
    }

    func closeWrite() async throws {
        if case .httpMask(let mask) = wire {
            try await mask.closeWrite()
        }
    }

    func waitHTTPMaskReady(timeout: TimeInterval) async throws {
        if case .httpMask(let mask) = wire {
            try await mask.waitReady(timeout: timeout)
        }
    }

    private func sendWire(_ data: Data) async throws {
        switch wire {
        case .stream(let stream): try await stream.sendAll(data)
        case .httpMask(let mask): try await mask.send(data)
        }
    }

    private func receiveWire(max: Int) async throws -> Data {
        switch wire {
        case .stream(let stream): return try await stream.readSome(max: max)
        case .httpMask(let mask): return try await mask.receive(max: max)
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

nonisolated final class SudokuRecordStream {
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
    /// Short synchronous critical section around the *receive* state (`readBuffer`, `recvSeq`,
    /// decryptor) — receive is single-flight, so this is never held across the wire `await`.
    private let readLock = UnfairLock()
    /// Serializes the *send* funnel across the wire `await` (mux frames from N streams + the
    /// keepalive timer converge here). This is the mandatory record-layer send lock.
    private let sendLock = AsyncMutex()

    init(transport: SudokuObfsTransport, method: SudokuAEADMethod, baseSend: Data, baseRecv: Data) throws {
        self.transport = transport
        self.method = method
        self.baseSend = baseSend
        self.baseRecv = baseRecv
        self.sendEpoch = try SudokuNativeCrypto.randomNonZeroUInt32()
        self.sendSeq = try SudokuNativeCrypto.randomNonZeroUInt64()
    }

    func rekey(send: Data, recv: Data) async throws {
        try await sendLock.withLock {
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

    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        try await sendLock.withLock {
            if method == .none {
                try await transport.send(data)
                return
            }
            var offset = 0
            while offset < data.count {
                let maxPlain = 65535 - 12 - 16
                let count = min(maxPlain, data.count - offset)
                let chunk = data.rangeData(offset: offset, count: count)
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
                try await transport.send(frame)
                offset += count
                try maybeBumpSendEpoch(added: count)
            }
        }
    }

    func receive(max: Int) async throws -> Data {
        guard max > 0 else { return Data() }
        if let buffered = readLock.withLock({ readBuffer.isEmpty ? nil : readBuffer.read(max: max) }) {
            return buffered
        }
        if readLock.withLock({ method == .none }) { return try await transport.receive(max: max) }
        while true {
            guard let lenData = try await transport.readExactAllowingEOF(2, what: "record length") else {
                throw SudokuNativeError.closed
            }
            let bodyLen = try Self.parseRecordLength(lenData)
            let body: Data
            do {
                body = try await transport.readExact(bodyLen)
            } catch SudokuNativeError.closed {
                throw SudokuNativeError.protocolError("truncated record body")
            }
            let out: Data? = try readLock.withLock {
                let plain = try decryptRecord(body: body, bodyLen: bodyLen)
                if plain.isEmpty { return nil }
                if plain.count > max {
                    readBuffer.append(plain, from: max)
                    return plain.prefixData(max)
                }
                return plain
            }
            if let out { return out }
        }
    }

    func readExact(_ count: Int) async throws -> Data {
        guard count > 0 else { return Data() }
        var out = Data(capacity: count)
        while out.count < count { out.append(try await receive(max: count - out.count)) }
        return out
    }

    private static func parseRecordLength(_ lenData: Data) throws -> Int {
        let bodyLen = Int(UInt16(lenData[0]) << 8 | UInt16(lenData[1]))
        guard bodyLen >= 12 && bodyLen <= 65535 else { throw SudokuNativeError.protocolError("bad record length") }
        return bodyLen
    }

    private func decryptRecord(body: Data, bodyLen: Int) throws -> Data {
        let epoch = body.uint32BE(at: 0)
        let seq = body.uint64BE(at: 4)
        if recvInitialized {
            if epoch < recvEpoch { throw SudokuNativeError.protocolError("replayed record epoch") }
            if epoch == recvEpoch && seq != recvSeq { throw SudokuNativeError.protocolError("out of order record") }
            if epoch > recvEpoch && epoch - recvEpoch > 8 { throw SudokuNativeError.protocolError("record epoch jump") }
        }
        let header = body.prefixData(12)
        let ciphertext = body.rangeData(offset: 12, count: bodyLen - 12)
        let key = SudokuNativeCrypto.recordEpochKey(base: baseRecv, method: method, epoch: epoch)
        let plain = try SudokuNativeCrypto.open(method: method, key: key, nonce: header, ciphertext: ciphertext, aad: header)
        recvEpoch = epoch
        recvSeq = seq + 1
        recvInitialized = true
        return plain
    }

    func close() { transport.close() }

    func closeWrite() async throws {
        try await sendLock.withLock {
            try await transport.closeWrite()
        }
    }

    func waitHTTPMaskReady(timeout: TimeInterval) async throws {
        try await transport.waitHTTPMaskReady(timeout: timeout)
    }

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

nonisolated final class SudokuNativeClient {
    private let config: SudokuNativeConfig
    private let factory: SudokuConnectionFactory
    private let tables: SudokuTables

    init(configuration: ProxyConfiguration, factory: SudokuConnectionFactory) throws {
        self.config = try SudokuNativeConfig(configuration: configuration)
        self.factory = factory
        self.tables = try SudokuTables(config: config)
    }

    var shouldUseNativeMux: Bool { config.nativeMuxEnabled }

    func openTCP(host: String, port: UInt16) async throws -> SudokuRecordStream {
        let record = try await connectBase()
        try await writeKIP(record: record, type: 0x10, payload: SudokuAddress.encode(host: host, port: port))
        return record
    }

    func openUoT() async throws -> SudokuRecordStream {
        let record = try await connectBase()
        try await writeKIP(record: record, type: 0x12, payload: Data())
        return record
    }

    /// `ownsFactory` hands the client's factory to the mux session so pooled sessions tear
    /// down their own transport; leave it false when the caller owns the factory.
    func openMux(ownsFactory: Bool = false) async throws -> SudokuMuxClient {
        let record = try await connectBase()
        do {
            try await writeKIP(record: record, type: 0x11, payload: Data())
            try await record.waitHTTPMaskReady(timeout: 30)
            return SudokuMuxClient(record: record, factory: ownsFactory ? factory : nil)
        } catch {
            record.close()
            throw error
        }
    }

    private func connectBase() async throws -> SudokuRecordStream {
        let wire: SudokuObfsTransport.Wire
        if !config.httpMask.disable && config.httpMask.mode == .ws {
            wire = .stream(try await openHTTPMaskWebSocket())
        } else if !config.httpMask.disable && [SudokuHTTPMaskMode.stream, .poll, .auto].contains(config.httpMask.mode) {
            let early = try buildEarlyHandshakePayload()
            let mask: SudokuHTTPMaskTransport
            if config.httpMask.mode == .poll {
                mask = try await SudokuHTTPMaskTransport(config: config, factory: factory, mode: .poll, earlyRequestPayload: early.request)
            } else if config.httpMask.mode == .stream {
                mask = try await SudokuHTTPMaskTransport(config: config, factory: factory, mode: .stream, earlyRequestPayload: early.request)
            } else {
                do {
                    mask = try await SudokuHTTPMaskTransport(config: config, factory: factory, mode: .stream, earlyRequestPayload: early.request)
                } catch {
                    mask = try await SudokuHTTPMaskTransport(config: config, factory: factory, mode: .poll, earlyRequestPayload: early.request)
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
            try await performKIP(record: record)
            return record
        } else {
            let stream = try await factory.open(host: config.serverHost, port: config.serverPort, useTLS: false, serverName: nil)
            if !config.httpMask.disable && config.httpMask.mode == .legacy {
                let path = SudokuHTTPMaskPathRoot.apply(config.httpMask.pathRoot, to: "/api")
                let host = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
                let request = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 1048576\r\n\r\n"
                try await stream.sendAll(Data(request.utf8))
            }
            wire = .stream(stream)
        }

        let transport = try SudokuObfsTransport(wire: wire, tables: tables, config: config)
        let bases = SudokuNativeCrypto.pskBases(config.key)
        let record = try SudokuRecordStream(transport: transport, method: config.aeadMethod, baseSend: bases.c2s, baseRecv: bases.s2c)
        try await performKIP(record: record)
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
        let message = try parseKIP(plain)
        guard message.type == 0x02 else { throw SudokuNativeError.protocolError("bad early KIP server hello") }
        return try finishKIP(state: state, message: message)
    }

    private func encodeEarlyObfs(_ data: Data) throws -> Data {
        let seedBytes = [UInt8](try SudokuNativeCrypto.randomData(count: 8))
        let seed = Int64(bitPattern: seedBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) })
        var rng = SudokuXorshift64Star(seed: seed)
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
            let bodyOffset = offset + 2
            let header = data.rangeData(offset: bodyOffset, count: 12)
            let ciphertext = data.rangeData(offset: bodyOffset + 12, count: bodyLen - 12)
            let epoch = header.uint32BE(at: 0)
            let key = SudokuNativeCrypto.recordEpochKey(base: base, method: config.aeadMethod, epoch: epoch)
            out.append(try SudokuNativeCrypto.open(method: config.aeadMethod, key: key, nonce: header, ciphertext: ciphertext, aad: header))
            offset += 2 + bodyLen
            if out.count >= 6 {
                let kipLen = Int(UInt16(out[4]) << 8 | UInt16(out[5]))
                if out.count >= 6 + kipLen { break }
            }
        }
        guard !out.isEmpty else { throw SudokuNativeError.protocolError("short early record") }
        return out
    }

    private func openHTTPMaskWebSocket() async throws -> BlockingProxyStream {
        let host = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
        let defaultPort = config.httpMask.tls ? UInt16(443) : UInt16(80)
        let hostHeader = config.serverPort == defaultPort ? host : "\(host):\(config.serverPort)"
        let auth = httpMaskAuthToken(mode: "ws", method: "GET", path: "/ws")
        let path = appendHTTPMaskAuth(applyHTTPMaskPathRoot("/ws"), token: auth)
        return try await factory.openWebSocket(
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
        SudokuHTTPMaskPathRoot.apply(config.httpMask.pathRoot, to: path)
    }

    private func appendHTTPMaskAuth(_ path: String, token: String) -> String {
        path + (path.contains("?") ? "&" : "?") + "auth=\(token)"
    }

    private func httpMaskAuthToken(mode: String, method: String, path: String) -> String {
        SudokuHTTPMaskAuth.token(key: config.key, mode: mode, method: method, path: path)
    }

    private func performKIP(record: SudokuRecordStream) async throws {
        let (state, payload) = try makeKIPClientHelloPayload()
        try await writeKIP(record: record, type: 0x01, payload: payload)
        let message = try await readKIP(record: record)
        let session = try finishKIP(state: state, message: message)
        try await record.rekey(send: session.c2s, recv: session.s2c)
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
        var featureFlags = UInt32(0x1f).bigEndian
        payload.append(Data(bytes: &featureFlags, count: 4))
        if tables.sendsTableHint {
            var hint = tables.hint.bigEndian
            payload.append(Data(bytes: &hint, count: 4))
        }
        return (SudokuKIPClientState(privateKey: privateKey, nonce: nonce), payload)
    }

    private func finishKIP(state: SudokuKIPClientState, message msg: (type: UInt8, payload: Data)) throws -> (c2s: Data, s2c: Data) {
        guard msg.type == 0x02, msg.payload.count == 52 else { throw SudokuNativeError.protocolError("bad KIP server hello") }
        guard msg.payload.prefixData(16) == state.nonce else { throw SudokuNativeError.protocolError("KIP nonce mismatch") }
        let serverPub = msg.payload.rangeData(offset: 16, count: 32)
        let shared = try state.privateKey.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPub)).withUnsafeBytes { Data($0) }
        return SudokuNativeCrypto.sessionBases(psk: config.key, shared: shared, nonce: state.nonce)
    }

    private func writeKIP(record: SudokuRecordStream, type: UInt8, payload: Data) async throws {
        try await record.send(encodeKIP(type: type, payload: payload))
    }

    private func encodeKIP(type: UInt8, payload: Data) -> Data {
        var frame = Data([0x6b, 0x69, 0x70, type, UInt8(payload.count >> 8), UInt8(payload.count & 0xff)])
        frame.append(payload)
        return frame
    }

    private func readKIP(record: SudokuRecordStream) async throws -> (type: UInt8, payload: Data) {
        let header: Data
        do {
            header = try await record.readExact(6)
        } catch SudokuNativeError.closed {
            throw SudokuNativeError.protocolError("truncated KIP header")
        }
        guard header[0] == 0x6b, header[1] == 0x69, header[2] == 0x70 else { throw SudokuNativeError.protocolError("bad KIP magic") }
        let length = Int(UInt16(header[4]) << 8 | UInt16(header[5]))
        do {
            return (header[3], try await record.readExact(length))
        } catch SudokuNativeError.closed {
            throw SudokuNativeError.protocolError("truncated KIP payload")
        }
    }

    private func parseKIP(_ data: Data) throws -> (type: UInt8, payload: Data) {
        guard data.count >= 6 else { throw SudokuNativeError.protocolError("short KIP frame") }
        guard data[0] == 0x6b, data[1] == 0x69, data[2] == 0x70 else { throw SudokuNativeError.protocolError("bad KIP magic") }
        let length = Int(UInt16(data[4]) << 8 | UInt16(data[5]))
        guard data.count >= 6 + length else { throw SudokuNativeError.protocolError("truncated KIP frame \(data.count)/\(6 + length)") }
        return (data[3], data.rangeData(offset: 6, count: length))
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

nonisolated final class SudokuMuxClient: Multiplexer, @unchecked Sendable {
    private static let keepaliveInterval: TimeInterval = 15
    private let record: SudokuRecordStream
    /// Non-nil when the session owns its transport (pooled sessions); torn down on close.
    private let factory: SudokuConnectionFactory?
    private let condition = NSCondition()
    private let keepaliveTimer: DispatchSourceTimer
    private var readerTask: Task<Void, Never>?
    private var streams: [UInt32: SudokuMuxStream] = [:]
    private var nextStreamID: UInt32 = 0
    private var lastWrite = DispatchTime.now().uptimeNanoseconds
    private var closed = false

    /// Called once when the session becomes permanently unusable so the pool can evict it.
    var onClose: (() -> Void)?

    var isClosed: Bool {
        condition.lock()
        defer { condition.unlock() }
        return closed
    }

    /// Thread-safe count read off-queue by the pool's idle sweep.
    var activeStreamCount: Int {
        condition.lock()
        defer { condition.unlock() }
        return streams.count
    }

    init(record: SudokuRecordStream, factory: SudokuConnectionFactory? = nil) {
        self.record = record
        self.factory = factory
        keepaliveTimer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        keepaliveTimer.schedule(
            deadline: .now() + Self.keepaliveInterval,
            repeating: Self.keepaliveInterval
        )
        keepaliveTimer.setEventHandler { [weak self] in
            self?.sendKeepaliveIfIdle()
        }
        keepaliveTimer.resume()
        readerTask = Task { [weak self] in await self?.readerLoop() }
    }

    func dialTCP(host: String, port: UInt16) async throws -> SudokuMuxStream {
        let stream = SudokuMuxStream(client: self, id: allocateStreamID())
        condition.lock()
        if closed {
            condition.unlock()
            throw SudokuNativeError.closed
        }
        streams[stream.id] = stream
        condition.unlock()
        do {
            try await sendFrame(type: 0x01, streamID: stream.id, payload: SudokuAddress.encode(host: host, port: port))
        } catch {
            condition.lock()
            streams.removeValue(forKey: stream.id)
            condition.unlock()
            stream.markClosed(discardQueuedData: true, error: error)
            throw error
        }
        return stream
    }

    func sendFrame(type: UInt8, streamID: UInt32, payload: Data) async throws {
        guard payload.count <= 256 * 1024 else { throw SudokuNativeError.protocolError("mux frame too large") }
        condition.lock()
        let isClosed = closed
        condition.unlock()
        guard !isClosed else { throw SudokuNativeError.closed }
        var frame = Data([type])
        var sid = streamID.bigEndian
        var length = UInt32(payload.count).bigEndian
        frame.append(Data(bytes: &sid, count: 4))
        frame.append(Data(bytes: &length, count: 4))
        frame.append(payload)
        do {
            try await record.send(frame)
            condition.lock()
            lastWrite = DispatchTime.now().uptimeNanoseconds
            condition.unlock()
        } catch {
            close(error: error)
            throw error
        }
    }

    func removeStream(id: UInt32) {
        condition.lock()
        streams.removeValue(forKey: id)
        condition.unlock()
    }

    /// `error` non-nil for transport failure, nil for clean close.
    func close(error: Error? = nil) {
        condition.lock()
        if closed {
            condition.unlock()
            return
        }
        closed = true
        let streamsToClose = Array(streams.values)
        streams.removeAll()
        let closeCallback = onClose
        onClose = nil
        condition.broadcast()
        condition.unlock()
        keepaliveTimer.cancel()
        readerTask?.cancel()
        for stream in streamsToClose {
            stream.markClosed(discardQueuedData: true)
        }
        record.close()
        factory?.closeAll()
        closeCallback?()
    }

    private func allocateStreamID() -> UInt32 {
        condition.lock(); defer { condition.unlock() }
        repeat { nextStreamID &+= 1 } while nextStreamID == 0
        return nextStreamID
    }

    private func sendKeepaliveIfIdle() {
        let intervalNanoseconds = UInt64(Self.keepaliveInterval * 1_000_000_000)
        condition.lock()
        let shouldSend = !closed
            && DispatchTime.now().uptimeNanoseconds &- lastWrite >= intervalNanoseconds
        condition.unlock()
        if shouldSend {
            // Timer fires on a sync queue; hop to a Task for the async send.
            Task { [weak self] in try? await self?.sendFrame(type: 0x02, streamID: 0, payload: Data()) }
        }
    }

    private func readerLoop() async {
        while true {
            do {
                let header = try await record.readExact(9)
                let type = header[0]
                let streamID = header.uint32BE(at: 1)
                let length = Int(header.uint32BE(at: 5))
                guard length <= 256 * 1024 else { throw SudokuNativeError.protocolError("mux frame too large") }
                let payload = try await record.readExact(length)
                condition.lock()
                let stream = streams[streamID]
                condition.unlock()
                switch type {
                case 0x02:
                    guard let stream, !payload.isEmpty else { continue }
                    if case .overflow = stream.enqueue(payload) {
                        let error = SudokuNativeError.connectionFailed("mux receive queue full")
                        sudokuLogger.warning("[Sudoku-Mux] stream \(streamID) receive queue overflow, resetting stream")
                        stream.markClosed(discardQueuedData: true, error: error)
                        removeStream(id: streamID)
                        // Detached so the reader never blocks on the send mutex behind a
                        // parked sender — it must keep draining incoming frames.
                        Task { [weak self] in
                            try? await self?.sendFrame(type: 0x04, streamID: streamID, payload: Data("receive queue full".utf8))
                            try? await self?.sendFrame(type: 0x03, streamID: streamID, payload: Data())
                        }
                    }
                case 0x03:
                    if stream?.markRemoteWriteClosed() == true {
                        removeStream(id: streamID)
                    }
                case 0x04:
                    let rawMessage = String(data: payload, encoding: .utf8)?
                        .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                    let message = rawMessage.isEmpty ? "mux stream reset" : rawMessage
                    stream?.markClosed(
                        discardQueuedData: true,
                        error: SudokuNativeError.connectionFailed(message)
                    )
                    removeStream(id: streamID)
                default: throw SudokuNativeError.protocolError("bad mux frame")
                }
            } catch SudokuNativeError.closed {
                close()
                return
            } catch {
                condition.lock()
                let wasClosed = closed
                condition.unlock()
                if !wasClosed {
                    sudokuLogger.error("[Sudoku-Mux] reader failed: \(error.localizedDescription)")
                }
                close(error: error)
                return
            }
        }
    }
}

nonisolated final class SudokuMuxStream: @unchecked Sendable {
    enum EnqueueResult {
        case accepted
        case ignored
        case overflow
    }

    let id: UInt32
    private weak var client: SudokuMuxClient?
    private let condition = NSCondition()
    /// Serializes this stream's frame sends (data chunks vs the FIN) across the wire `await`,
    /// so no data frame is ever emitted after the stream's close frame.
    private let sendLock = AsyncMutex()
    private var queue = SudokuDataQueue()
    private var fullyClosed = false
    private var localReadClosed = false
    private var localWriteClosed = false
    private var remoteWriteClosed = false
    private var terminalError: Error?
    /// Single-flight receive slot. Every terminal path nils it under `condition` and resumes
    /// exactly once; the `fullyClosed`/read-closed gates ensure at most one path proceeds.
    private var pendingReceive: CheckedContinuation<Data?, Error>?
    private var pendingMax = 0

    init(client: SudokuMuxClient, id: UInt32) { self.client = client; self.id = id }

    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        try await sendLock.withLock {
            guard let client else { throw SudokuNativeError.closed }
            condition.lock()
            let cannotWrite = fullyClosed || localWriteClosed
            let error = terminalError
            condition.unlock()
            if let error { throw error }
            guard !cannotWrite else { throw SudokuNativeError.closed }

            var offset = 0
            while offset < data.count {
                let count = min(128 * 1024, data.count - offset)
                try await client.sendFrame(type: 0x02, streamID: id, payload: data.rangeData(offset: offset, count: count))
                offset += count
            }
        }
    }

    /// Receives one chunk; `nil` == EOF. Single-flight by contract.
    func receive(max: Int) async throws -> Data? {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            var deliver: (() -> Void)?
            condition.lock()
            if !queue.isEmpty {
                let out = queue.read(max: max)
                deliver = { continuation.resume(returning: out) }
            } else if fullyClosed {
                if let error = terminalError {
                    deliver = { continuation.resume(throwing: error) }
                } else {
                    deliver = { continuation.resume(returning: nil) }
                }
            } else if localReadClosed || remoteWriteClosed {
                deliver = { continuation.resume(returning: nil) }
            } else if pendingReceive != nil {
                deliver = { continuation.resume(throwing: SudokuNativeError.protocolError("concurrent mux receive")) }
            } else {
                pendingMax = max
                pendingReceive = continuation
            }
            condition.unlock()
            deliver?()
        }
    }

    func enqueue(_ data: Data) -> EnqueueResult {
        condition.lock()
        if fullyClosed || localReadClosed || remoteWriteClosed {
            condition.unlock()
            return .ignored
        }
        if let pending = pendingReceive {
            pendingReceive = nil
            let out: Data
            if data.count <= pendingMax {
                out = data
            } else {
                out = data.prefixData(pendingMax)
                queue.append(data, from: pendingMax)
            }
            condition.unlock()
            pending.resume(returning: out)
            return .accepted
        }
        guard queue.count + data.count <= sudokuMuxMaxQueueBytes else {
            condition.unlock()
            return .overflow
        }
        queue.append(data)
        condition.unlock()
        return .accepted
    }

    func closeWrite() async throws {
        condition.lock()
        if fullyClosed || localWriteClosed {
            condition.unlock()
            return
        }
        localWriteClosed = true
        let shouldRemove = remoteWriteClosed || localReadClosed
        condition.unlock()

        guard let client else { throw SudokuNativeError.closed }
        defer { if shouldRemove { client.removeStream(id: id) } }
        try await sendLock.withLock {
            try await client.sendFrame(type: 0x03, streamID: id, payload: Data())
        }
    }

    func closeRead() {
        var deliver: (() -> Void)?
        condition.lock()
        if fullyClosed || localReadClosed {
            condition.unlock()
            return
        }
        localReadClosed = true
        queue.removeAll(keepingCapacity: false)
        let shouldRemove = localWriteClosed
        if let pending = pendingReceive {
            pendingReceive = nil
            deliver = { pending.resume(returning: nil) }
        }
        condition.unlock()
        if shouldRemove {
            client?.removeStream(id: id)
        }
        deliver?()
    }

    func close() {
        // Terminal transition + continuation resume run under the state lock only (never the
        // send mutex), so close always fires and unblocks a parked sender. The best-effort FIN
        // is dispatched to a Task, ordered after in-flight data via the send mutex.
        var deliver: (() -> Void)?
        let shouldSendClose: Bool
        condition.lock()
        if fullyClosed {
            condition.unlock()
            return
        }
        shouldSendClose = !localWriteClosed
        fullyClosed = true
        localReadClosed = true
        localWriteClosed = true
        terminalError = nil
        queue.removeAll(keepingCapacity: false)
        if let pending = pendingReceive {
            pendingReceive = nil
            deliver = { pending.resume(returning: nil) }
        }
        condition.unlock()

        if let client {
            if shouldSendClose {
                Task { [weak self] in await self?.sendCloseFrame(to: client) }
            }
            client.removeStream(id: id)
        }
        deliver?()
    }

    private func sendCloseFrame(to client: SudokuMuxClient) async {
        await sendLock.withLock {
            try? await client.sendFrame(type: 0x03, streamID: id, payload: Data())
        }
    }

    @discardableResult
    func markRemoteWriteClosed() -> Bool {
        var deliver: (() -> Void)?
        condition.lock()
        if fullyClosed {
            condition.unlock()
            return false
        }
        remoteWriteClosed = true
        let shouldRemove = localWriteClosed && (remoteWriteClosed || localReadClosed)
        if queue.isEmpty, let pending = pendingReceive {
            pendingReceive = nil
            deliver = { pending.resume(returning: nil) }
        }
        condition.unlock()
        deliver?()
        return shouldRemove
    }

    func markClosed(discardQueuedData: Bool = false, error: Error? = nil) {
        var deliver: (() -> Void)?
        condition.lock()
        if fullyClosed {
            condition.unlock()
            return
        }
        fullyClosed = true
        terminalError = error
        if discardQueuedData {
            queue.removeAll(keepingCapacity: false)
        }
        if let pending = pendingReceive {
            pendingReceive = nil
            if let error {
                deliver = { pending.resume(throwing: error) }
            } else {
                deliver = { pending.resume(returning: nil) }
            }
        }
        condition.unlock()
        deliver?()
    }
}

nonisolated final class SudokuTCPProxyConnection:
    AsyncProxyConnection,
    @unchecked Sendable
{
    private let stream: SudokuRecordStream
    private var closed = false

    init(stream: SudokuRecordStream) { self.stream = stream; super.init() }
    override var isConnected: Bool { !lock.withLock { closed } }

    override func sendRaw(_ data: Data) async throws {
        if lock.withLock({ closed }) { throw SudokuNativeError.closed }
        try await stream.send(data)
    }

    override func receiveRaw() async throws -> Data? {
        if lock.withLock({ closed }) { return nil }
        do {
            return try await stream.receive(max: sudokuTCPReceiveChunkSize)
        } catch SudokuNativeError.closed {
            return nil
        }
    }

    override func closeWrite() async throws {
        if lock.withLock({ closed }) { throw SudokuNativeError.closed }
        try await stream.closeWrite()
    }

    override func performCancel() { lock.withLock { closed = true }; stream.close() }
}

nonisolated final class SudokuMuxTCPProxyConnection:
    AsyncProxyConnection,
    @unchecked Sendable
{
    private let client: SudokuMuxClient
    private let stream: SudokuMuxStream
    private let closesClientOnClose: Bool
    private var onClose: (() -> Void)?
    private var closed = false
    private var readEOF = false

    init(
        client: SudokuMuxClient,
        stream: SudokuMuxStream,
        closesClientOnClose: Bool = true,
        onClose: (() -> Void)? = nil
    ) {
        self.client = client
        self.stream = stream
        self.closesClientOnClose = closesClientOnClose
        self.onClose = onClose
        super.init()
    }

    override var isConnected: Bool { !lock.withLock { closed } && !client.isClosed }

    override func sendRaw(_ data: Data) async throws {
        if lock.withLock({ closed }) { throw SudokuNativeError.closed }
        do {
            try await stream.send(data)
        } catch {
            closeResources(closeStream: true)
            throw error
        }
    }

    override func receiveRaw() async throws -> Data? {
        if lock.withLock({ closed || readEOF }) { return nil }
        do {
            if let data = try await stream.receive(max: sudokuTCPReceiveChunkSize), !data.isEmpty {
                return data
            }
            lock.withLock { readEOF = true }
            return nil
        } catch {
            closeResources(closeStream: false)
            throw error
        }
    }

    override func closeWrite() async throws {
        if lock.withLock({ closed }) { throw SudokuNativeError.closed }
        try await stream.closeWrite()
    }

    override func performCancel() {
        closeResources(closeStream: true)
    }

    private func closeResources(closeStream: Bool) {
        let callback: (() -> Void)? = lock.withLock {
            guard !closed else { return nil }
            closed = true
            let callback = onClose
            onClose = nil
            return callback
        }
        if closeStream { stream.close() }
        if closesClientOnClose { client.close() }
        callback?()
    }
}

nonisolated final class SudokuUDPProxyConnection: AsyncProxyConnection, @unchecked Sendable {
    private let stream: SudokuRecordStream
    private let destinationHost: String
    private let destinationPort: UInt16
    private var closed = false

    init(stream: SudokuRecordStream, destinationHost: String, destinationPort: UInt16) {
        self.stream = stream
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        super.init()
    }

    override var isConnected: Bool { !lock.withLock { closed } }

    override func sendRaw(_ data: Data) async throws {
        if lock.withLock({ closed }) { throw SudokuNativeError.closed }
        let address = try SudokuAddress.encode(host: destinationHost, port: destinationPort)
        guard address.count <= UInt16.max else { throw SudokuNativeError.protocolError("UoT address too large") }
        guard data.count <= UInt16.max else { throw SudokuNativeError.protocolError("UoT payload too large") }
        var frame = Data([UInt8(address.count >> 8), UInt8(address.count & 0xff), UInt8(data.count >> 8), UInt8(data.count & 0xff)])
        frame.append(address)
        frame.append(data)
        try await stream.send(frame)
    }

    override func receiveRaw() async throws -> Data? {
        if lock.withLock({ closed }) { return nil }
        do {
            let header = try await stream.readExact(4)
            let addrLen = Int(UInt16(header[0]) << 8 | UInt16(header[1]))
            let payloadLen = Int(UInt16(header[2]) << 8 | UInt16(header[3]))
            guard addrLen > 0 && addrLen <= 64 * 1024 else { throw SudokuNativeError.protocolError("bad UoT address length") }
            guard payloadLen <= 64 * 1024 else { throw SudokuNativeError.protocolError("bad UoT payload length") }
            _ = try await stream.readExact(addrLen)
            return try await stream.readExact(payloadLen)
        } catch SudokuNativeError.closed {
            return nil
        }
    }

    override func performCancel() { lock.withLock { closed = true }; stream.close() }
}
