//
//  SudokuProxyConnection.swift
//  Anywhere
//
//  Created by saba-futai on 4/23/26.
//

// MARK: Various code quality violation issues in this file (handler patterns), consider refactor

import Foundation
import Darwin
import CryptoKit
import Security
import Synchronization

nonisolated private let sudokuLogger = AnywhereLogger(category: "SudokuProxyConnection")
nonisolated private let sudokuObfsReadChunkSize = 128 * 1024
nonisolated private let sudokuTCPReceiveChunkSize = 64 * 1024
nonisolated private let sudokuHTTPMaskMaxQueueBytes = 4 * 1024 * 1024
nonisolated private let sudokuHTTPMaskMaxPollLineBytes = 256 * 1024
nonisolated private let sudokuMuxMaxQueueBytes = 4 * 1024 * 1024
nonisolated private let sudokuHTTPMaskStreamEOFHeader = "x-sudoku-stream-eof"

nonisolated private enum SudokuHTTPMaskAuth {
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

nonisolated private enum SudokuHTTPMaskPathRoot {
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

nonisolated private struct SudokuDataQueue {
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

nonisolated private enum SudokuNativeCrypto {
    static func randomData(count: Int) throws -> Data {
        guard count > 0 else { return Data() }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { raw -> OSStatus in
            guard let base = raw.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "random generator failed")) }
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
            guard ciphertext.count >= 16 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "short AES-GCM frame")) }
            let split = ciphertext.count - 16
            do {
                let box = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: nonce),
                    ciphertext: ciphertext.prefix(split),
                    tag: ciphertext.suffix(16)
                )
                return try AES.GCM.open(box, using: SymmetricKey(data: key.prefix(16)), authenticating: aad)
            } catch {
                throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "AES-GCM open failed"))
            }
        case .chacha20Poly1305:
            guard ciphertext.count >= 16 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "short ChaCha20-Poly1305 frame")) }
            let split = ciphertext.count - 16
            do {
                let box = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonce),
                    ciphertext: ciphertext.prefix(split),
                    tag: ciphertext.suffix(16)
                )
                return try ChaChaPoly.open(box, using: SymmetricKey(data: key.prefix(32)), authenticating: aad)
            } catch {
                throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "ChaCha20-Poly1305 open failed"))
            }
        case .none:
            return ciphertext
        }
    }
}

nonisolated final class SudokuNativeConfig: Sendable {
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
            throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "missing protocol settings"))
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

nonisolated private struct SudokuTableCacheKey: Hashable {
    let key: String
    let asciiMode: String
    let customTable: String
}

nonisolated private enum SudokuTableCache {
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

nonisolated final class SudokuTables: Sendable {
    /// The table pair is immutable after construction (`SudokuTable`/`SudokuTablePair` are
    /// `Sendable`), so it's shared read-only — no lock. Multiple `SudokuTables` may share the
    /// same cached pair; that's safe precisely because nothing mutates it.
    private let pair: SudokuTablePair
    let sendsTableHint: Bool

    init(config: SudokuNativeConfig) throws {
        sendsTableHint = config.sendsTableHint
        pair = try SudokuTableCache.pair(for: config)
    }

    func withUplink<T>(_ body: (SudokuTable) throws -> T) rethrows -> T {
        try body(pair.uplink)
    }

    func withDownlink<T>(_ body: (SudokuTable) throws -> T) rethrows -> T {
        try body(pair.downlink)
    }

    var hint: UInt32 { pair.uplink.hint }
}

/// An async byte stream over a ``ProxyConnection``, with a leftover-read buffer.
///
/// Send is serialized by the caller (the record-layer send chain funnels every
/// write, and each per-request HTTPMask stream is used by one task), so this holds no
/// send lock. Receive is single-flight by contract, so `pending` is only touched under
/// a short synchronous `Mutex` — never across the wire `await`.
nonisolated final class BlockingProxyStream: Sendable {
    private let connection: ProxyConnection
    private let closed = Atomic<Bool>(false)
    private let pending = Mutex(SudokuDataQueue())

    init(connection: ProxyConnection) { self.connection = connection }

    func sendAll(_ data: Data) async throws {
        if data.isEmpty { return }
        if isClosed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        try await connection.sendRaw(data)
    }

    func readSome(max: Int) async throws -> Data {
        guard max > 0 else { return Data() }
        if let buffered = pending.withLock({ $0.isEmpty ? nil : $0.read(max: max) }) {
            return buffered
        }
        if isClosed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        guard let data = try await connection.receiveRaw(), !data.isEmpty else {
            markClosed()
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        if data.count > max {
            pending.withLock { $0.append(data, from: max) }
            return data.prefixData(max)
        }
        return data
    }

    func readExact(_ count: Int) async throws -> Data {
        guard count > 0 else { return Data() }
        var out = Data(capacity: count)
        pending.withLock { pending in
            if !pending.isEmpty { pending.drain(exact: count, into: &out) }
        }
        while out.count < count {
            if isClosed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
            guard let data = try await connection.receiveRaw(), !data.isEmpty else {
                markClosed()
                throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
            }
            let need = count - out.count
            if data.count > need {
                out.append(data.prefixData(need))
                pending.withLock { $0.append(data, from: need) }
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
        closed.load(ordering: .acquiring)
    }

    private func markClosed() {
        closed.store(true, ordering: .releasing)
    }
}

private nonisolated extension Data {
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

nonisolated final class SudokuConnectionFactory: Sendable {
    private struct PreparedKey: Hashable {
        let host: String
        let port: UInt16
        let useTLS: Bool
        let serverName: String
    }

    private final class PreparedConnection: Sendable {
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

    /// Prepared-connection pool state. Formerly guarded by an `NSCondition` used as a plain
    /// mutex; delivery is now via the async preparation `Task`s, so no thread ever parks here.
    /// `generation`/`waiters` implement a generation-counted async broadcast so callers waiting
    /// on the pool sleep until a transition (a connection lands, a pending drops, or close) or
    /// their deadline, rather than polling.
    private struct PreparedState {
        var preparedConnections: [PreparedKey: [PreparedConnection]] = [:]
        var pendingPreparations: [PreparedKey: Int] = [:]
        var maintainedPreparations: [PreparedKey: Int] = [:]
        var preparedClosed = false
        /// Pending TTL-expiry and maintenance-retry timers, so `closeAll` can cancel them.
        var scheduledTasks: [Int: Task<Void, Never>] = [:]
        var nextScheduledTaskID = 0
        var generation: UInt64 = 0
        var nextWaiterID: UInt64 = 0
        var waiters: [(id: UInt64, cont: AsyncStream<Never>.Continuation)] = []
    }
    private let preparedState = Mutex(PreparedState())

    /// Bumps `generation` and returns every parked waiter to resume (outside the lock).
    private func drainPreparedWaitersLocked(_ s: inout PreparedState) -> [AsyncStream<Never>.Continuation] {
        s.generation &+= 1
        let conts = s.waiters.map { $0.cont }
        s.waiters.removeAll(keepingCapacity: true)
        return conts
    }

    /// Suspends until the next prepared-pool broadcast. `observed` is the generation read under the
    /// lock at the caller's decision point, so a broadcast racing in before registration is not lost.
    /// Cancellation-aware: a cancelled waiter removes itself and resumes rather than leaking.
    private func waitPreparedSignal(observed: UInt64) async {
        let id = preparedState.withLock { s -> UInt64 in
            let id = s.nextWaiterID
            s.nextWaiterID &+= 1
            return id
        }
        let stream: AsyncStream<Never>? = preparedState.withLock { s -> AsyncStream<Never>? in
            if s.generation != observed { return nil }
            let (stream, cont) = AsyncStream.makeStream(of: Never.self)
            s.waiters.append((id: id, cont: cont))
            return stream
        }
        guard let stream else { return }
        for await _ in stream {}
        preparedState.withLock { s in s.waiters.removeAll { $0.id == id } }
    }

    /// Suspends until a prepared-pool broadcast or `deadline`, whichever comes first.
    private func waitPreparedSignal(observed: UInt64, until deadline: Date) async {
        let interval = deadline.timeIntervalSinceNow
        guard interval > 0 else { return }
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.waitPreparedSignal(observed: observed) }
            group.addTask { try? await Task.sleep(for: .seconds(interval)) }
            _ = await group.next()
            group.cancelAll()
        }
    }

    init(configuration: ProxyConfiguration, initialTunnel: ProxyConnection?, directDialHost: String) {
        self.configuration = configuration
        self.stateLock = Mutex(State(initialTunnel: initialTunnel))
        self.directDialHost = directDialHost
    }

    func open(host: String, port: UInt16, useTLS: Bool, serverName: String?) async throws -> BlockingProxyStream {
        if stateLock.withLock({ $0.closed }) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        let key = preparedKey(host: host, port: port, useTLS: useTLS, serverName: serverName)
        if let prepared = await takePreparedConnection(for: key) {
            return BlockingProxyStream(connection: prepared.connection)
        }
        let connection = try await openProxyConnection(host: host, port: port, useTLS: useTLS, serverName: serverName)
        guard retainConnection(connection) else {
            connection.cancel()
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
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
        let closed = preparedState.withLock { state -> Bool in
            if state.preparedClosed { return true }
            state.maintainedPreparations[key] = 1
            return false
        }
        if closed { return }
        ensurePreparedConnections(for: key, targetCount: 1)
    }

    func stopMaintainingPreparedConnection(host: String, port: UInt16, useTLS: Bool, serverName: String?) {
        let key = preparedKey(host: host, port: port, useTLS: useTLS, serverName: serverName)
        preparedState.withLock { _ = $0.maintainedPreparations.removeValue(forKey: key) }
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
        // The prepared-connection pool is fed by async preparation tasks; sleep on the pool's
        // async broadcast until a connection lands (or close/deadline) rather than polling.
        while true {
            try Task.checkCancellation()
            let (ready, closed, generation) = preparedState.withLock { state in
                (!(state.preparedConnections[key]?.isEmpty ?? true), state.preparedClosed, state.generation)
            }
            if ready { return }
            if closed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
            if Date() >= deadline {
                throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "timeout waiting for prepared HTTPMask upload"))
            }
            await waitPreparedSignal(observed: generation, until: deadline)
        }
    }

    private func ensurePreparedConnections(for key: PreparedKey, targetCount: Int) {
        guard targetCount > 0 else { return }
        let needed = preparedState.withLock { state -> Int in
            if state.preparedClosed { return 0 }
            let readyCount = state.preparedConnections[key]?.count ?? 0
            let pendingCount = state.pendingPreparations[key] ?? 0
            let needed = max(0, targetCount - readyCount - pendingCount)
            if needed > 0 {
                state.pendingPreparations[key] = pendingCount + needed
            }
            return needed
        }
        guard needed > 0 else { return }

        for _ in 0..<needed {
            Task { [weak self] in
                guard let self else { return }
                let result: Result<ProxyConnection, Error>
                do {
                    result = .success(try await self.openProxyConnection(
                        host: key.host,
                        port: key.port,
                        useTLS: key.useTLS,
                        serverName: key.serverName
                    ))
                } catch {
                    result = .failure(error)
                }
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
        if stateLock.withLock({ $0.closed }) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        let base = try await openProxyConnection(host: host, port: port, useTLS: useTLS, serverName: serverName)
        guard retainConnection(base) else {
            base.cancel()
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
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
            try await ws.performUpgrade()
        } catch {
            releaseConnection(base)
            ws.cancel()
            base.cancel()
            throw error
        }
        let connection = WebSocketProxyConnection(wsConnection: ws)
        guard replaceConnection(base, with: connection) else {
            connection.cancel()
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        return BlockingProxyStream(connection: connection)
    }

    func closeAll() {
        var waitersToWake: [AsyncStream<Never>.Continuation] = []
        let scheduledTasks: [Task<Void, Never>] = preparedState.withLock { state in
            state.preparedClosed = true
            state.preparedConnections.removeAll()
            state.pendingPreparations.removeAll()
            state.maintainedPreparations.removeAll()
            let tasks = Array(state.scheduledTasks.values)
            state.scheduledTasks.removeAll()
            waitersToWake = drainPreparedWaitersLocked(&state)
            return tasks
        }
        for cont in waitersToWake { cont.finish() }
        for task in scheduledTasks { task.cancel() }

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
            let taken: (connection: PreparedConnection, maintainedCount: Int?)?
            let shouldWait: Bool
            let generation: UInt64
            (taken, shouldWait, generation) = preparedState.withLock { state -> ((connection: PreparedConnection, maintainedCount: Int?)?, Bool, UInt64) in
                if var ready = state.preparedConnections[key], !ready.isEmpty {
                    let connection = ready.removeFirst()
                    if ready.isEmpty {
                        state.preparedConnections.removeValue(forKey: key)
                    } else {
                        state.preparedConnections[key] = ready
                    }
                    return ((connection, state.maintainedPreparations[key]), false, state.generation)
                }
                let shouldWait = !state.preparedClosed && (state.pendingPreparations[key] ?? 0) > 0
                return (nil, shouldWait, state.generation)
            }
            if let taken {
                if let maintainedCount = taken.maintainedCount {
                    ensurePreparedConnections(for: key, targetCount: maintainedCount)
                }
                return taken.connection
            }
            // Sleep on the pool's async broadcast until an in-flight preparation lands (or the
            // deadline), rather than parking a cooperative thread; otherwise dial fresh.
            guard shouldWait, Date() < deadline else { return nil }
            await waitPreparedSignal(observed: generation, until: deadline)
            if Task.isCancelled { return nil }
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

        var waitersToWake: [AsyncStream<Never>.Continuation] = []
        let acceptedPrepared: PreparedConnection? = preparedState.withLock { state in
            decrementPendingPreparationLocked(&state, for: key)
            if let prepared, !state.preparedClosed {
                state.preparedConnections[key, default: []].append(prepared)
            }
            waitersToWake = drainPreparedWaitersLocked(&state)
            return state.preparedClosed ? nil : prepared
        }
        for cont in waitersToWake { cont.finish() }

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
        let conts = preparedState.withLock { state -> [AsyncStream<Never>.Continuation] in
            decrementPendingPreparationLocked(&state, for: key)
            return drainPreparedWaitersLocked(&state)
        }
        for cont in conts { cont.finish() }
    }

    private func decrementPendingPreparationLocked(_ state: inout PreparedState, for key: PreparedKey) {
        let remaining = max(0, (state.pendingPreparations[key] ?? 1) - 1)
        if remaining == 0 {
            state.pendingPreparations.removeValue(forKey: key)
        } else {
            state.pendingPreparations[key] = remaining
        }
    }

    private func expirePreparedConnection(_ prepared: PreparedConnection, for key: PreparedKey) {
        scheduleAfter(Self.preparedConnectionTTL) { [weak self] in
            guard let self else { return }
            let expired: Bool = self.preparedState.withLock { state in
                guard var ready = state.preparedConnections[key],
                      let index = ready.firstIndex(where: { $0 === prepared }) else { return false }
                ready.remove(at: index)
                if ready.isEmpty {
                    state.preparedConnections.removeValue(forKey: key)
                } else {
                    state.preparedConnections[key] = ready
                }
                return true
            }
            if expired {
                self.releaseConnection(prepared.connection)
                prepared.connection.cancel()
                self.refillMaintainedPreparation(for: key)
            }
        }
    }

    private func refillMaintainedPreparation(for key: PreparedKey) {
        let targetCount = preparedState.withLock { $0.maintainedPreparations[key] }
        if let targetCount {
            ensurePreparedConnections(for: key, targetCount: targetCount)
        }
    }

    private func scheduleMaintainedPreparationRetry(for key: PreparedKey) {
        scheduleAfter(Self.preparationRetryInterval) { [weak self] in
            self?.refillMaintainedPreparation(for: key)
        }
    }

    /// Runs `operation` after `delay`, unless the factory closes first. The timer is a tracked
    /// `Task` so `closeAll` can cancel any still-pending expiry/retry.
    private func scheduleAfter(_ delay: TimeInterval, _ operation: @escaping @Sendable () -> Void) {
        let id: Int? = preparedState.withLock { state in
            guard !state.preparedClosed else { return nil }
            let id = state.nextScheduledTaskID
            state.nextScheduledTaskID += 1
            return id
        }
        guard let id else { return }
        let task = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard let self, !Task.isCancelled else { return }
            // Deregister; a nil removal means `closeAll` already pulled (and cancelled) us.
            let stillTracked = self.preparedState.withLock { $0.scheduledTasks.removeValue(forKey: id) != nil }
            guard stillTracked else { return }
            operation()
        }
        let closedNow = preparedState.withLock { state -> Bool in
            guard !state.preparedClosed else { return true }
            state.scheduledTasks[id] = task
            return false
        }
        if closedNow { task.cancel() }
    }

    private func openProxyConnection(
        host: String,
        port: UInt16,
        useTLS: Bool,
        serverName: String?
    ) async throws -> ProxyConnection {
        if let tunnel = stateLock.withLock({ (state: inout State) -> ProxyConnection? in
            let current = state.initialTunnel
            state.initialTunnel = nil
            return current
        }) {
            return tunnel
        }

        if let chain = configuration.chain, !chain.isEmpty {
            return try await buildChainTunnel(
                chain: chain,
                index: 0,
                currentTunnel: nil,
                targetHost: host,
                targetPort: port
            )
        }

        if useTLS {
            let tls = TLSClient(configuration: TLSConfiguration(serverName: serverName ?? host, alpn: ["http/1.1"]))
            guard retainTLSClient(tls) else {
                throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
            }
            do {
                let connection = try await tls.connect(host: directDialHost, port: port)
                releaseTLSClient(tls)
                return TLSProxyConnection(tlsConnection: connection)
            } catch {
                releaseTLSClient(tls)
                throw error
            }
        }

        let transport = TCPTransport(host: directDialHost, port: port, resolvesViaProxyDNS: true)
        guard retainTransport(transport) else {
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        do {
            try await transport.connect()
        } catch {
            releaseTransport(transport)
            throw error
        }
        releaseTransport(transport)
        return DirectProxyConnection(transport: transport)
    }

    private func buildChainTunnel(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        targetHost: String,
        targetPort: UInt16
    ) async throws -> ProxyConnection {
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
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
        }
        let connection = try await client.connect(to: nextHost, port: nextPort)
        if index + 1 < chain.count {
            return try await buildChainTunnel(
                chain: chain,
                index: index + 1,
                currentTunnel: connection,
                targetHost: targetHost,
                targetPort: targetPort
            )
        }
        return connection
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

private nonisolated func sudokuReadHTTPLine(
    from stream: BlockingProxyStream,
    maxBytes: Int = 8 * 1024
) async throws -> String {
    var data = Data()
    while true {
        let byte = try await stream.readExact(1)[0]
        if byte == 0x0a { break }
        if byte != 0x0d { data.append(byte) }
        if data.count > maxBytes {
            throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "HTTP line too long"))
        }
    }
    return String(data: data, encoding: .utf8) ?? ""
}

nonisolated private final class SudokuHTTPBodyReader {
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
                    throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad chunk length"))
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
        catch AnywhereError.proxy(.sudoku, .connectionClosed) {
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

nonisolated final class SudokuHTTPMaskTransport: Sendable {
    private let config: SudokuNativeConfig
    private let factory: SudokuConnectionFactory
    private let mode: SudokuHTTPMaskMode
    private let earlyRequestPayload: Data?

    /// Request paths built once by `authorize()` (awaited in `init` before the loops start), so
    /// set-once is compiler-checked rather than a bare-var contract.
    private struct Paths {
        let pullPath: String
        let pushPath: String
        let finPath: String
        let closePath: String
    }
    private let paths: Paths

    /// The early-handshake payload observed during `authorize()`; read by the record layer.
    var earlyResponsePayload: Data { state.withLock { $0.earlyResponsePayload } }

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
        var earlyResponsePayload = Data()
        var runTask: Task<Void, Never>?
        var generation: UInt64 = 0
        var nextWaiterID: UInt64 = 0
        var waiters: [(id: UInt64, cont: AsyncStream<Never>.Continuation)] = []
    }
    private let state = Mutex(State())

    init(config: SudokuNativeConfig, factory: SudokuConnectionFactory, mode: SudokuHTTPMaskMode, earlyRequestPayload: Data? = nil) async throws {
        let earlyRequest = earlyRequestPayload?.isEmpty == false ? earlyRequestPayload : nil
        self.config = config
        self.factory = factory
        self.mode = mode
        self.earlyRequestPayload = earlyRequest
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
        let auth = try await Self.authorize(config: config, factory: factory, mode: mode, earlyRequestPayload: earlyRequest)
        self.paths = auth.paths
        state.withLock { $0.earlyResponsePayload = auth.earlyResponse }
        let run = Task {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await self.pullLoop() }
                group.addTask { await self.pushLoop() }
            }
        }
        state.withLock { $0.runTask = run }
    }

    // MARK: Async broadcast (replaces the single NSCondition)

    /// Bumps `generation` and returns every parked waiter to resume (outside the lock).
    private func drainWaitersLocked(_ s: inout State) -> [AsyncStream<Never>.Continuation] {
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
        // Enroll a finishing `AsyncStream` under the lock, re-checking the generation so a broadcast
        // racing in before registration isn't lost. A drain `finish()`es it; a cancellation ends the
        // `for await` too, and the post-loop cleanup removes a still-registered (cancelled) waiter.
        let stream: AsyncStream<Never>? = state.withLock { s -> AsyncStream<Never>? in
            if s.generation != observed { return nil }
            let (stream, cont) = AsyncStream.makeStream(of: Never.self)
            s.waiters.append((id: id, cont: cont))
            return stream
        }
        guard let stream else { return }
        for await _ in stream {}
        state.withLock { s in s.waiters.removeAll { $0.id == id } }
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
            var toResume: [AsyncStream<Never>.Continuation] = []
            let step: Step<Void> = state.withLock { s in
                if s.closed || s.writeClosed { return .fail(AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))) }
                if s.txQueue.count + data.count > queueLimit { return .wait(s.generation) }
                s.txQueue.append(data)
                toResume = drainWaitersLocked(&s)
                return .done(())
            }
            for cont in toResume { cont.finish() }
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
            var toResume: [AsyncStream<Never>.Continuation] = []
            let step: Step<Data> = state.withLock { s in
                if !s.rxQueue.isEmpty {
                    let out = s.rxQueue.read(max: max)
                    if s.rxQueue.isEmpty { s.rxQueue.removeAll(keepingCapacity: false) }
                    toResume = drainWaitersLocked(&s)
                    return .done(out)
                }
                if s.readEOF { return .fail(AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))) }
                if s.closed {
                    return .fail(s.fatal ? AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask closed")) : AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)))
                }
                return .wait(s.generation)
            }
            for cont in toResume { cont.finish() }
            switch step {
            case .done(let out): return out
            case .fail(let error): throw error
            case .wait(let generation): await waitSignal(observed: generation)
            }
        }
    }

    func close() {
        markClosed(fatal: false)
        // Best-effort session-control close frame; the connection is already down for callers.
        let path = paths.closePath
        Task { [weak self] in try? await self?.sendSessionControl(path: path) }
    }

    func waitReady(timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        ready: while true {
            try Task.checkCancellation()
            let step: Step<Void> = state.withLock { s in
                if s.pullReady && s.pushReady { return .done(()) }
                if s.closed { return .fail(AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask closed before tunnel became ready"))) }
                return .wait(s.generation)
            }
            switch step {
            case .done: break ready
            case .fail(let error): throw error
            case .wait(let generation):
                if Date() >= deadline {
                    throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "timeout waiting for HTTPMask tunnel readiness"))
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

    private static func hostHeader(config: SudokuNativeConfig) -> String {
        let host = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
        if (config.httpMask.tls && config.serverPort == 443) || (!config.httpMask.tls && config.serverPort == 80) { return host }
        return "\(host):\(config.serverPort)"
    }

    private static func applyPathRoot(config: SudokuNativeConfig, _ path: String) -> String {
        SudokuHTTPMaskPathRoot.apply(config.httpMask.pathRoot, to: path)
    }

    private static func authToken(config: SudokuNativeConfig, mode: String, method: String, path: String) -> String {
        SudokuHTTPMaskAuth.token(key: config.key, mode: mode, method: method, path: path)
    }

    private static func appendAuth(_ path: String, token: String) -> String {
        path + (path.contains("?") ? "&" : "?") + "auth=\(token)"
    }

    private static func appendEarlyData(_ path: String, payload: Data?) -> String {
        guard let payload, !payload.isEmpty else { return path }
        let encoded = payload.base64URLEncodedString()
        return path + (path.contains("?") ? "&" : "?") + "ed=\(encoded)"
    }

    /// Static because `authorize()` must run before `self` is fully initialized; it depends only
    /// on the immutable config/factory/mode, and the loops call it the same way.
    private static func request(
        config: SudokuNativeConfig,
        factory: SudokuConnectionFactory,
        mode: SudokuHTTPMaskMode,
        method: String,
        requestPath: String,
        authPath: String,
        contentType: String? = nil,
        body: Data
    ) async throws -> SudokuHTTPBodyReader {
        let stream = try await factory.open(host: config.serverHost, port: config.serverPort, useTLS: config.httpMask.tls, serverName: config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host)
        let modeName = mode == .poll ? "poll" : "stream"
        let auth = authToken(config: config, mode: modeName, method: method, path: authPath)
        let path = appendAuth(requestPath, token: auth)
        var requestHead = "\(method) \(path) HTTP/1.1\r\nHost: \(hostHeader(config: config))\r\nUser-Agent: \(ProxyUserAgent.chrome)\r\nAccept: */*\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: close\r\nX-Sudoku-Tunnel: \(modeName)\r\nAuthorization: Bearer \(auth)\r\n"
        if let contentType { requestHead += "Content-Type: \(contentType)\r\n" }
        requestHead += "Content-Length: \(body.count)\r\n\r\n"
        var data = Data(requestHead.utf8)
        data.append(body)
        try await stream.sendAll(data)
        return try await readHeaders(stream: stream)
    }

    private func sendSessionControl(path: String) async throws {
        guard !path.isEmpty else {
            throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "HTTPMask session control path is empty"))
        }
        var lastError: Error = AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask session control failed"))
        for attempt in 0..<3 {
            do {
                let opened = try await Self.request(
                    config: config,
                    factory: factory,
                    mode: mode,
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
                lastError = AnywhereError.proxy(.sudoku, .connectionClosed(detail:
                    "HTTPMask session control status \(opened.status)"
                ))
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    private static func readHeaders(stream: BlockingProxyStream) async throws -> SudokuHTTPBodyReader {
        let statusLine = try await sudokuReadHTTPLine(from: stream)
        let parts = statusLine.split(separator: " ")
        guard parts.count >= 2, let status = Int(parts[1]) else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad HTTP response")) }
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

    /// Runs the `/session` handshake and returns the derived request paths plus any early-handshake
    /// response payload. Static so `init` can assign the set-once `paths` `let` from its result.
    private static func authorize(
        config: SudokuNativeConfig,
        factory: SudokuConnectionFactory,
        mode: SudokuHTTPMaskMode,
        earlyRequestPayload: Data?
    ) async throws -> (paths: Paths, earlyResponse: Data) {
        let sessionPath = applyPathRoot(config: config, "/session")
        let opened = try await request(config: config, factory: factory, mode: mode, method: "GET", requestPath: appendEarlyData(sessionPath, payload: earlyRequestPayload), authPath: "/session", body: Data())
        guard opened.status == 200 else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask authorize status \(opened.status)")) }
        let body = try await opened.readAll(limit: 4096)
        guard let text = String(data: body, encoding: .utf8), let range = text.range(of: "token=") else {
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask authorize missing token"))
        }
        let tail = text[range.upperBound...]
        let token = String(tail.prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
        guard !token.isEmpty else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask empty token")) }
        var earlyResponse = Data()
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.hasPrefix("ed=") else { continue }
            let encoded = String(trimmed.dropFirst(3))
            if let decoded = Data(base64URLEncoded: encoded) {
                earlyResponse = decoded
            }
            break
        }
        let streamPath = applyPathRoot(config: config, "/stream")
        let uploadPath = applyPathRoot(config: config, "/api/v1/upload")
        let pushPath = "\(uploadPath)?token=\(token)"
        let paths = Paths(
            pullPath: "\(streamPath)?token=\(token)",
            pushPath: pushPath,
            finPath: "\(pushPath)&fin=1",
            closePath: "\(pushPath)&close=1"
        )
        return (paths, earlyResponse)
    }

    private func markReadEOF() {
        let conts = state.withLock { s -> [AsyncStream<Never>.Continuation] in
            guard !s.readEOF else { return [] }
            s.readEOF = true
            return drainWaitersLocked(&s)
        }
        for cont in conts { cont.finish() }
    }

    private func completeWrite(_ error: Error?) {
        let conts = state.withLock { s -> [AsyncStream<Never>.Continuation] in
            guard !s.writeDone else { return [] }
            s.writeError = error
            s.writeDone = true
            return drainWaitersLocked(&s)
        }
        for cont in conts { cont.finish() }
    }

    private func markClosed(fatal: Bool) {
        var stopPreparedMaintenance = false
        var taskToCancel: Task<Void, Never>?
        let conts = state.withLock { s -> [AsyncStream<Never>.Continuation] in
            s.fatal = s.fatal || fatal
            s.closed = true
            if !s.stoppedPreparedMaintenance {
                s.stoppedPreparedMaintenance = true
                stopPreparedMaintenance = true
            }
            taskToCancel = s.runTask
            s.runTask = nil
            return drainWaitersLocked(&s)
        }
        for cont in conts { cont.finish() }
        taskToCancel?.cancel()
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
                opened = try await Self.request(config: config, factory: factory, mode: mode, method: "GET", requestPath: paths.pullPath, authPath: "/stream", body: Data())
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
                guard opened.status == 200 else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask pull status \(opened.status)")) }
                retryCount = 0
                retryDelayMs = 10
                let conts = state.withLock { s -> [AsyncStream<Never>.Continuation] in
                    s.pullReady = true
                    return drainWaitersLocked(&s)
                }
                for cont in conts { cont.finish() }
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
                                        throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "invalid HTTPMask poll payload"))
                                    }
                                    await enqueueRX(decoded)
                                    pollLine.removeAll()
                                }
                            } else {
                                pollLine.append(byte)
                                if pollLine.count > sudokuHTTPMaskMaxPollLineBytes {
                                    throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "HTTPMask poll line too long"))
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
            var toResume: [AsyncStream<Never>.Continuation] = []
            let step: Step<Void> = state.withLock { s in
                if s.closed { return .done(()) }
                if s.rxQueue.count + data.count > queueLimit { return .wait(s.generation) }
                s.rxQueue.append(data)
                toResume = drainWaitersLocked(&s)
                return .done(())
            }
            for cont in toResume { cont.finish() }
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
            var toResume: [AsyncStream<Never>.Continuation] = []
            let (batch, shouldFinishWrite, isClosed): (Data?, Bool, Bool) = state.withLock { s in
                if s.closed { return (nil, false, true) }
                if s.txQueue.isEmpty { return (nil, s.writeClosed, false) }
                let n = min(maxBatchBytes, s.txQueue.count)
                let batch = s.txQueue.read(max: n)
                if s.txQueue.isEmpty { s.txQueue.removeAll(keepingCapacity: false) }
                toResume = drainWaitersLocked(&s)
                return (batch, false, false)
            }
            for cont in toResume { cont.finish() }
            if isClosed { return }

            if shouldFinishWrite {
                do {
                    try await sendSessionControl(path: paths.finPath)
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
                let opened = try await Self.request(config: config, factory: factory, mode: mode, method: "POST", requestPath: paths.pushPath, authPath: "/api/v1/upload", contentType: contentType, body: body)
                _ = try await opened.readAll(limit: 256)
                guard opened.status == 200 else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask push status \(opened.status)")) }
                let conts = state.withLock { s -> [AsyncStream<Never>.Continuation] in
                    s.pushReady = true
                    return drainWaitersLocked(&s)
                }
                for cont in conts { cont.finish() }
            } catch {
                markClosed(fatal: true)
                return
            }
        }
    }
}

nonisolated final class SudokuObfsTransport: Sendable {
    enum Wire {
        case stream(BlockingProxyStream)
        case httpMask(SudokuHTTPMaskTransport)
    }

    private let wire: Wire
    private let tables: SudokuTables
    private let threshold: UInt64
    private let pureDownlink: Bool
    /// Send-side RNG for uplink padding. Send is serialized by the record-layer send chain, so this
    /// short synchronous critical section is uncontended and never held across the wire `await`.
    private struct SendState {
        var rng: SudokuXorshift64Star
    }
    private let sendState: Mutex<SendState>
    /// Short synchronous critical section around the decoder state — receive is single-flight
    /// by contract, so this is never held across the wire `await`.
    private struct State {
        var pureDecoder = SudokuPureDecoder()
        var packedDecoder: SudokuPackedDecoder
    }
    private let state: Mutex<State>

    init(wire: Wire, tables: SudokuTables, config: SudokuNativeConfig) throws {
        self.wire = wire
        self.tables = tables
        self.pureDownlink = config.pureDownlink
        let seedBytes = [UInt8](try SudokuNativeCrypto.randomData(count: 8))
        let seed = Int64(bitPattern: seedBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) })
        var seeded = SudokuXorshift64Star(seed: seed)
        self.threshold = seeded.pickPaddingThreshold(min: config.paddingMin, max: config.paddingMax)
        self.sendState = Mutex(SendState(rng: seeded))
        self.state = Mutex(State(packedDecoder: tables.withDownlink { SudokuPackedDecoder(table: $0) }))
    }

    func send(_ data: Data) async throws {
        let encoded = sendState.withLock { sendState in
            tables.withUplink { $0.encode(data, rng: &sendState.rng, paddingThreshold: threshold) }
        }
        try await sendWire(encoded)
    }

    func receive(max: Int) async throws -> Data {
        guard max > 0 else { return Data() }
        let pending = try state.withLock { state in try drainDecoderPending(&state, max: max) }
        if !pending.isEmpty { return pending }
        while true {
            let wireData = try await receiveWire(max: sudokuObfsWireReadSize(decodedRemaining: max, pureDownlink: pureDownlink, maxRaw: sudokuObfsReadChunkSize))
            let out = try state.withLock { state -> Data in
                try tables.withDownlink { table -> Data in
                    if pureDownlink {
                        return try state.pureDecoder.decode(wireData, table: table, limit: max)
                    }
                    return try state.packedDecoder.decode(wireData, table: table, limit: max)
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
            } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
                if out.isEmpty { return nil }
                throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "truncated \(what)"))
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

    private func drainDecoderPending(_ state: inout State, max: Int) throws -> Data {
        try tables.withDownlink { table -> Data in
            if pureDownlink {
                return try state.pureDecoder.decode(Data(), table: table, limit: max)
            }
            return try state.packedDecoder.decode(Data(), table: table, limit: max)
        }
    }

}

nonisolated final class SudokuRecordStream: Sendable {
    private let transport: SudokuObfsTransport
    /// Set once at init; read from both the send and receive paths.
    private let method: SudokuAEADMethod
    /// Short synchronous critical section around the *send* state (epoch/seq/base + byte counters).
    /// Every mutation runs inside a `chainedSend {}` body, so the lock is uncontended and never
    /// held across the wire `await`.
    private struct SendState {
        var baseSend: Data
        var sendEpoch: UInt32
        var sendSeq: UInt64
        var sendBytes: Int64 = 0
        var sendEpochUpdates: UInt32 = 0
    }
    private let sendState: Mutex<SendState>
    /// Short synchronous critical section around the *receive* state (`readBuffer`, `recvSeq`,
    /// decryptor) — receive is single-flight, so this is never held across the wire `await`.
    private struct State {
        var baseRecv: Data
        var recvEpoch: UInt32 = 0
        var recvSeq: UInt64 = 0
        var recvInitialized = false
        var readBuffer = SudokuDataQueue()
    }
    private let state: Mutex<State>
    /// Tail of the send chain (mux frames from N streams + the keepalive timer converge here). Each
    /// chained body — the epoch/seq assignment plus the wire write — runs only once the previous
    /// finished, so record order matches wire order without a lock held across the `await`.
    private let sendChain = SerialSender()

    /// Links `body` after all prior chained sends and awaits it (ordering + backpressure + errors).
    private func chainedSend(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await sendChain.run(body)
    }

    init(transport: SudokuObfsTransport, method: SudokuAEADMethod, baseSend: Data, baseRecv: Data) throws {
        self.transport = transport
        self.method = method
        self.sendState = Mutex(SendState(
            baseSend: baseSend,
            sendEpoch: try SudokuNativeCrypto.randomNonZeroUInt32(),
            sendSeq: try SudokuNativeCrypto.randomNonZeroUInt64()
        ))
        self.state = Mutex(State(baseRecv: baseRecv))
    }

    func rekey(send: Data, recv: Data) async throws {
        try await chainedSend { [self] in
            try sendState.withLock { s in
                s.baseSend = send
                s.sendEpoch = try SudokuNativeCrypto.randomNonZeroUInt32()
                s.sendSeq = try SudokuNativeCrypto.randomNonZeroUInt64()
                s.sendBytes = 0
                s.sendEpochUpdates = 0
            }
            state.withLock { state in
                state.baseRecv = recv
                state.recvEpoch = 0
                state.recvSeq = 0
                state.recvInitialized = false
                state.readBuffer.removeAll()
            }
        }
    }

    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        try await chainedSend { [self] in
            if method == .none {
                try await transport.send(data)
                return
            }
            var offset = 0
            while offset < data.count {
                let maxPlain = 65535 - 12 - 16
                let count = min(maxPlain, data.count - offset)
                let chunk = data.rangeData(offset: offset, count: count)
                let frame = try sendState.withLock { s -> Data in
                    var header = Data()
                    var epochBE = s.sendEpoch.bigEndian
                    var seqBE = s.sendSeq.bigEndian
                    header.append(Data(bytes: &epochBE, count: 4))
                    header.append(Data(bytes: &seqBE, count: 8))
                    s.sendSeq &+= 1
                    let key = SudokuNativeCrypto.recordEpochKey(base: s.baseSend, method: method, epoch: s.sendEpoch)
                    let cipher = try SudokuNativeCrypto.seal(method: method, key: key, nonce: header, plaintext: chunk, aad: header)
                    var bodyLen = UInt16(header.count + cipher.count).bigEndian
                    var frame = Data(bytes: &bodyLen, count: 2)
                    frame.append(header)
                    frame.append(cipher)
                    return frame
                }
                try await transport.send(frame)
                offset += count
                try maybeBumpSendEpoch(added: count)
            }
        }
    }

    func receive(max: Int) async throws -> Data {
        guard max > 0 else { return Data() }
        if let buffered = state.withLock({ $0.readBuffer.isEmpty ? nil : $0.readBuffer.read(max: max) }) {
            return buffered
        }
        if method == .none { return try await transport.receive(max: max) }
        while true {
            guard let lenData = try await transport.readExactAllowingEOF(2, what: "record length") else {
                throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))
            }
            let bodyLen = try Self.parseRecordLength(lenData)
            let body: Data
            do {
                body = try await transport.readExact(bodyLen)
            } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
                throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "truncated record body"))
            }
            let out: Data? = try state.withLock { state in
                let plain = try decryptRecord(&state, body: body, bodyLen: bodyLen)
                if plain.isEmpty { return nil }
                if plain.count > max {
                    state.readBuffer.append(plain, from: max)
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
        guard bodyLen >= 12 && bodyLen <= 65535 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad record length")) }
        return bodyLen
    }

    private func decryptRecord(_ state: inout State, body: Data, bodyLen: Int) throws -> Data {
        let epoch = body.uint32BE(at: 0)
        let seq = body.uint64BE(at: 4)
        if state.recvInitialized {
            if epoch < state.recvEpoch { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "replayed record epoch")) }
            if epoch == state.recvEpoch && seq != state.recvSeq { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "out of order record")) }
            if epoch > state.recvEpoch && epoch - state.recvEpoch > 8 { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "record epoch jump")) }
        }
        let header = body.prefixData(12)
        let ciphertext = body.rangeData(offset: 12, count: bodyLen - 12)
        let key = SudokuNativeCrypto.recordEpochKey(base: state.baseRecv, method: method, epoch: epoch)
        let plain = try SudokuNativeCrypto.open(method: method, key: key, nonce: header, ciphertext: ciphertext, aad: header)
        state.recvEpoch = epoch
        state.recvSeq = seq + 1
        state.recvInitialized = true
        return plain
    }

    func close() { transport.close() }

    func waitHTTPMaskReady(timeout: TimeInterval) async throws {
        try await transport.waitHTTPMaskReady(timeout: timeout)
    }

    private func maybeBumpSendEpoch(added: Int) throws {
        guard method != .none else { return }
        try sendState.withLock { s in
            s.sendBytes += Int64(added)
            let threshold = Int64(32 << 20) * Int64(s.sendEpochUpdates + 1)
            guard s.sendBytes >= threshold else { return }
            s.sendEpoch &+= 1
            s.sendEpochUpdates &+= 1
            s.sendSeq = try SudokuNativeCrypto.randomNonZeroUInt64()
        }
    }
}

nonisolated private struct SudokuKIPClientState {
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
    func openMux(ownsFactory: Bool = false,
                 onClose: (@Sendable (SudokuMuxClient) -> Void)? = nil) async throws -> SudokuMuxClient {
        let record = try await connectBase()
        do {
            try await writeKIP(record: record, type: 0x11, payload: Data())
            try await record.waitHTTPMaskReady(timeout: 30)
            return SudokuMuxClient(record: record, factory: ownsFactory ? factory : nil, onClose: onClose)
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
        guard message.type == 0x02 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad early KIP server hello")) }
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
                if out.isEmpty { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad early record length")) }
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
        guard !out.isEmpty else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "short early record")) }
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
        guard msg.type == 0x02, msg.payload.count == 52 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad KIP server hello")) }
        guard msg.payload.prefixData(16) == state.nonce else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "KIP nonce mismatch")) }
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
        } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
            throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "truncated KIP header"))
        }
        guard header[0] == 0x6b, header[1] == 0x69, header[2] == 0x70 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad KIP magic")) }
        let length = Int(UInt16(header[4]) << 8 | UInt16(header[5]))
        do {
            return (header[3], try await record.readExact(length))
        } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
            throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "truncated KIP payload"))
        }
    }

    private func parseKIP(_ data: Data) throws -> (type: UInt8, payload: Data) {
        guard data.count >= 6 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "short KIP frame")) }
        guard data[0] == 0x6b, data[1] == 0x69, data[2] == 0x70 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad KIP magic")) }
        let length = Int(UInt16(data[4]) << 8 | UInt16(data[5]))
        guard data.count >= 6 + length else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "truncated KIP frame \(data.count)/\(6 + length)")) }
        return (data[3], data.rangeData(offset: 6, count: length))
    }
}

nonisolated private enum SudokuAddress {
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
            guard bytes.count <= 255 else { throw AnywhereError.proxy(.sudoku, .invalidConfiguration(detail: "domain too long")) }
            out.append(0x03)
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(UInt8(port >> 8))
        out.append(UInt8(port & 0xff))
        return out
    }
}

nonisolated final class SudokuMuxClient: Multiplexer, Sendable {
    private static let keepaliveInterval: TimeInterval = 15
    private let record: SudokuRecordStream
    private let factory: SudokuConnectionFactory?
    
    private let onClose: (@Sendable (SudokuMuxClient) -> Void)?

    private struct State {
        var streams: [UInt32: SudokuMuxStream] = [:]
        var nextStreamID: UInt32 = 0
        var lastWrite: ContinuousClock.Instant = ContinuousClock.now
        var closed = false
        var runTask: Task<Void, Never>?
    }
    private let state = Mutex(State())

    var isClosed: Bool {
        state.withLock { $0.closed }
    }
    
    var activeStreamCount: Int {
        state.withLock { $0.streams.count }
    }

    init(record: SudokuRecordStream, factory: SudokuConnectionFactory? = nil,
         onClose: (@Sendable (SudokuMuxClient) -> Void)? = nil) {
        self.record = record
        self.factory = factory
        self.onClose = onClose
        let task = Task {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await self.readerLoop() }
                group.addTask { await self.keepaliveLoop() }
            }
        }
        state.withLock { $0.runTask = task }
    }

    private func keepaliveLoop() async {
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(Self.keepaliveInterval))
            if Task.isCancelled { return }
            sendKeepaliveIfIdle()
        }
    }

    func dialTCP(host: String, port: UInt16) async throws -> SudokuMuxStream {
        let stream = SudokuMuxStream(client: self, id: allocateStreamID())
        let closed = state.withLock { state -> Bool in
            if state.closed { return true }
            state.streams[stream.id] = stream
            return false
        }
        if closed { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        do {
            try await sendFrame(type: 0x01, streamID: stream.id, payload: SudokuAddress.encode(host: host, port: port))
        } catch {
            state.withLock { _ = $0.streams.removeValue(forKey: stream.id) }
            stream.markClosed(discardQueuedData: true, error: error)
            throw error
        }
        return stream
    }

    func sendFrame(type: UInt8, streamID: UInt32, payload: Data) async throws {
        guard payload.count <= 256 * 1024 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "mux frame too large")) }
        let isClosed = state.withLock { $0.closed }
        guard !isClosed else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        var frame = Data([type])
        var sid = streamID.bigEndian
        var length = UInt32(payload.count).bigEndian
        frame.append(Data(bytes: &sid, count: 4))
        frame.append(Data(bytes: &length, count: 4))
        frame.append(payload)
        do {
            try await record.send(frame)
            state.withLock { $0.lastWrite = ContinuousClock.now }
        } catch {
            close(error: error)
            throw error
        }
    }

    func removeStream(id: UInt32) {
        state.withLock { _ = $0.streams.removeValue(forKey: id) }
    }
    
    func close(error: Error? = nil) {
        typealias Drained = (streams: [SudokuMuxStream], run: Task<Void, Never>?)
        let drained: Drained? = state.withLock { state in
            if state.closed { return nil }
            state.closed = true
            let streamsToClose = Array(state.streams.values)
            state.streams.removeAll()
            let run = state.runTask
            state.runTask = nil
            return (streamsToClose, run)
        }
        guard let drained else { return }
        drained.run?.cancel()
        for stream in drained.streams {
            stream.markClosed(discardQueuedData: true, error: error)
        }
        record.close()
        factory?.closeAll()
        onClose?(self)
    }

    private func allocateStreamID() -> UInt32 {
        state.withLock { state in
            repeat { state.nextStreamID &+= 1 } while state.nextStreamID == 0
            return state.nextStreamID
        }
    }

    private func sendKeepaliveIfIdle() {
        let shouldSend = state.withLock { state in
            !state.closed && state.lastWrite.duration(to: ContinuousClock.now) >= .seconds(Self.keepaliveInterval)
        }
        if shouldSend {
            // The keepalive loop is off the send path; hop to a Task for the async send.
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
                guard length <= 256 * 1024 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "mux frame too large")) }
                let payload = try await record.readExact(length)
                let stream = state.withLock { $0.streams[streamID] }
                switch type {
                case 0x02:
                    guard let stream, !payload.isEmpty else { continue }
                    if case .overflow = stream.enqueue(payload) {
                        let error = AnywhereError.proxy(.sudoku, .connectionClosed(detail: "mux receive queue full"))
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
                        error: AnywhereError.proxy(.sudoku, .connectionClosed(detail: message))
                    )
                    removeStream(id: streamID)
                default: throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad mux frame"))
                }
            } catch AnywhereError.proxy(.sudoku, .connectionClosed(nil)) {
                // Clean record EOF (nil detail); a detailed .connectionClosed is a real failure
                // (e.g. HTTPMask non-200) and falls through to the error branch below.
                close()
                return
            } catch {
                let wasClosed = state.withLock { $0.closed }
                if !wasClosed {
                    sudokuLogger.error("[Sudoku-Mux] reader failed: \(error.localizedDescription)")
                }
                close(error: error)
                return
            }
        }
    }
}

nonisolated final class SudokuMuxStream: Sendable {
    enum EnqueueResult {
        case accepted
        case ignored
        case overflow
    }

    let id: UInt32
    /// Weak back-reference to the owning mux client, boxed so the stream stays `Sendable`; set once at init.
    private struct WeakClient { weak var value: SudokuMuxClient? }
    private let clientBox: Mutex<WeakClient>
    /// Tail of this stream's send chain: each frame (data chunk or the FIN) links after the previous
    /// and runs only once it finishes, so no data frame is ever emitted after the close frame — no
    /// lock held across the `await`.
    private let sendChain = SerialSender()

    /// Links `body` after all prior chained sends and awaits it (ordering + backpressure + errors).
    private func chainedSend(_ body: @escaping @Sendable () async throws -> Void) async throws {
        try await sendChain.run(body)
    }

    private struct State {
        var queue = SudokuDataQueue()
        var fullyClosed = false
        var localReadClosed = false
        var localWriteClosed = false
        var remoteWriteClosed = false
        var terminalError: Error?
        /// Single-flight receive gate: ``receive(max:)`` enrolls a one-shot waiter here when the
        /// queue is empty; any data/close path finishes it (under the lock) so `receive` re-checks.
        /// Single consumer by contract — a second concurrent `receive` is rejected.
        var receiveWaiter: AsyncStream<Void>.Continuation?
    }
    private let state = Mutex(State())

    /// Wakes a parked ``receive(max:)`` so it re-evaluates the queue/close state. Lock held.
    private func wakeReceiveWaiterLocked(_ state: inout State) {
        state.receiveWaiter?.finish()
        state.receiveWaiter = nil
    }

    init(client: SudokuMuxClient, id: UInt32) { self.clientBox = Mutex(WeakClient(value: client)); self.id = id }

    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        try await chainedSend { [self] in
            guard let client = clientBox.withLock({ $0.value }) else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
            let (cannotWrite, error) = state.withLock { state in
                (state.fullyClosed || state.localWriteClosed, state.terminalError)
            }
            if let error { throw error }
            guard !cannotWrite else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }

            var offset = 0
            while offset < data.count {
                let count = min(128 * 1024, data.count - offset)
                try await client.sendFrame(type: 0x02, streamID: id, payload: data.rangeData(offset: offset, count: count))
                offset += count
            }
        }
    }

    /// Receives one chunk; `nil` == EOF. Single-flight by contract. Parks on an `AsyncStream`
    /// gate (re-checking the queue/close state on each wake) instead of a stored continuation.
    func receive(max: Int) async throws -> Data? {
        enum Outcome { case data(Data), eof, error(Error), concurrent, wait(AsyncStream<Void>) }
        while true {
            let outcome: Outcome = state.withLock { state in
                if !state.queue.isEmpty {
                    return .data(state.queue.read(max: max))
                }
                if state.fullyClosed {
                    if let error = state.terminalError { return .error(error) }
                    return .eof
                }
                if state.localReadClosed || state.remoteWriteClosed {
                    return .eof
                }
                if state.receiveWaiter != nil {
                    return .concurrent
                }
                let (stream, continuation) = AsyncStream<Void>.makeStream()
                state.receiveWaiter = continuation
                return .wait(stream)
            }
            switch outcome {
            case .data(let out): return out
            case .eof: return nil
            case .error(let error): throw error
            case .concurrent: throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "concurrent mux receive"))
            case .wait(let stream):
                // Parks until a data/close path finishes the gate, then re-evaluates.
                for await _ in stream { break }
                // A finished gate loops to re-check; a cancelled task must not spin.
                try Task.checkCancellation()
            }
        }
    }

    func enqueue(_ data: Data) -> EnqueueResult {
        state.withLock { state in
            if state.fullyClosed || state.localReadClosed || state.remoteWriteClosed {
                return .ignored
            }
            guard state.queue.count + data.count <= sudokuMuxMaxQueueBytes else {
                return .overflow
            }
            // A parked receiver only enrolls with an empty queue, so this append stays within the
            // cap; `receive` reads back up to its own `max` (partial reads live in `SudokuDataQueue`).
            state.queue.append(data)
            wakeReceiveWaiterLocked(&state)
            return .accepted
        }
    }

    func closeRead() {
        var shouldRemove = false
        let skip = state.withLock { state -> Bool in
            if state.fullyClosed || state.localReadClosed {
                return true
            }
            state.localReadClosed = true
            state.queue.removeAll(keepingCapacity: false)
            shouldRemove = state.localWriteClosed
            wakeReceiveWaiterLocked(&state)
            return false
        }
        if skip { return }
        if shouldRemove {
            clientBox.withLock { $0.value }?.removeStream(id: id)
        }
    }

    func close() {
        // Terminal transition + continuation resume run under the state lock only (never the
        // send mutex), so close always fires and unblocks a parked sender. The best-effort FIN
        // is dispatched to a Task, ordered after in-flight data via the send mutex.
        let shouldSendClose: Bool? = state.withLock { state -> Bool? in
            if state.fullyClosed {
                return nil
            }
            let shouldSendClose = !state.localWriteClosed
            state.fullyClosed = true
            state.localReadClosed = true
            state.localWriteClosed = true
            state.terminalError = nil
            state.queue.removeAll(keepingCapacity: false)
            wakeReceiveWaiterLocked(&state)
            return shouldSendClose
        }
        guard let shouldSendClose else { return }

        if let client = clientBox.withLock({ $0.value }) {
            if shouldSendClose {
                Task { [weak self] in await self?.sendCloseFrame(to: client) }
            }
            client.removeStream(id: id)
        }
    }

    private func sendCloseFrame(to client: SudokuMuxClient) async {
        try? await chainedSend { [self] in
            try? await client.sendFrame(type: 0x03, streamID: id, payload: Data())
        }
    }

    @discardableResult
    func markRemoteWriteClosed() -> Bool {
        state.withLock { state -> Bool in
            if state.fullyClosed {
                return false
            }
            state.remoteWriteClosed = true
            let shouldRemove = state.localWriteClosed && (state.remoteWriteClosed || state.localReadClosed)
            // A parked receiver has an empty queue, so waking it surfaces EOF; if the queue holds
            // data, the receiver drains it first (it re-checks `remoteWriteClosed` only when empty).
            if state.queue.isEmpty {
                wakeReceiveWaiterLocked(&state)
            }
            return shouldRemove
        }
    }

    func markClosed(discardQueuedData: Bool = false, error: Error? = nil) {
        state.withLock { state in
            if state.fullyClosed {
                return
            }
            state.fullyClosed = true
            state.terminalError = error
            if discardQueuedData {
                state.queue.removeAll(keepingCapacity: false)
            }
            wakeReceiveWaiterLocked(&state)
        }
    }
}

nonisolated final class SudokuTCPProxyConnection:
    ProxyConnection,
    Sendable
{
    private let closed = Atomic<Bool>(false)
    private let stream: SudokuRecordStream

    init(stream: SudokuRecordStream) { self.stream = stream }
    var isConnected: Bool { !closed.load(ordering: .acquiring) }

    func sendRaw(_ data: Data) async throws {
        if closed.load(ordering: .acquiring) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        try await stream.send(data)
    }

    func receiveRaw() async throws -> Data? {
        if closed.load(ordering: .acquiring) { return nil }
        do {
            return try await stream.receive(max: sudokuTCPReceiveChunkSize)
        } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
            return nil
        }
    }

    func cancel() { closed.store(true, ordering: .releasing); stream.close() }
}

nonisolated final class SudokuMuxTCPProxyConnection:
    ProxyConnection,
    Sendable
{
    private struct State {
        var onClose: (@Sendable () -> Void)?
        var closed = false
        var readEOF = false
    }
    private let state: Mutex<State>
    private let client: SudokuMuxClient
    private let stream: SudokuMuxStream
    private let closesClientOnClose: Bool

    init(
        client: SudokuMuxClient,
        stream: SudokuMuxStream,
        closesClientOnClose: Bool = true,
        onClose: (@Sendable () -> Void)? = nil
    ) {
        self.client = client
        self.stream = stream
        self.closesClientOnClose = closesClientOnClose
        self.state = Mutex(State(onClose: onClose))
    }

    var isConnected: Bool { !state.withLock { $0.closed } && !client.isClosed }

    func sendRaw(_ data: Data) async throws {
        if state.withLock({ $0.closed }) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        do {
            try await stream.send(data)
        } catch {
            closeResources(closeStream: true)
            throw error
        }
    }

    func receiveRaw() async throws -> Data? {
        if state.withLock({ $0.closed || $0.readEOF }) { return nil }
        do {
            if let data = try await stream.receive(max: sudokuTCPReceiveChunkSize), !data.isEmpty {
                return data
            }
            state.withLock { $0.readEOF = true }
            return nil
        } catch {
            closeResources(closeStream: false)
            throw error
        }
    }

    func cancel() {
        closeResources(closeStream: true)
    }

    private func closeResources(closeStream: Bool) {
        let callback: (() -> Void)? = state.withLock { state in
            guard !state.closed else { return nil }
            state.closed = true
            let callback = state.onClose
            state.onClose = nil
            return callback
        }
        if closeStream { stream.close() }
        if closesClientOnClose { client.close() }
        callback?()
    }
}

nonisolated final class SudokuUDPProxyConnection: ProxyConnection, Sendable {
    private let closed = Atomic<Bool>(false)
    private let stream: SudokuRecordStream
    private let destinationHost: String
    private let destinationPort: UInt16

    init(stream: SudokuRecordStream, destinationHost: String, destinationPort: UInt16) {
        self.stream = stream
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
    }

    var isConnected: Bool { !closed.load(ordering: .acquiring) }

    func sendRaw(_ data: Data) async throws {
        if closed.load(ordering: .acquiring) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        let address = try SudokuAddress.encode(host: destinationHost, port: destinationPort)
        guard address.count <= UInt16.max else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "UoT address too large")) }
        guard data.count <= UInt16.max else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "UoT payload too large")) }
        var frame = Data([UInt8(address.count >> 8), UInt8(address.count & 0xff), UInt8(data.count >> 8), UInt8(data.count & 0xff)])
        frame.append(address)
        frame.append(data)
        try await stream.send(frame)
    }

    func receiveRaw() async throws -> Data? {
        if closed.load(ordering: .acquiring) { return nil }
        do {
            let header = try await stream.readExact(4)
            let addrLen = Int(UInt16(header[0]) << 8 | UInt16(header[1]))
            let payloadLen = Int(UInt16(header[2]) << 8 | UInt16(header[3]))
            guard addrLen > 0 && addrLen <= 64 * 1024 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad UoT address length")) }
            guard payloadLen <= 64 * 1024 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad UoT payload length")) }
            _ = try await stream.readExact(addrLen)
            return try await stream.readExact(payloadLen)
        } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
            return nil
        }
    }

    func cancel() { closed.store(true, ordering: .releasing); stream.close() }
}
