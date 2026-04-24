//
//  SudokuProxyConnection.swift
//  Anywhere
//
//  Native Swift Sudoku outbound. The Sudoku table encoder/decoder remains in
//  SudokuCore.c for now; transport, HTTPMask, KIP, record AEAD, UoT, and mux
//  are implemented here with platform crypto and the existing Anywhere TLS stack.
//

import Foundation
import Darwin
import CryptoKit
import Security

private let sudokuLogger = AnywhereLogger(category: "Sudoku")

private enum SudokuNativeError: Error, LocalizedError {
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
        var recovered = [CChar](repeating: 0, count: 65)
        if sudoku.key.withCString({ sudoku_recover_public_key_hex($0, &recovered) }) == 0 {
            self.key = String(cString: recovered)
        } else {
            self.key = sudoku.key
        }
    }

    var nativeMuxEnabled: Bool {
        !httpMask.disable && [.stream, .poll, .auto, .ws].contains(httpMask.mode) && httpMask.multiplex == .on
    }
}

final class SudokuTables {
    private var pair = sudoku_table_pair_t()
    private let lock = UnfairLock()
    let sendsTableHint: Bool

    init(config: SudokuNativeConfig) throws {
        sendsTableHint = config.sendsTableHint
        let result = config.key.withCString { keyPtr in
            config.asciiMode.withCString { modePtr in
                config.selectedCustomTable.withCString { customPtr in
                    sudoku_table_pair_init(&pair, keyPtr, modePtr, customPtr, customPtr)
                }
            }
        }
        guard result == 0 else { throw SudokuNativeError.invalidConfiguration("failed to build Sudoku table") }
    }

    deinit { sudoku_table_pair_free(&pair) }

    func withUplink<T>(_ body: (UnsafePointer<sudoku_table_t>) throws -> T) rethrows -> T {
        try lock.withLock { try withUnsafePointer(to: &pair.uplink, body) }
    }

    func withDownlink<T>(_ body: (UnsafePointer<sudoku_table_t>) throws -> T) rethrows -> T {
        try lock.withLock { try withUnsafePointer(to: &pair.downlink, body) }
    }

    var hint: UInt32 { lock.withLock { pair.uplink.hint } }
}

final class BlockingProxyStream {
    private let connection: ProxyConnection
    private let readLock = UnfairLock()
    private let writeLock = UnfairLock()
    private var pending = Data()
    private var closed = false

    init(connection: ProxyConnection) { self.connection = connection }

    func sendAll(_ data: Data) throws {
        if data.isEmpty { return }
        try writeLock.withLock {
            if closed { throw SudokuNativeError.closed }
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
                let n = min(max, pending.count)
                let out = pending.prefix(n)
                pending.removeFirst(n)
                return Data(out)
            }
            if closed { throw SudokuNativeError.closed }
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
                closed = true
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
        closed = true
        connection.cancel()
    }
}

final class SudokuConnectionFactory {
    private let configuration: ProxyConfiguration
    private let directDialHost: String
    private let stateLock = UnfairLock()
    private var initialTunnel: ProxyConnection?
    private var retainedClients: [ProxyClient] = []
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
        stateLock.withLock { connections.append(connection) }
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
            base.cancel()
            throw SudokuNativeError.connectionFailed("timeout upgrading WebSocket transport")
        }
        if let upgradeError {
            base.cancel()
            throw upgradeError
        }
        let connection = WebSocketProxyConnection(wsConnection: ws)
        stateLock.withLock { connections.append(connection) }
        return BlockingProxyStream(connection: connection)
    }

    func closeAll() {
        let toClose: [ProxyConnection]
        let clients: [ProxyClient]
        stateLock.lock()
        if closed {
            stateLock.unlock()
            return
        }
        closed = true
        toClose = connections + (initialTunnel.map { [$0] } ?? [])
        clients = retainedClients
        connections.removeAll()
        retainedClients.removeAll()
        initialTunnel = nil
        stateLock.unlock()
        for connection in toClose { connection.cancel() }
        for client in clients { client.cancel() }
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
            let tls = TLSClient(configuration: TLSConfiguration(serverName: serverName ?? host))
            tls.connect(host: directDialHost, port: configuration.serverPort) { result in
                switch result {
                case .success(let conn): completion(.success(TLSProxyConnection(tlsConnection: conn)))
                case .failure(let error): completion(.failure(error))
                }
            }
            return
        }

        let socket = RawTCPSocket()
        socket.connect(host: directDialHost, port: configuration.serverPort) { error in
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
        stateLock.withLock { retainedClients.append(client) }
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
    private var rxQueue = Data()
    private var txQueue = Data()
    private var closed = false
    private var fatal = false
    private var token = ""
    private var pullPath = ""
    private var pushPath = ""
    private var closePath = ""

    init(config: SudokuNativeConfig, factory: SudokuConnectionFactory, mode: SudokuHTTPMaskMode) throws {
        self.config = config
        self.factory = factory
        self.mode = mode
        try authorize()
        DispatchQueue.global(qos: .userInitiated).async { self.pullLoop() }
        DispatchQueue.global(qos: .userInitiated).async { self.pushLoop() }
    }

    func send(_ data: Data) throws {
        condition.lock()
        defer { condition.unlock() }
        if closed { throw SudokuNativeError.closed }
        txQueue.append(data)
        condition.signal()
    }

    func receive(max: Int) throws -> Data {
        condition.lock()
        defer { condition.unlock() }
        while rxQueue.isEmpty && !closed { condition.wait() }
        if rxQueue.isEmpty && closed { throw fatal ? SudokuNativeError.connectionFailed("HTTPMask closed") : SudokuNativeError.closed }
        let n = min(max, rxQueue.count)
        let out = Data(rxQueue.prefix(n))
        rxQueue.removeFirst(n)
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
        var keyMaterial = Data("sudoku-httpmask-auth-v1:".utf8)
        keyMaterial.append(Data(config.key.utf8))
        let key = SudokuNativeCrypto.sha256(keyMaterial)
        var ts = UInt64(Date().timeIntervalSince1970).bigEndian
        let tsData = Data(bytes: &ts, count: 8)
        let zero = Data([0])
        let mac = SudokuNativeCrypto.hmacSHA256(key: key, parts: [Data(mode.utf8), zero, Data(method.utf8), zero, Data(path.utf8), zero, tsData])
        var payload = tsData
        payload.append(mac.prefix(16))
        return payload.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func appendAuth(_ path: String, token: String) -> String {
        path + (path.contains("?") ? "&" : "?") + "auth=\(token)"
    }

    private func request(method: String, requestPath: String, authPath: String, contentType: String? = nil, body: Data) throws -> (stream: BlockingProxyStream, body: SudokuHTTPBodyReader) {
        let stream = try factory.open(host: config.serverHost, port: config.serverPort, useTLS: config.httpMask.tls, serverName: config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host)
        let modeName = mode == .poll ? "poll" : "stream"
        let auth = authToken(mode: modeName, method: method, path: authPath)
        let path = appendAuth(requestPath, token: auth)
        var req = "\(method) \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: close\r\nX-Sudoku-Tunnel: \(modeName)\r\nAuthorization: Bearer \(auth)\r\n"
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
        let opened = try request(method: "GET", requestPath: sessionPath, authPath: "/session", body: Data())
        guard opened.body.status == 200 else { throw SudokuNativeError.connectionFailed("HTTPMask authorize status \(opened.body.status)") }
        let body = try opened.body.readAll(limit: 4096)
        guard let text = String(data: body, encoding: .utf8), let range = text.range(of: "token=") else {
            throw SudokuNativeError.connectionFailed("HTTPMask authorize missing token")
        }
        let tail = text[range.upperBound...]
        token = String(tail.prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
        guard !token.isEmpty else { throw SudokuNativeError.connectionFailed("HTTPMask empty token") }
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
            batch = Data(txQueue.prefix(n))
            txQueue.removeFirst(n)
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
    private var rng = sudoku_splitmix64_t()
    private var threshold: UInt64 = 0
    private var pureDecoder = sudoku_decoder_t()
    private var packedDecoder = sudoku_packed_decoder_t()
    private let pureDownlink: Bool
    private var plainBuffer = Data()
    private let readLock = UnfairLock()
    private let writeLock = UnfairLock()

    init(wire: Wire, tables: SudokuTables, config: SudokuNativeConfig) throws {
        self.wire = wire
        self.tables = tables
        self.pureDownlink = config.pureDownlink
        let seedBytes = [UInt8](try SudokuNativeCrypto.randomData(count: 8))
        let seed = Int64(bitPattern: seedBytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) })
        sudoku_splitmix64_seed(&rng, seed)
        threshold = sudoku_pick_padding_threshold(&rng, config.paddingMin, config.paddingMax)
        sudoku_decoder_init(&pureDecoder)
        tables.withDownlink { sudoku_packed_decoder_init(&packedDecoder, $0) }
    }

    func send(_ data: Data) throws {
        try writeLock.withLock {
            var offset = 0
            while offset < data.count {
                let count = min(8192, data.count - offset)
                let chunk = data.subdata(in: offset..<(offset + count))
                var encoded = Data(count: count * 6 + 8)
                let encodedCapacity = encoded.count
                let written = tables.withUplink { tablePtr in
                    encoded.withUnsafeMutableBytes { dst in
                        chunk.withUnsafeBytes { src -> Int in
                            guard let dstBase = dst.baseAddress?.assumingMemoryBound(to: UInt8.self), let srcBase = src.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
                            return sudoku_encode_pure(dstBase, encodedCapacity, tablePtr, &rng, threshold, srcBase, count)
                        }
                    }
                }
                encoded.removeSubrange(written..<encoded.count)
                try sendWire(encoded)
                offset += count
            }
        }
    }

    func receive(max: Int) throws -> Data {
        try readLock.withLock {
            if !plainBuffer.isEmpty {
                let n = min(max, plainBuffer.count)
                let out = Data(plainBuffer.prefix(n))
                plainBuffer.removeFirst(n)
                return out
            }
            while true {
                let wireData = try receiveWire(max: 8192)
                var out = Data(count: 65536)
                let outCapacity = out.count
                var err: Int32 = 0
                let decoded = tables.withDownlink { tablePtr in
                    out.withUnsafeMutableBytes { dst in
                        wireData.withUnsafeBytes { src -> Int in
                            guard let dstBase = dst.baseAddress?.assumingMemoryBound(to: UInt8.self), let srcBase = src.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return 0 }
                            if pureDownlink {
                                return sudoku_decode_pure(&pureDecoder, tablePtr, srcBase, wireData.count, dstBase, outCapacity, &err)
                            }
                            return sudoku_decode_packed(&packedDecoder, tablePtr, srcBase, wireData.count, dstBase, outCapacity, &err)
                        }
                    }
                }
                if err != 0 { throw SudokuNativeError.protocolError("Sudoku decode failed") }
                if decoded == 0 { continue }
                out.removeSubrange(decoded..<out.count)
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
    private var readBuffer = Data()
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
                let n = min(max, readBuffer.count)
                let out = Data(readBuffer.prefix(n))
                readBuffer.removeFirst(n)
                return out
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
            if config.httpMask.mode == .poll {
                wire = .httpMask(try SudokuHTTPMaskTransport(config: config, factory: factory, mode: .poll))
            } else if config.httpMask.mode == .stream {
                wire = .httpMask(try SudokuHTTPMaskTransport(config: config, factory: factory, mode: .stream))
            } else {
                do { wire = .httpMask(try SudokuHTTPMaskTransport(config: config, factory: factory, mode: .stream)) }
                catch { wire = .httpMask(try SudokuHTTPMaskTransport(config: config, factory: factory, mode: .poll)) }
            }
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
        var keyMaterial = Data("sudoku-httpmask-auth-v1:".utf8)
        keyMaterial.append(Data(config.key.utf8))
        let key = SudokuNativeCrypto.sha256(keyMaterial)
        var ts = UInt64(Date().timeIntervalSince1970).bigEndian
        let tsData = Data(bytes: &ts, count: 8)
        let zero = Data([0])
        let mac = SudokuNativeCrypto.hmacSHA256(key: key, parts: [Data(mode.utf8), zero, Data(method.utf8), zero, Data(path.utf8), zero, tsData])
        var payload = tsData
        payload.append(mac.prefix(16))
        return payload.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func performKIP(record: SudokuRecordStream) throws {
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
        try writeKIP(record: record, type: 0x01, payload: payload)
        let msg = try readKIP(record: record)
        guard msg.type == 0x02, msg.payload.count == 52 else { throw SudokuNativeError.protocolError("bad KIP server hello") }
        guard msg.payload.prefix(16) == nonce else { throw SudokuNativeError.protocolError("KIP nonce mismatch") }
        let serverPub = msg.payload.subdata(in: 16..<48)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPub)).withUnsafeBytes { Data($0) }
        let session = SudokuNativeCrypto.sessionBases(psk: config.key, shared: shared, nonce: nonce)
        try record.rekey(send: session.c2s, recv: session.s2c)
    }

    private func writeKIP(record: SudokuRecordStream, type: UInt8, payload: Data) throws {
        var frame = Data([0x6b, 0x69, 0x70, type, UInt8(payload.count >> 8), UInt8(payload.count & 0xff)])
        frame.append(payload)
        try record.send(frame)
    }

    private func readKIP(record: SudokuRecordStream) throws -> (type: UInt8, payload: Data) {
        let header = try record.readExact(6)
        guard header[0] == 0x6b, header[1] == 0x69, header[2] == 0x70 else { throw SudokuNativeError.protocolError("bad KIP magic") }
        let length = Int(UInt16(header[4]) << 8 | UInt16(header[5]))
        return (header[3], try record.readExact(length))
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
                case 0x02: stream?.enqueue(payload)
                case 0x03, 0x04: stream?.markClosed()
                default: throw SudokuNativeError.protocolError("bad mux frame")
                }
            } catch {
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
    private var queue = Data()
    private var closed = false

    init(client: SudokuMuxClient, id: UInt32) { self.client = client; self.id = id }

    func send(_ data: Data) throws {
        var offset = 0
        while offset < data.count {
            let count = min(128 * 1024, data.count - offset)
            try client?.sendFrame(type: 0x02, streamID: id, payload: data.subdata(in: offset..<(offset + count)))
            offset += count
        }
    }

    func receive(max: Int) throws -> Data {
        condition.lock(); defer { condition.unlock() }
        while queue.isEmpty && !closed { condition.wait() }
        if queue.isEmpty && closed { throw SudokuNativeError.closed }
        let n = min(max, queue.count)
        let out = Data(queue.prefix(n))
        queue.removeFirst(n)
        return out
    }

    func enqueue(_ data: Data) {
        condition.lock(); if !closed { queue.append(data); condition.signal() }; condition.unlock()
    }

    func close() { client?.close(stream: self) }
    func markClosed() { condition.lock(); closed = true; condition.broadcast(); condition.unlock() }
}

final class SudokuTCPProxyConnection: ProxyConnection {
    private let stream: SudokuRecordStream
    private let readQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.tcp.read", qos: .userInitiated)
    private let writeQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.tcp.write", qos: .userInitiated)
    private var closed = false

    init(stream: SudokuRecordStream) { self.stream = stream; super.init() }
    override var isConnected: Bool { !lock.withLock { closed } }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        writeQueue.async { do { try self.stream.send(data); completion(nil) } catch { completion(error) } }
    }

    override func sendRaw(data: Data) { sendRaw(data: data) { if let error = $0 { sudokuLogger.error("[Sudoku] send failed: \(error.localizedDescription)") } } }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        readQueue.async { do { completion(try self.stream.receive(max: 16 * 1024), nil) } catch SudokuNativeError.closed { completion(nil, nil) } catch { completion(nil, error) } }
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
        writeQueue.async { do { try self.stream.send(data); completion(nil) } catch { completion(error) } }
    }

    override func sendRaw(data: Data) { sendRaw(data: data) { if let error = $0 { sudokuLogger.error("[Sudoku-Mux] send failed: \(error.localizedDescription)") } } }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        readQueue.async { do { completion(try self.stream.receive(max: 16 * 1024), nil) } catch SudokuNativeError.closed { completion(nil, nil) } catch { completion(nil, error) } }
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
                let addr = try SudokuAddress.encode(host: self.destinationHost, port: self.destinationPort)
                var frame = Data([UInt8(addr.count >> 8), UInt8(addr.count & 0xff), UInt8(data.count >> 8), UInt8(data.count & 0xff)])
                frame.append(addr)
                frame.append(data)
                try self.stream.send(frame)
                completion(nil)
            } catch { completion(error) }
        }
    }

    override func sendRaw(data: Data) { sendRaw(data: data) { if let error = $0 { sudokuLogger.error("[Sudoku-UoT] send failed: \(error.localizedDescription)") } } }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        readQueue.async {
            do {
                let hdr = try self.stream.readExact(4)
                let addrLen = Int(UInt16(hdr[0]) << 8 | UInt16(hdr[1]))
                let payloadLen = Int(UInt16(hdr[2]) << 8 | UInt16(hdr[3]))
                _ = try self.stream.readExact(addrLen)
                completion(try self.stream.readExact(payloadLen), nil)
            } catch SudokuNativeError.closed { completion(nil, nil) } catch { completion(nil, error) }
        }
    }

    override func cancel() { lock.withLock { closed = true }; stream.close() }
}
