//
//  SudokuNativeClient.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation
import CryptoKit

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
        do {
            try await writeKIP(record: record, type: 0x10, payload: SudokuAddress.encode(host: host, port: port))
        } catch {
            record.close()
            throw error
        }
        return record
    }

    func openUoT() async throws -> SudokuRecordStream {
        let record = try await connectBase()
        do {
            try await writeKIP(record: record, type: 0x12, payload: Data())
        } catch {
            record.close()
            throw error
        }
        return record
    }
    
    func openMux(
        ownsFactory: Bool = false,
        onClose: (@Sendable (SudokuMuxClient) -> Void)? = nil
    ) async throws -> SudokuMuxClient {
        let record = try await connectBase()
        do {
            try await writeKIP(record: record, type: 0x11, payload: Data())
            try await record.waitHTTPMaskReady(timeout: 30)
            let usesHTTPMaskControlFrames = !config.httpMask.disable &&
                [SudokuHTTPMaskMode.stream, .poll, .auto].contains(config.httpMask.mode)
            return SudokuMuxClient(
                record: record,
                factory: ownsFactory ? factory : nil,
                usesHTTPMaskControlFrames: usesHTTPMaskControlFrames,
                onClose: onClose
            )
        } catch {
            record.close()
            throw error
        }
    }

    private func connectBase() async throws -> SudokuRecordStream {
        let wire: SudokuObfsTransport.Wire
        var earlyBases: (c2s: Data, s2c: Data)?

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
            if !mask.earlyResponsePayload.isEmpty {
                do {
                    earlyBases = try completeEarlyHandshake(state: early.state, response: mask.earlyResponsePayload)
                } catch {
                    wire.close()
                    throw error
                }
            }
        } else {
            let stream = try await factory.open(host: config.serverHost, port: config.serverPort, useTLS: false, serverName: nil)
            if !config.httpMask.disable && config.httpMask.mode == .legacy {
                let path = SudokuHTTPMaskPathRoot.apply(config.httpMask.pathRoot, to: "/api")
                let host = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
                let request = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: 1048576\r\n\r\n"
                do {
                    try await stream.sendAll(Data(request.utf8))
                } catch {
                    stream.cancel()
                    throw error
                }
            }
            wire = .stream(stream)
        }
        
        do {
            let transport = try SudokuObfsTransport(wire: wire, tables: tables, config: config)
            let bases = earlyBases ?? SudokuNativeCrypto.pskBases(config.key)
            let record = try SudokuRecordStream(transport: transport, method: config.aeadMethod, baseSend: bases.c2s, baseRecv: bases.s2c)
            if earlyBases == nil { try await performKIP(record: record) }
            return record
        } catch {
            wire.close()
            throw error
        }
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
        var rng = SudokuRandom(seed: seed)
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
            let bodyLen = Int(UInt16(data.uint8(at: offset)) << 8 | UInt16(data.uint8(at: offset + 1)))
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
                let kipLen = Int(UInt16(out.uint8(at: 4)) << 8 | UInt16(out.uint8(at: 5)))
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
        let auth = webSocketAuthToken(mode: "ws", method: "GET", path: "/ws")
        let path = appendWebSocketAuth(applyHTTPMaskPathRoot("/ws"), token: auth)
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

    private func appendWebSocketAuth(_ path: String, token: String) -> String {
        path + (path.contains("?") ? "&" : "?") + "auth=\(token)"
    }

    private func webSocketAuthToken(mode: String, method: String, path: String) -> String {
        SudokuHTTPMaskWebSocketAuth.token(key: config.key, mode: mode, method: method, path: path)
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
        guard header.uint8(at: 0) == 0x6b, header.uint8(at: 1) == 0x69, header.uint8(at: 2) == 0x70 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad KIP magic")) }
        let length = Int(UInt16(header.uint8(at: 4)) << 8 | UInt16(header.uint8(at: 5)))
        do {
            return (header.uint8(at: 3), try await record.readExact(length))
        } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
            throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "truncated KIP payload"))
        }
    }

    private func parseKIP(_ data: Data) throws -> (type: UInt8, payload: Data) {
        guard data.count >= 6 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "short KIP frame")) }
        guard data.uint8(at: 0) == 0x6b, data.uint8(at: 1) == 0x69, data.uint8(at: 2) == 0x70 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad KIP magic")) }
        let length = Int(UInt16(data.uint8(at: 4)) << 8 | UInt16(data.uint8(at: 5)))
        guard data.count >= 6 + length else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "truncated KIP frame \(data.count)/\(6 + length)")) }
        return (data.uint8(at: 3), data.rangeData(offset: 6, count: length))
    }
}
