//
//  NowhereMorph.swift
//  Anywhere
//
//  Created by NodePassProject on 9/11/26.
//

import CryptoKit
import Foundation
import Security
import Synchronization

nonisolated enum NowhereMorph {
    static let nonceSize = 12
    static let tcpPreludeSize = 64
    static let byteLimit: UInt64 = (1 << 38) - 64
    private static let handshakeDeadline: Duration = .seconds(30)

    struct Keys: Hashable, Sendable {
        let tcpClientToServer: Data
        let tcpServerToClient: Data
        let udpClientToServer: Data
        let udpServerToClient: Data
    }

    static func deriveKeys(sharedKey: String) throws -> Keys {
        let input = Data(sharedKey.utf8)
        guard !input.isEmpty, input.count <= UInt8.max else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Invalid Morph shared key"))
        }
        func derive(_ label: String) -> Data {
            let key = HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: input),
                salt: Data("nowhere/morph".utf8),
                info: Data(label.utf8),
                outputByteCount: 32
            )
            return key.withUnsafeBytes { Data($0) }
        }
        return Keys(
            tcpClientToServer: derive("tcp c2s"),
            tcpServerToClient: derive("tcp s2c"),
            udpClientToServer: derive("udp c2s"),
            udpServerToClient: derive("udp s2c")
        )
    }

    static func connectTLS(
        client: TLSClient,
        base: any ByteTransport,
        keys: Keys,
        prelude: NowhereMorphPrelude
    ) async throws -> TLSRecordConnection {
        do {
            return try await withTaskCancellationHandler {
                try Task.checkCancellation()
                let record = try await withDialDeadline(handshakeDeadline, onExpiry: {
                    base.cancel()
                    client.cancel()
                }, error: {
                    AnywhereError.tls(.handshakeFailed(detail: "Morph bootstrap or TLS handshake timed out"))
                }, discardingLateResult: { record in
                    record.cancel()
                }, operation: {
                    let transport = try await NowhereMorphTCPTransport.bootstrap(
                        inner: base,
                        keys: keys,
                        prelude: prelude
                    )
                    return try await client.connect(transport: transport)
                })
                guard !Task.isCancelled else {
                    record.cancel()
                    throw CancellationError()
                }
                return record
            } onCancel: {
                base.cancel()
                client.cancel()
            }
        } catch {
            base.cancel()
            client.cancel()
            throw error
        }
    }

    static func apply(_ input: Data, key: Data, nonce: Data, offset: UInt64) throws -> Data {
        try validate(count: input.count, keyCount: key.count, nonceCount: nonce.count, offset: offset)
        if input.isEmpty { return Data() }
        var output = Data(count: input.count)
        output.withUnsafeMutableBytes { destination in
            input.withUnsafeBytes { source in
                key.withUnsafeBytes { keyBytes in
                    nonce.withUnsafeBytes { nonceBytes in
                        NowhereMorphCrypto.xor(
                            destination: destination,
                            input: source,
                            key: keyBytes,
                            nonce: nonceBytes,
                            offset: offset
                        )
                    }
                }
            }
        }
        return output
    }

    static func apply(
        _ input: UnsafeRawBufferPointer,
        into output: UnsafeMutableRawBufferPointer,
        key: UnsafeRawBufferPointer,
        nonce: UnsafeRawBufferPointer,
        offset: UInt64
    ) throws {
        try validate(count: input.count, keyCount: key.count, nonceCount: nonce.count, offset: offset)
        guard output.count == input.count else {
            throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Morph buffer size mismatch"))
        }
        NowhereMorphCrypto.xor(destination: output, input: input, key: key, nonce: nonce, offset: offset)
    }

    private static func validate(count: Int, keyCount: Int, nonceCount: Int, offset: UInt64) throws {
        guard keyCount == 32, nonceCount == nonceSize,
              offset <= byteLimit, UInt64(count) <= byteLimit - offset else {
            throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Morph stream limit exceeded"))
        }
    }
}

nonisolated final class NowhereMorphNonceGenerator: Sendable {
    typealias RandomBytes = @Sendable (Int) throws -> Data

    private struct State {
        var key: Data
        var nonce: Data
        var offset: UInt64
    }

    private let state: Mutex<State>
    private let randomBytes: RandomBytes
    private let reseedByteLimit: UInt64

    init(
        randomBytes: @escaping RandomBytes = NowhereMorphNonceGenerator.secureRandomBytes,
        reseedByteLimit: UInt64 = NowhereMorph.byteLimit
    ) throws {
        guard reseedByteLimit >= UInt64(NowhereMorph.nonceSize) else {
            throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid Morph nonce limit"))
        }
        self.randomBytes = randomBytes
        self.reseedByteLimit = reseedByteLimit
        state = Mutex(try Self.makeState(randomBytes: randomBytes))
    }

    func next(into nonce: UnsafeMutableRawBufferPointer) throws {
        try state.withLock { state in
            if state.offset > reseedByteLimit - UInt64(NowhereMorph.nonceSize) {
                state = try Self.makeState(randomBytes: randomBytes)
            }
            let offset = state.offset
            try withUnsafeTemporaryAllocation(byteCount: NowhereMorph.nonceSize, alignment: 4) { zero in
                zero.initializeMemory(as: UInt8.self, repeating: 0)
                try state.key.withUnsafeBytes { key in
                    try state.nonce.withUnsafeBytes { base in
                        try NowhereMorph.apply(UnsafeRawBufferPointer(zero), into: nonce, key: key, nonce: base, offset: offset)
                    }
                }
            }
            state.offset += UInt64(NowhereMorph.nonceSize)
        }
    }

    private static func makeState(randomBytes: RandomBytes) throws -> State {
        let seed = try randomBytes(44)
        guard seed.count == 44 else {
            throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Failed to seed Morph nonce generator"))
        }
        return State(key: Data(seed.prefix(32)), nonce: Data(seed.suffix(12)), offset: 0)
    }

    static func secureRandomBytes(count: Int) throws -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Failed to seed Morph nonce generator"))
        }
        return bytes
    }
}

nonisolated final class NowhereMorphPacketObfuscator: QUICPacketObfuscator {
    private struct FailureState {
        var failed = false
        var handler: (@Sendable (Error) -> Void)?
    }

    private let sendKey: Data
    private let receiveKey: Data
    private let nonceGenerator: NowhereMorphNonceGenerator
    private let failureState = Mutex(FailureState())

    init(sendKey: Data, receiveKey: Data) throws {
        self.sendKey = sendKey
        self.receiveKey = receiveKey
        nonceGenerator = try NowhereMorphNonceGenerator()
    }

    init(sendKey: Data, receiveKey: Data, nonceGenerator: NowhereMorphNonceGenerator) {
        self.sendKey = sendKey
        self.receiveKey = receiveKey
        self.nonceGenerator = nonceGenerator
    }

    func setFailureHandler(_ handler: @escaping @Sendable (Error) -> Void) {
        let error: Error? = failureState.withLock { state in
            state.handler = handler
            return state.failed
                ? AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Morph nonce generation failed"))
                : nil
        }
        if let error { handler(error) }
    }

    func seal(_ packet: UnsafeRawBufferPointer) -> [Data] {
        var output = Data(count: NowhereMorph.nonceSize + packet.count)
        let sealed: Bool = output.withUnsafeMutableBytes { raw in
            let nonce = UnsafeMutableRawBufferPointer(rebasing: raw[..<NowhereMorph.nonceSize])
            let payload = UnsafeMutableRawBufferPointer(rebasing: raw[NowhereMorph.nonceSize...])
            do {
                try nonceGenerator.next(into: nonce)
                try sendKey.withUnsafeBytes { key in
                    try NowhereMorph.apply(packet, into: payload, key: key, nonce: UnsafeRawBufferPointer(nonce), offset: 0)
                }
                return true
            } catch {
                reportFailure(error)
                return false
            }
        }
        return sealed ? [output] : []
    }

    func open(_ datagram: Data) -> Data? {
        let count = datagram.count - NowhereMorph.nonceSize
        guard count > 0 else { return nil }
        var output = Data(count: count)
        let opened: Bool = datagram.withUnsafeBytes { raw in
            output.withUnsafeMutableBytes { destination in
                receiveKey.withUnsafeBytes { key in
                    (try? NowhereMorph.apply(
                        UnsafeRawBufferPointer(rebasing: raw[NowhereMorph.nonceSize...]),
                        into: destination,
                        key: key,
                        nonce: UnsafeRawBufferPointer(rebasing: raw[..<NowhereMorph.nonceSize]),
                        offset: 0
                    )) != nil
                }
            }
        }
        return opened ? output : nil
    }

    private func reportFailure(_ error: Error) {
        let handler: (@Sendable (Error) -> Void)? = failureState.withLock { state in
            guard !state.failed else { return nil }
            state.failed = true
            return state.handler
        }
        handler?(error)
    }
}

nonisolated final class NowhereMorphTCPTransport: ByteTransport, Sendable {
    private struct State {
        let nonce: Data
        var sendOffset: UInt64 = 0
        var receiveOffset: UInt64 = 0
    }

    private let inner: any ByteTransport
    private let clientToServerKey: Data
    private let serverToClientKey: Data
    private let state: Mutex<State>

    private init(inner: any ByteTransport, keys: NowhereMorph.Keys, nonce: Data) throws {
        guard nonce.count == NowhereMorph.nonceSize else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Invalid Morph nonce"))
        }
        self.inner = inner
        clientToServerKey = keys.tcpClientToServer
        serverToClientKey = keys.tcpServerToClient
        state = Mutex(State(nonce: nonce))
    }

    static func bootstrap(
        inner: any ByteTransport,
        keys: NowhereMorph.Keys,
        prelude policy: NowhereMorphPrelude
    ) async throws -> NowhereMorphTCPTransport {
        do {
            var prelude = try NowhereMorphNonceGenerator.secureRandomBytes(
                count: NowhereMorph.tcpPreludeSize
            )
            guard prelude.count == NowhereMorph.tcpPreludeSize else {
                throw AnywhereError.proxy(
                    .nowhere,
                    .connectionClosed(detail: "Failed to generate Morph TCP prelude")
                )
            }
            switch policy {
            case .low7:
                prelude.withUnsafeMutableBytes { bytes in
                    for index in bytes.indices {
                        bytes[index] &= 0x7f
                    }
                }
            case .full8:
                break
            }
            let nonce = try NowhereMorphNonceGenerator.secureRandomBytes(
                count: NowhereMorph.nonceSize
            )
            let transport = try NowhereMorphTCPTransport(inner: inner, keys: keys, nonce: nonce)
            try await inner.send(prelude)
            try await inner.send(nonce)
            return transport
        } catch {
            inner.cancel()
            throw error
        }
    }

    var isReady: Bool { inner.isReady }

    func send(_ data: Data) async throws {
        do {
            let wire = try state.withLock { state -> Data in
                let ciphertext = try NowhereMorph.apply(
                    data,
                    key: clientToServerKey,
                    nonce: state.nonce,
                    offset: state.sendOffset
                )
                state.sendOffset += UInt64(data.count)
                return ciphertext
            }
            try await inner.send(wire)
        } catch {
            inner.cancel()
            throw error
        }
    }

    func receive() async throws -> TransportChunk {
        do {
            switch try await inner.receive() {
            case .end:
                return .end
            case .bytes(let data):
                return try state.withLock { state in
                    let plaintext = try NowhereMorph.apply(
                        data,
                        key: serverToClientKey,
                        nonce: state.nonce,
                        offset: state.receiveOffset
                    )
                    state.receiveOffset += UInt64(data.count)
                    return .bytes(plaintext)
                }
            }
        } catch {
            inner.cancel()
            throw error
        }
    }

    func cancel() {
        inner.cancel()
    }
}
