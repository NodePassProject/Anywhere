//
//  SudokuRecordLayer.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation
import CryptoKit
import Synchronization

nonisolated private let sudokuObfsReadChunkSize = 128 * 1024

nonisolated final class SudokuObfsTransport: Sendable {
    enum Wire {
        case stream(BlockingProxyStream)
        case httpMask(SudokuHTTPMaskTransport)
        
        func close() {
            switch self {
            case .stream(let stream): stream.cancel()
            case .httpMask(let mask): mask.close()
            }
        }
    }

    private let wire: Wire
    private let tables: SudokuTables
    private let threshold: UInt64
    private let pureDownlink: Bool
    private struct SendState {
        var rng: SudokuRandom
    }
    private let sendState: Mutex<SendState>
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
        var seeded = SudokuRandom(seed: seed)
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
        var out = try await receive(max: count)
        if out.count < count { out.reserveCapacity(count) }
        while out.count < count { out.append(try await receive(max: count - out.count)) }
        return out
    }

    func readExactAllowingEOF(_ count: Int, what: String) async throws -> Data? {
        guard count > 0 else { return Data() }
        var out = Data()
        while out.count < count {
            do {
                let chunk = try await receive(max: count - out.count)
                if out.isEmpty {
                    out = chunk
                    if out.count < count { out.reserveCapacity(count) }
                } else {
                    out.append(chunk)
                }
            } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
                if out.isEmpty { return nil }
                throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "truncated \(what)"))
            }
        }
        return out
    }

    func close() {
        wire.close()
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
    
    private let method: SudokuAEADMethod
    
    private struct SendState {
        var baseSend: Data
        var sendEpoch: UInt32
        var sendSeq: UInt64
        var sendBytes: Int64 = 0
        var sendEpochUpdates: UInt32 = 0
        var epochKey: SymmetricKey?
    }
    private let sendState: Mutex<SendState>
    
    private struct State {
        var baseRecv: Data
        var recvEpoch: UInt32 = 0
        var recvSeq: UInt64 = 0
        var recvInitialized = false
        var epochKey: SymmetricKey?
        var readBuffer = SudokuDataQueue()
    }
    private let state: Mutex<State>
    
    private let sendChain = SerialSender()
    
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
                s.epochKey = nil
            }
            state.withLock { state in
                state.baseRecv = recv
                state.recvEpoch = 0
                state.recvSeq = 0
                state.recvInitialized = false
                state.epochKey = nil
                state.readBuffer.removeAll()
            }
        }
    }

    func send(_ data: Data) async throws {
        if data.isEmpty { return }
        try await sendBuffers([data])
    }
    
    func sendBuffers(_ buffers: [Data]) async throws {
        try await chainedSend { [self] in
            var pending = SudokuDataQueue()
            for buffer in buffers { pending.append(buffer) }
            guard !pending.isEmpty else { return }
            if method == .none {
                try await transport.send(pending.readCoalesced(max: pending.count))
                return
            }
            while !pending.isEmpty {
                let maxPlain = 65535 - 12 - 16
                let chunk = pending.readCoalesced(max: maxPlain)
                let frame = try sendState.withLock { s -> Data in
                    var header = Data()
                    var epochBE = s.sendEpoch.bigEndian
                    var seqBE = s.sendSeq.bigEndian
                    header.append(Data(bytes: &epochBE, count: 4))
                    header.append(Data(bytes: &seqBE, count: 8))
                    s.sendSeq &+= 1
                    let key = s.epochKey ?? SudokuNativeCrypto.recordSymmetricKey(base: s.baseSend, method: method, epoch: s.sendEpoch)
                    s.epochKey = key
                    let cipher = try SudokuNativeCrypto.seal(method: method, key: key, nonce: header, plaintext: chunk, aad: header)
                    let bodyLen = header.count + cipher.count
                    return SudokuBufferPool.makeData(capacity: bodyLen + 2) { output in
                        output[0] = UInt8(bodyLen >> 8)
                        output[1] = UInt8(truncatingIfNeeded: bodyLen)
                        header.withUnsafeBytes { input in
                            output.baseAddress!.advanced(by: 2).copyMemory(from: input.baseAddress!, byteCount: input.count)
                        }
                        cipher.withUnsafeBytes { input in
                            output.baseAddress!.advanced(by: 2 + header.count).copyMemory(from: input.baseAddress!, byteCount: input.count)
                        }
                        return bodyLen + 2
                    }
                }
                try await transport.send(frame)
                try maybeBumpSendEpoch(added: chunk.count)
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
                let plain = try decryptRecord(&state, body: body)
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
        var out = try await receive(max: count)
        if out.count < count { out.reserveCapacity(count) }
        while out.count < count { out.append(try await receive(max: count - out.count)) }
        return out
    }

    private static func parseRecordLength(_ lenData: Data) throws -> Int {
        let bodyLen = Int(UInt16(lenData.uint8(at: 0)) << 8 | UInt16(lenData.uint8(at: 1)))
        guard bodyLen >= 12 && bodyLen <= 65535 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad record length")) }
        return bodyLen
    }

    private func decryptRecord(_ state: inout State, body: Data) throws -> Data {
        let epoch = body.uint32BE(at: 0)
        let seq = body.uint64BE(at: 4)
        if state.recvInitialized {
            if epoch < state.recvEpoch { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "replayed record epoch")) }
            if epoch == state.recvEpoch && seq != state.recvSeq { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "out of order record")) }
            if epoch > state.recvEpoch && epoch - state.recvEpoch > 8 { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "record epoch jump")) }
        }
        let key: SymmetricKey
        if epoch == state.recvEpoch, let cached = state.epochKey {
            key = cached
        } else {
            key = SudokuNativeCrypto.recordSymmetricKey(base: state.baseRecv, method: method, epoch: epoch)
        }
        let plain = try SudokuNativeCrypto.openRecord(method: method, key: key, body: body)
        state.epochKey = key
        state.recvEpoch = epoch
        state.recvSeq = seq &+ 1
        state.recvInitialized = true
        return plain
    }

    func close() {
        sendChain.cancel()
        transport.close()
    }

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
            s.epochKey = nil
            s.sendEpochUpdates &+= 1
            s.sendSeq = try SudokuNativeCrypto.randomNonZeroUInt64()
        }
    }
}
