//
//  SudokuProxyConnection.swift
//  Anywhere
//
//  Created by saba-futai on 4/23/26.
//

import Foundation
import Synchronization

nonisolated private let sudokuTCPReceiveChunkSize = 64 * 1024

nonisolated final class SudokuTCPProxyConnection:
    ProxyConnection,
    Sendable
{
    private let phase = Mutex<SudokuLifecycle>(.open)
    private let stream: SudokuRecordStream

    init(stream: SudokuRecordStream) { self.stream = stream }
    var isConnected: Bool { phase.withLock { $0 == .open } }

    func sendRaw(_ data: Data) async throws {
        if phase.withLock({ $0 == .closed }) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        try await stream.send(data)
    }

    func receiveRaw() async throws -> Data? {
        if phase.withLock({ $0 == .closed }) { return nil }
        do {
            return try await stream.receive(max: sudokuTCPReceiveChunkSize).zeroBasedData()
        } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
            return nil
        }
    }

    func cancel() {
        _ = phase.withLock { SudokuLifecycle.transition(&$0, to: .closed) }
        stream.close()
    }
}

nonisolated final class SudokuMuxTCPProxyConnection:
    ProxyConnection,
    Sendable
{
    private enum Phase: PhaseTransitionable {
        case open
        case halfClosedRemote
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.open, .halfClosedRemote):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }

        var readsFinished: Bool { self != .open }
    }
    private struct State: PhaseHolding {
        var onClose: (@Sendable () -> Void)?
        var phase: Phase = .open
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

    var isConnected: Bool { !state.withLock { $0.phase == .closed } && !client.isClosed }

    func sendRaw(_ data: Data) async throws {
        if state.withLock({ $0.phase == .closed }) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        do {
            try await stream.send(data)
        } catch {
            closeResources(closeStream: true)
            throw error
        }
    }

    func receiveRaw() async throws -> Data? {
        if state.withLock({ $0.phase.readsFinished }) { return nil }
        do {
            if let data = try await stream.receive(max: sudokuTCPReceiveChunkSize), !data.isEmpty {
                return data.zeroBasedData()
            }
            state.withLock { _ = $0.transition(to: .halfClosedRemote) }
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
            guard state.transition(to: .closed) else { return nil }
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
    private let phase = Mutex<SudokuLifecycle>(.open)
    private let stream: SudokuRecordStream
    private let destinationHost: String
    private let destinationPort: UInt16

    init(stream: SudokuRecordStream, destinationHost: String, destinationPort: UInt16) {
        self.stream = stream
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
    }

    var isConnected: Bool { phase.withLock { $0 == .open } }

    func sendRaw(_ data: Data) async throws {
        if phase.withLock({ $0 == .closed }) { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)) }
        let address = try SudokuAddress.encode(host: destinationHost, port: destinationPort)
        guard address.count <= UInt16.max else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "UoT address too large")) }
        guard data.count <= UInt16.max else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "UoT payload too large")) }
        var frame = Data([UInt8(address.count >> 8), UInt8(address.count & 0xff), UInt8(data.count >> 8), UInt8(data.count & 0xff)])
        frame.append(address)
        frame.append(data)
        try await stream.send(frame)
    }

    func receiveRaw() async throws -> Data? {
        if phase.withLock({ $0 == .closed }) { return nil }
        do {
            let header = try await stream.readExact(4)
            let addrLen = Int(UInt16(header.uint8(at: 0)) << 8 | UInt16(header.uint8(at: 1)))
            let payloadLen = Int(UInt16(header.uint8(at: 2)) << 8 | UInt16(header.uint8(at: 3)))
            guard addrLen > 0 && addrLen <= 64 * 1024 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad UoT address length")) }
            guard payloadLen <= 64 * 1024 else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad UoT payload length")) }
            _ = try await stream.readExact(addrLen)
            return try await stream.readExact(payloadLen).zeroBasedData()
        } catch AnywhereError.proxy(.sudoku, .connectionClosed) {
            return nil
        }
    }

    func cancel() {
        _ = phase.withLock { SudokuLifecycle.transition(&$0, to: .closed) }
        stream.close()
    }
}
