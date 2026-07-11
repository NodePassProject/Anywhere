//
//  ProxyClient+Sudoku.swift
//  Anywhere
//
//  Created by saba-futai on 4/23/26.
//

import Foundation
import Synchronization

private let sudokuMuxPoolLogger = AnywhereLogger(category: "SudokuMuxPool")

private enum SudokuConnectCommand {
    case tcp
    case udp
}

extension ProxyClient {
    func connectWithSudoku(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data? = nil,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let sudokuCommand: SudokuConnectCommand
        switch command {
        case .tcp:
            sudokuCommand = .tcp
        case .udp:
            sudokuCommand = .udp
        case .mux:
            completion(.failure(ProxyError.protocolError("Sudoku does not use the host mux manager")))
            return
        }

        let configuration = configuration
        let directDialHost = directDialHost
        let initialTunnel = tunnel
        let usesInitialTunnel = initialTunnel != nil
        let factory = SudokuConnectionFactory(
            configuration: configuration,
            initialTunnel: initialTunnel,
            directDialHost: directDialHost
        )
        own(factory)

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let client = try SudokuNativeClient(configuration: configuration, factory: factory)
                let connection: ProxyConnection
                switch sudokuCommand {
                case .tcp:
                    if client.shouldUseNativeMux {
                        if !usesInitialTunnel {
                            let lease = try SudokuSharedMuxPool.dialTCP(
                                configuration: configuration,
                                directDialHost: directDialHost,
                                host: destinationHost,
                                port: destinationPort
                            )
                            do {
                                try ProxyClient.sendSudokuInitialData(initialData, to: lease.stream)
                                connection = SudokuMuxTCPProxyConnection(
                                    client: lease.client,
                                    stream: lease.stream,
                                    closesClientOnClose: false,
                                    onClose: lease.release
                                )
                            } catch {
                                lease.stream.close()
                                lease.release()
                                throw error
                            }
                        } else {
                            let multiplexer = try client.openMux()
                            let stream = try multiplexer.dialTCP(host: destinationHost, port: destinationPort)
                            try ProxyClient.sendSudokuInitialData(initialData, to: stream)
                            connection = SudokuMuxTCPProxyConnection(client: multiplexer, stream: stream)
                        }
                    } else {
                        let stream = try client.openTCP(host: destinationHost, port: destinationPort)
                        try stream.sendInitialDataIfNeeded(initialData)
                        connection = SudokuTCPProxyConnection(stream: stream)
                    }
                case .udp:
                    let stream = try client.openUoT()
                    connection = SudokuUDPProxyConnection(
                        stream: stream,
                        destinationHost: destinationHost,
                        destinationPort: destinationPort
                    )
                }
                completion(.success(connection))
            } catch {
                factory.closeAll()
                completion(.failure(error))
            }
        }
    }

    private static func sendSudokuInitialData(_ data: Data?, to stream: SudokuMuxStream) throws {
        guard let data, !data.isEmpty else { return }
        try stream.send(data)
    }
}

private extension SudokuRecordStream {
    func sendInitialDataIfNeeded(_ data: Data?) throws {
        guard let data, !data.isEmpty else { return }
        try send(data)
    }
}

private struct SudokuSharedMuxKey: Hashable {
    let serverAddress: String
    let serverPort: UInt16
    let directDialHost: String
    let outbound: Outbound

    init(configuration: ProxyConfiguration, directDialHost: String) {
        self.serverAddress = configuration.serverAddress
        self.serverPort = configuration.serverPort
        self.directDialHost = directDialHost
        self.outbound = configuration.outbound
    }
}

private struct SudokuSharedMuxLease {
    let client: SudokuMuxClient
    let stream: SudokuMuxStream
    let release: () -> Void
}

private enum SudokuSharedMuxPool {
    private static let maxEntries = 16

    private struct State {
        var clients: [SudokuSharedMuxKey: SudokuSharedMuxClient] = [:]
        var accessOrder: [SudokuSharedMuxKey] = []
    }

    private static let state = Mutex(State())

    static func dialTCP(
        configuration: ProxyConfiguration,
        directDialHost: String,
        host: String,
        port: UInt16
    ) throws -> SudokuSharedMuxLease {
        let key = SudokuSharedMuxKey(configuration: configuration, directDialHost: directDialHost)
        let (shared, evicted) = sharedClient(for: key, configuration: configuration)
        for client in evicted { client.close() }
        shared.startMaintaining()
        shared.retainStream()
        do {
            let (client, stream) = try shared.dialTCP(host: host, port: port)
            touch(key)
            return SudokuSharedMuxLease(client: client, stream: stream) {
                shared.releaseStream()
                trimIfNeeded()
            }
        } catch {
            shared.releaseStream()
            if shared.isStopped {
                remove(key: key, closing: false)
            }
            throw error
        }
    }

    static func warm(
        configuration: ProxyConfiguration,
        directDialHost: String,
        timeout: TimeInterval
    ) {
        let key = SudokuSharedMuxKey(configuration: configuration, directDialHost: directDialHost)
        let (shared, evicted) = sharedClient(for: key, configuration: configuration)
        for client in evicted { client.close() }
        shared.startMaintaining()
        shared.waitUntilReady(timeout: timeout)
    }

    private static func sharedClient(
        for key: SudokuSharedMuxKey,
        configuration: ProxyConfiguration
    ) -> (SudokuSharedMuxClient, [SudokuSharedMuxClient]) {
        state.withLock { state in
            let shared: SudokuSharedMuxClient
            if let existing = state.clients[key] {
                shared = existing
            } else {
                shared = SudokuSharedMuxClient(
                    configuration: configuration,
                    directDialHost: key.directDialHost
                )
                state.clients[key] = shared
            }
            touchLocked(key, in: &state)
            return (shared, trimIfNeededLocked(&state, protecting: key))
        }
    }

    private static func touch(_ key: SudokuSharedMuxKey) {
        state.withLock { touchLocked(key, in: &$0) }
    }

    private static func touchLocked(_ key: SudokuSharedMuxKey, in state: inout State) {
        state.accessOrder.removeAll { $0 == key }
        state.accessOrder.append(key)
    }

    private static func remove(key: SudokuSharedMuxKey, closing: Bool) {
        let client = state.withLock { (state: inout State) -> SudokuSharedMuxClient? in
            state.accessOrder.removeAll { $0 == key }
            return state.clients.removeValue(forKey: key)
        }
        if closing { client?.close() }
    }

    private static func trimIfNeeded() {
        let evicted = state.withLock { trimIfNeededLocked(&$0) }
        for client in evicted { client.close() }
    }

    private static func trimIfNeededLocked(
        _ state: inout State,
        protecting protectedKey: SudokuSharedMuxKey? = nil
    ) -> [SudokuSharedMuxClient] {
        var evicted: [SudokuSharedMuxClient] = []
        state.accessOrder.removeAll { state.clients[$0] == nil }
        while state.clients.count > maxEntries {
            guard let victimIndex = state.accessOrder.firstIndex(where: { key in
                key != protectedKey && state.clients[key]?.canEvict == true
            }) else {
                break
            }
            let victim = state.accessOrder.remove(at: victimIndex)
            guard let client = state.clients.removeValue(forKey: victim) else { continue }
            evicted.append(client)
        }
        return evicted
    }

    static func reclaim() {
        let victims = state.withLock { (state: inout State) -> [SudokuSharedMuxClient] in
            let all = Array(state.clients.values)
            state.clients.removeAll()
            state.accessOrder.removeAll()
            return all
        }
        for client in victims { client.close() }
    }
}

enum SudokuTransportPool {
    static let pool: TransportPool = Reclaimer()

    static func warm(
        configuration: ProxyConfiguration,
        directDialHost: String,
        timeout: TimeInterval = 2
    ) {
        guard case .sudoku(let sudoku) = configuration.outbound,
              sudoku.multiplex == .on else {
            return
        }
        SudokuSharedMuxPool.warm(
            configuration: configuration,
            directDialHost: directDialHost,
            timeout: timeout
        )
    }

    private final class Reclaimer: TransportPool {
        func reclaim() { SudokuSharedMuxPool.reclaim() }
    }
}

private final class SudokuSharedMuxClient: @unchecked Sendable {
    private let configuration: ProxyConfiguration
    private let directDialHost: String
    private let condition = NSCondition()
    private var client: SudokuMuxClient?
    private var factory: SudokuConnectionFactory?
    private var creating = false
    private var maintaining = false
    private var stopped = false
    private var activeStreams = 0

    init(configuration: ProxyConfiguration, directDialHost: String) {
        self.configuration = configuration
        self.directDialHost = directDialHost
    }

    var canEvict: Bool {
        condition.lock()
        defer { condition.unlock() }
        return activeStreams == 0
    }

    var isStopped: Bool {
        condition.lock()
        defer { condition.unlock() }
        return stopped
    }

    func retainStream() {
        condition.lock()
        if !stopped {
            activeStreams += 1
        }
        condition.unlock()
    }

    func releaseStream() {
        condition.lock()
        activeStreams = max(0, activeStreams - 1)
        condition.broadcast()
        condition.unlock()
    }

    func dialTCP(host: String, port: UInt16) throws -> (SudokuMuxClient, SudokuMuxStream) {
        let multiplexer = try getOrCreateMux()
        do {
            return (multiplexer, try multiplexer.dialTCP(host: host, port: port))
        } catch {
            reset(multiplexer)
            let retry = try getOrCreateMux()
            return (retry, try retry.dialTCP(host: host, port: port))
        }
    }

    func startMaintaining() {
        condition.lock()
        guard !stopped, !maintaining else {
            condition.unlock()
            return
        }
        maintaining = true
        condition.unlock()

        DispatchQueue.global(qos: .utility).async {
            self.maintainLoop()
        }
    }

    func waitUntilReady(timeout: TimeInterval) {
        guard timeout > 0 else { return }
        let deadline = Date().addingTimeInterval(timeout)
        condition.lock()
        while client == nil && !stopped {
            guard condition.wait(until: deadline) else { break }
        }
        condition.unlock()
    }

    func close() {
        condition.lock()
        if stopped {
            condition.unlock()
            return
        }
        stopped = true
        let old = client
        let oldFactory = factory
        client = nil
        factory = nil
        condition.broadcast()
        condition.unlock()
        old?.close()
        oldFactory?.closeAll()
    }

    private func getOrCreateMux() throws -> SudokuMuxClient {
        condition.lock()
        while true {
            if stopped {
                condition.unlock()
                throw SudokuNativeError.closed
            }
            if let existing = client, !existing.isClosed {
                condition.unlock()
                return existing
            }
            if let stale = client {
                let staleFactory = factory
                client = nil
                factory = nil
                condition.unlock()
                stale.close()
                staleFactory?.closeAll()
                condition.lock()
                continue
            }
            if !creating {
                creating = true
                break
            }
            condition.wait()
        }
        condition.unlock()

        do {
            let factory = SudokuConnectionFactory(
                configuration: configuration,
                initialTunnel: nil,
                directDialHost: directDialHost
            )
            let created: SudokuMuxClient
            do {
                let native = try SudokuNativeClient(configuration: configuration, factory: factory)
                created = try native.openMux()
            } catch {
                factory.closeAll()
                throw error
            }
            condition.lock()
            if stopped {
                creating = false
                condition.broadcast()
                condition.unlock()
                created.close()
                factory.closeAll()
                throw SudokuNativeError.closed
            }
            client = created
            self.factory = factory
            creating = false
            condition.broadcast()
            condition.unlock()
            return created
        } catch {
            condition.lock()
            creating = false
            condition.broadcast()
            condition.unlock()
            throw error
        }
    }

    private func reset(_ mux: SudokuMuxClient) {
        let oldFactory: SudokuConnectionFactory?
        condition.lock()
        if client === mux {
            client = nil
            oldFactory = factory
            factory = nil
        } else {
            oldFactory = nil
        }
        condition.broadcast()
        condition.unlock()
        mux.close()
        oldFactory?.closeAll()
    }

    private func maintainLoop() {
        var retryDelay: TimeInterval = 0.25
        var lastReportedError: String?
        while true {
            do {
                let mux = try getOrCreateMux()
                retryDelay = 0.25
                lastReportedError = nil
                mux.waitUntilClosed()
                reset(mux)
            } catch {
                if isStopped { return }
                let message = error.localizedDescription
                if message != lastReportedError {
                    sudokuMuxPoolLogger.warning("[Sudoku-Mux] warm session unavailable: \(message)")
                    lastReportedError = message
                }
            }

            guard waitForRetry(retryDelay) else { return }
            retryDelay = min(retryDelay * 2, 5)
        }
    }

    private func waitForRetry(_ delay: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(delay)
        condition.lock()
        while !stopped {
            if !condition.wait(until: deadline) {
                condition.unlock()
                return true
            }
        }
        condition.unlock()
        return false
    }
}
