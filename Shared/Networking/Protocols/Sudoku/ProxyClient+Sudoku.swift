//
//  ProxyClient+Sudoku.swift
//  Anywhere
//
//  Created by saba-futai on 4/23/26.
//

import Foundation
import Synchronization

extension ProxyClient {
    func connectWithSudoku(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data? = nil,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard command != .mux else {
            completion(.failure(ProxyError.protocolError("Sudoku does not use the host mux manager")))
            return
        }

        let factory = SudokuConnectionFactory(
            configuration: configuration,
            initialTunnel: tunnel,
            directDialHost: directDialHost
        )
        own(factory)

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let client = try SudokuNativeClient(configuration: self.configuration, factory: factory)
                let connection: ProxyConnection
                switch command {
                case .tcp:
                    if client.shouldUseNativeMux {
                        if self.tunnel == nil {
                            let lease = try SudokuSharedMuxPool.dialTCP(
                                configuration: self.configuration,
                                directDialHost: self.directDialHost,
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
                case .mux:
                    throw ProxyError.protocolError("Sudoku does not use the host mux manager")
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
        let (shared, evicted) = state.withLock { (state: inout State) -> (SudokuSharedMuxClient, [SudokuSharedMuxClient]) in
            let shared: SudokuSharedMuxClient
            if let existing = state.clients[key] {
                shared = existing
            } else {
                shared = SudokuSharedMuxClient(configuration: configuration, directDialHost: directDialHost)
                state.clients[key] = shared
            }
            touchLocked(key, in: &state)
            return (shared, trimIfNeededLocked(&state))
        }
        for client in evicted { client.close() }
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
            if shared.isClosed {
                remove(key: key, closing: false)
            }
            throw error
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

    private static func trimIfNeededLocked(_ state: inout State) -> [SudokuSharedMuxClient] {
        var evicted: [SudokuSharedMuxClient] = []
        while state.clients.count > maxEntries {
            guard let victim = state.accessOrder.first else { break }
            guard let client = state.clients[victim] else {
                state.accessOrder.removeFirst()
                continue
            }
            if !client.canEvict {
                state.accessOrder.removeFirst()
                state.accessOrder.append(victim)
                if !state.clients.values.contains(where: { $0.canEvict }) { break }
                continue
            }
            state.accessOrder.removeFirst()
            state.clients.removeValue(forKey: victim)
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
    private final class Reclaimer: TransportPool {
        func reclaim() { SudokuSharedMuxPool.reclaim() }
    }
}

private final class SudokuSharedMuxClient {
    private let configuration: ProxyConfiguration
    private let directDialHost: String
    private let condition = NSCondition()
    private var client: SudokuMuxClient?
    private var creating = false
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

    var isClosed: Bool {
        condition.lock()
        defer { condition.unlock() }
        return client?.isClosed ?? true
    }

    func retainStream() {
        condition.lock()
        activeStreams += 1
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

    func close() {
        condition.lock()
        let old = client
        client = nil
        creating = false
        condition.broadcast()
        condition.unlock()
        old?.close()
    }

    private func getOrCreateMux() throws -> SudokuMuxClient {
        condition.lock()
        while true {
            if let existing = client, !existing.isClosed {
                condition.unlock()
                return existing
            }
            if let stale = client {
                client = nil
                condition.unlock()
                stale.close()
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
            let native = try SudokuNativeClient(configuration: configuration, factory: factory)
            let created = try native.openMux()
            condition.lock()
            client = created
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
        condition.lock()
        if client === mux {
            client = nil
        }
        condition.unlock()
        mux.close()
    }
}
