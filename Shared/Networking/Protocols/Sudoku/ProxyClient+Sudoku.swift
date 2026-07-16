//
//  ProxyClient+Sudoku.swift
//  Anywhere
//
//  Created by saba-futai on 4/23/26.
//

import Foundation

nonisolated private enum SudokuConnectCommand {
    case tcp
    case udp
}

extension ProxyClient {
    func connectWithSudoku(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        let sudokuCommand: SudokuConnectCommand
        switch command {
        case .tcp:
            sudokuCommand = .tcp
        case .udp:
            sudokuCommand = .udp
        case .mux:
            throw ProxyError.protocolError("Sudoku does not use the host mux manager")
        }

        guard case .sudoku(let sudoku) = configuration.outbound else {
            throw ProxyError.protocolError("missing Sudoku protocol settings")
        }

        if case .tcp = sudokuCommand, sudoku.multiplex == .on, tunnel == nil {
            return try await connectWithPooledSudokuMux(
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData
            )
        }

        let configuration = configuration
        let factory = SudokuConnectionFactory(
            configuration: configuration,
            initialTunnel: tunnel,
            directDialHost: directDialHost
        )

        do {
            let client = try SudokuNativeClient(configuration: configuration, factory: factory)
            let connection: ProxyConnection
            switch sudokuCommand {
            case .tcp where client.shouldUseNativeMux:
                let multiplexer = try await client.openMux()
                let stream = try await multiplexer.dialTCP(host: destinationHost, port: destinationPort)
                try await ProxyClient.sendSudokuInitialData(initialData, to: stream)
                connection = SudokuMuxTCPProxyConnection(client: multiplexer, stream: stream)
            case .tcp:
                let stream = try await client.openTCP(host: destinationHost, port: destinationPort)
                try await stream.sendInitialDataIfNeeded(initialData)
                connection = SudokuTCPProxyConnection(stream: stream)
            case .udp:
                let stream = try await client.openUoT()
                connection = SudokuUDPProxyConnection(
                    stream: stream,
                    destinationHost: destinationHost,
                    destinationPort: destinationPort
                )
            }
            return connection
        } catch {
            factory.closeAll()
            throw error
        }
    }

    /// The pooled session outlives this ProxyClient, so nothing here is `own`ed; closing
    /// the connection only closes its stream and re-arms the pool's idle clock.
    private func connectWithPooledSudokuMux(
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?
    ) async throws -> ProxyConnection {
        guard let pool = SudokuMultiplexerRegistry.shared.pool(
            for: configuration,
            directDialHost: directDialHost
        ) else {
            throw ProxyError.connectionFailed("Failed to acquire Sudoku mux pool")
        }

        let (multiplexer, stream) = try await pool.dialTCP(host: destinationHost, port: destinationPort)
        do {
            try await ProxyClient.sendSudokuInitialData(initialData, to: stream)
        } catch {
            stream.close()
            throw error
        }
        return SudokuMuxTCPProxyConnection(
            client: multiplexer,
            stream: stream,
            closesClientOnClose: false,
            onClose: { pool.noteStreamEnded(multiplexer) }
        )
    }

    private static func sendSudokuInitialData(_ data: Data?, to stream: SudokuMuxStream) async throws {
        guard let data, !data.isEmpty else { return }
        try await stream.send(data)
    }
}

private extension SudokuRecordStream {
    func sendInitialDataIfNeeded(_ data: Data?) async throws {
        guard let data, !data.isEmpty else { return }
        try await send(data)
    }
}
