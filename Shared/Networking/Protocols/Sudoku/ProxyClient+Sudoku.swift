//
//  ProxyClient+Sudoku.swift
//  Anywhere
//
//  Created by saba-futai on 4/23/26.
//

import Foundation

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

        guard case .sudoku(let sudoku) = configuration.outbound else {
            completion(.failure(ProxyError.protocolError("missing Sudoku protocol settings")))
            return
        }
        
        if case .tcp = sudokuCommand, sudoku.multiplex == .on, tunnel == nil {
            connectWithPooledSudokuMux(
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                initialData: initialData,
                completion: completion
            )
            return
        }

        let configuration = configuration
        let factory = SudokuConnectionFactory(
            configuration: configuration,
            initialTunnel: tunnel,
            directDialHost: directDialHost
        )
        own(factory)

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let client = try SudokuNativeClient(configuration: configuration, factory: factory)
                let connection: ProxyConnection
                switch sudokuCommand {
                case .tcp where client.shouldUseNativeMux:
                    let multiplexer = try client.openMux()
                    let stream = try multiplexer.dialTCP(host: destinationHost, port: destinationPort)
                    try ProxyClient.sendSudokuInitialData(initialData, to: stream)
                    connection = SudokuMuxTCPProxyConnection(client: multiplexer, stream: stream)
                case .tcp:
                    let stream = try client.openTCP(host: destinationHost, port: destinationPort)
                    try stream.sendInitialDataIfNeeded(initialData)
                    connection = SudokuTCPProxyConnection(stream: stream)
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

    /// The pooled session outlives this ProxyClient, so nothing here is `own`ed; closing
    /// the connection only closes its stream and re-arms the pool's idle clock.
    private func connectWithPooledSudokuMux(
        destinationHost: String,
        destinationPort: UInt16,
        initialData: Data?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        guard let pool = SudokuMultiplexerRegistry.shared.pool(
            for: configuration,
            directDialHost: directDialHost
        ) else {
            completion(.failure(ProxyError.connectionFailed("Failed to acquire Sudoku mux pool")))
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let (multiplexer, stream) = try pool.dialTCP(host: destinationHost, port: destinationPort)
                do {
                    try ProxyClient.sendSudokuInitialData(initialData, to: stream)
                } catch {
                    stream.close()
                    throw error
                }
                let connection = SudokuMuxTCPProxyConnection(
                    client: multiplexer,
                    stream: stream,
                    closesClientOnClose: false,
                    onClose: { pool.noteStreamEnded(multiplexer) }
                )
                completion(.success(connection))
            } catch {
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
