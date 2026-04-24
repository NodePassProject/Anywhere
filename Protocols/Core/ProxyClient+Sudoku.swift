//
//  ProxyClient+Sudoku.swift
//  Anywhere
//
//  Native Swift Sudoku outbound entry points.
//

import Foundation

extension ProxyClient {
    func connectWithSudoku(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
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

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let client = try SudokuNativeClient(configuration: self.configuration, factory: factory)
                let connection: ProxyConnection
                switch command {
                case .tcp:
                    if client.shouldUseNativeMux {
                        let mux = try client.openMux()
                        let stream = try mux.dialTCP(host: destinationHost, port: destinationPort)
                        connection = SudokuMuxTCPProxyConnection(client: mux, stream: stream)
                    } else {
                        let stream = try client.openTCP(host: destinationHost, port: destinationPort)
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
}
