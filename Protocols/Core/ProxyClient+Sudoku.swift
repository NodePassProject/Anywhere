//
//  ProxyClient+Sudoku.swift
//  Anywhere
//
//  Copyright (C) 2026 by saba <contact me via issue>. GPLv3.
//  Created by saba on 4/23/26.
//

import Foundation

private func sudokuCString<T>(_ value: inout T) -> String {
    withUnsafePointer(to: &value) { pointer in
        pointer.withMemoryRebound(to: CChar.self, capacity: MemoryLayout<T>.size) { chars in
            String(cString: chars)
        }
    }
}

extension ProxyClient {
    func connectWithSudoku(
        command: ProxyCommand,
        destinationHost: String,
        destinationPort: UInt16,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        let chainConnector = SudokuChainConnector(configuration: configuration, initialTunnel: tunnel)

        let bridgedConfig: SudokuOutboundConfigBridge
        do {
            bridgedConfig = try SudokuOutboundConfigBridge(
                configuration: configuration,
                serverHost: directDialHost,
                socketFactoryContext: chainConnector?.contextPointer()
            )
        } catch {
            completion(.failure(error))
            return
        }

        switch command {
        case .tcp:
            connectSudokuTCP(
                config: bridgedConfig.raw,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                chainConnector: chainConnector,
                completion: completion
            )
        case .udp:
            connectSudokuUDP(
                config: bridgedConfig.raw,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                chainConnector: chainConnector,
                completion: completion
            )
        case .mux:
            completion(.failure(ProxyError.protocolError("Sudoku does not use the host mux manager")))
        }
    }

    private func connectSudokuTCP(
        config: sudoku_outbound_config_t,
        destinationHost: String,
        destinationPort: UInt16,
        chainConnector: SudokuChainConnector?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            var cfg = config
            if cfg.httpmask_disable == 0,
               sudokuCString(&cfg.httpmask_multiplex) == SudokuHTTPMaskMultiplex.on.rawValue,
               ["stream", "poll", "auto", "ws"].contains(sudokuCString(&cfg.httpmask_mode)) {
                var muxHandle: sudoku_mux_handle_t?
                var streamHandle: sudoku_mux_stream_handle_t?
                let openResult = sudoku_swift_mux_client_open(&cfg, &muxHandle)
                if openResult != 0 || muxHandle == nil {
                    chainConnector?.closeAll()
                    completion(.failure(ProxyError.connectionFailed("Sudoku mux connect failed")))
                    return
                }
                let dialResult = destinationHost.withCString { host in
                    sudoku_swift_mux_dial_tcp(muxHandle!, host, destinationPort, &streamHandle)
                }
                if dialResult != 0 || streamHandle == nil {
                    sudoku_swift_mux_client_close(muxHandle!)
                    chainConnector?.closeAll()
                    completion(.failure(ProxyError.connectionFailed("Sudoku mux TCP dial failed")))
                    return
                }
                completion(.success(SudokuMuxTCPProxyConnection(
                    muxHandle: muxHandle!,
                    streamHandle: streamHandle!,
                    chainConnector: chainConnector
                )))
                return
            }

            var handle: sudoku_tcp_handle_t?
            let result = destinationHost.withCString { host in
                sudoku_swift_client_connect_tcp(&cfg, host, destinationPort, &handle)
            }
            if result != 0 || handle == nil {
                chainConnector?.closeAll()
                completion(.failure(ProxyError.connectionFailed("Sudoku TCP connect failed")))
                return
            }
            completion(.success(SudokuTCPProxyConnection(handle: handle!, chainConnector: chainConnector)))
        }
    }

    private func connectSudokuUDP(
        config: sudoku_outbound_config_t,
        destinationHost: String,
        destinationPort: UInt16,
        chainConnector: SudokuChainConnector?,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            var cfg = config
            var handle: sudoku_uot_handle_t?
            let result = sudoku_swift_client_connect_uot(&cfg, &handle)
            if result != 0 || handle == nil {
                chainConnector?.closeAll()
                completion(.failure(ProxyError.connectionFailed("Sudoku UDP connect failed")))
                return
            }
            completion(.success(SudokuUDPProxyConnection(
                handle: handle!,
                destinationHost: destinationHost,
                destinationPort: destinationPort,
                chainConnector: chainConnector
            )))
        }
    }
}
