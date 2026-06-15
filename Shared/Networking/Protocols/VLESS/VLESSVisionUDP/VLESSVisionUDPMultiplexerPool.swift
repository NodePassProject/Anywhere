//
//  VLESSVisionUDPMultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated class VLESSVisionUDPMultiplexerPool {
    let configuration: ProxyConfiguration
    let flowQueue: DispatchQueue
    private var multiplexers: [VLESSVisionUDPMultiplexer] = []

    init(configuration: ProxyConfiguration, flowQueue: DispatchQueue) {
        self.configuration = configuration
        self.flowQueue = flowQueue
    }

    /// Dispatches a new stream to a non-full VLESSVisionUDPMultiplexer, creating one if needed.
    func acquireStream(
        network: VLESSVisionUDPNetwork,
        host: String,
        port: UInt16,
        globalID: Data?,
        completion: @escaping (Result<VLESSVisionUDPStream, Error>) -> Void
    ) {
        multiplexers.removeAll { $0.closed }

        if let multiplexer = multiplexers.first(where: { !$0.isFull }) {
            multiplexer.openStream(network: network, host: host, port: port, globalID: globalID, completion: completion)
            return
        }

        let multiplexer = VLESSVisionUDPMultiplexer(configuration: configuration, flowQueue: flowQueue)
        multiplexers.append(multiplexer)

        multiplexer.openStream(network: network, host: host, port: port, globalID: globalID, completion: completion)
    }

    /// Closes all multiplexers and their streams.
    func closeAll() {
        for multiplexer in multiplexers {
            multiplexer.close()
        }
        multiplexers.removeAll()
    }
}
