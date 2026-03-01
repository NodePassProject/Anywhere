//
//  MuxManager.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

class MuxManager {
    let configuration: VLESSConfiguration
    let lwipQueue: DispatchQueue
    private var clients: [MuxClient] = []

    init(configuration: VLESSConfiguration, lwipQueue: DispatchQueue) {
        self.configuration = configuration
        self.lwipQueue = lwipQueue
    }

    /// Dispatches a new session to a non-full MuxClient, creating one if needed.
    func dispatch(
        network: MuxNetwork,
        host: String,
        port: UInt16,
        globalID: Data?,
        completion: @escaping (Result<MuxSession, Error>) -> Void
    ) {
        // Remove dead clients
        clients.removeAll { $0.closed }

        // Find a non-full client
        if let client = clients.first(where: { !$0.isFull }) {
            client.createSession(network: network, host: host, port: port, globalID: globalID, completion: completion)
            return
        }

        // Create a new client
        let client = MuxClient(configuration: configuration, lwipQueue: lwipQueue)
        clients.append(client)

        client.createSession(network: network, host: host, port: port, globalID: globalID, completion: completion)
    }

    /// Closes all clients and their sessions.
    func closeAll() {
        for client in clients {
            client.closeAll()
        }
        clients.removeAll()
    }
}
