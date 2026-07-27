//
//  QUICDatagramCarrier+Compatibility.swift
//  Anywhere
//
//  Created by NodePassProject on 7/27/26.
//

import Foundation
import Network
import Synchronization

nonisolated private final class TerminationLatch: Sendable {
    private let terminated = Atomic<Bool>(false)
    
    @discardableResult
    func trip() -> Bool { !terminated.exchange(true, ordering: .relaxed) }

    var isTripped: Bool { terminated.load(ordering: .relaxed) }
}

nonisolated final class LegacyQUICDatagramEngine: QUICDatagramEngine, Sendable {
    private static let receiveConcurrency = 16

    private let connection: NWConnection
    private let obfuscator: QUICPacketObfuscator?
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.QUICDatagramCarrier", qos: .userInitiated)

    private let terminated = TerminationLatch()

    init(endpoint: NWEndpoint, obfuscator: QUICPacketObfuscator?, sink: QUICDatagramEngineSink) {
        let connection = NWConnection(to: endpoint, using: .udp)
        self.connection = connection
        self.obfuscator = obfuscator

        connection.stateUpdateHandler = { [weak connection] state in
            switch state {
            case .ready:
                sink.ready(interfaceType: connection?.currentPath?.availableInterfaces.first?.type)
            case .failed(let error):
                sink.failed(AnywhereError.errnoCode(from: error))
            case .waiting(let error):
                sink.waiting(AnywhereError.errnoCode(from: error))
            default:
                break
            }
        }
        connection.viabilityUpdateHandler = { viable in
            guard !viable else { return }
            sink.viabilityLost()
        }
        connection.betterPathUpdateHandler = { better in
            guard better else { return }
            sink.betterPath()
        }
        connection.pathUpdateHandler = { path in
            sink.pathChanged(interfaceType: path.availableInterfaces.first?.type)
        }

        connection.start(queue: queue)
        for _ in 0..<Self.receiveConcurrency {
            Self.armReceive(on: connection, obfuscator: obfuscator, sink: sink, terminated: terminated)
        }
    }

    deinit {
        connection.cancel()
    }

    func send(_ datagram: Data) {
        if let obfuscator {
            let wireDatagrams = datagram.withUnsafeBytes { obfuscator.seal($0) }
            for wire in wireDatagrams {
                connection.send(content: wire, completion: .contentProcessed { _ in })
            }
        } else {
            connection.send(content: datagram, completion: .contentProcessed { _ in })
        }
    }

    func close() {
        terminated.trip()
        connection.cancel()
    }
    
    private static func armReceive(
        on connection: NWConnection,
        obfuscator: QUICPacketObfuscator?,
        sink: QUICDatagramEngineSink,
        terminated: TerminationLatch
    ) {
        connection.receiveMessage { content, _, _, error in
            if let error {
                if terminated.trip() {
                    sink.failed(AnywhereError.errnoCode(from: error))
                    sink.finished()
                }
                return
            }
            if let content, !content.isEmpty {
                if let obfuscator {
                    if let opened = obfuscator.open(content) {
                        sink.packet(opened)
                    }
                } else {
                    sink.packet(content)
                }
            }
            guard !terminated.isTripped else { return }
            Self.armReceive(on: connection, obfuscator: obfuscator, sink: sink, terminated: terminated)
        }
    }
}
