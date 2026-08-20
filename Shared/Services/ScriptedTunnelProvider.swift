//
//  ScriptedTunnelProvider.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

#if DEBUG
import Foundation
import NetworkExtension

@MainActor
final class ScriptedTunnelProvider: TunnelProviding {
    private(set) var status: NEVPNStatus
    private var continuations: [UUID: AsyncStream<NEVPNStatus>.Continuation] = [:]
    
    var onMessage: ((Data) -> Data?)?
    
    private(set) var startRequests: [TunnelStartRequest] = []
    private(set) var stopCount = 0

    init(initialStatus: NEVPNStatus = .disconnected) {
        status = initialStatus
    }

    func prepare() async {}

    func statusUpdates() -> AsyncStream<NEVPNStatus> {
        AsyncStream { continuation in
            let id = UUID()
            continuations[id] = continuation
            continuation.onTermination = { _ in
                Task { @MainActor in
                    self.continuations[id] = nil
                }
            }
        }
    }

    func start(_ request: TunnelStartRequest) async throws {
        startRequests.append(request)
        send(status: .connecting)
        send(status: .connected)
    }

    func stop(disablingAlwaysOn: Bool) async {
        stopCount += 1
        send(status: .disconnecting)
        send(status: .disconnected)
    }

    func send(_ data: Data) async -> Data? {
        onMessage?(data)
    }
    
    func send(status: NEVPNStatus) {
        self.status = status
        for continuation in continuations.values {
            continuation.yield(status)
        }
    }
}

extension AppContainer {
    static func preview(tunnel: ScriptedTunnelProvider = ScriptedTunnelProvider()) -> AppContainer {
        let container = AppContainer(syncStore: .ephemeral(), tunnelProvider: tunnel)
        container.start()
        return container
    }
}
#endif
