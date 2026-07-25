//
//  PathMonitorConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Network
import NetworkExtension
import Synchronization

nonisolated final class PathMonitorConcurrencyBridge: Sendable {

    private let queue: DispatchQueue

    init() {
        self.queue = DispatchQueue(label: "com.argsment.Anywhere.PathMonitorConcurrencyBridge")
    }
    
    func paths() -> AsyncStream<Network.NWPath> {
        let queue = self.queue
        return AsyncStream(Network.NWPath.self, bufferingPolicy: .unbounded) { continuation in
            let monitor = NWPathMonitor()
            let previous = Mutex<Network.NWPath?>(nil)
            monitor.pathUpdateHandler = { path in
                let changed = previous.withLock { stored in
                    guard stored != path else { return false }
                    stored = path
                    return true
                }
                guard changed else { return }
                continuation.yield(path)
            }
            continuation.onTermination = { _ in monitor.cancel() }
            monitor.start(queue: queue)
        }
    }

#if os(iOS)
    func currentWiFiSSID() async -> String? {
        await withCheckedContinuation { continuation in
            NEHotspotNetwork.fetchCurrent { network in
                continuation.resume(returning: network?.ssid)
            }
        }
    }
#endif
}
