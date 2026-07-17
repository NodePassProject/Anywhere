//
//  PathMonitorConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Network
import NetworkExtension

nonisolated final class PathMonitorConcurrencyBridge: Sendable {

    private let queue: DispatchQueue

    init() {
        self.queue = DispatchQueue(label: "com.argsment.Anywhere.PathMonitorConcurrencyBridge")
    }

    /// Streams `NWPath` updates in order. The monitor is cancelled when the consuming task is
    /// cancelled (the stream's `onTermination` fires on cooperative cancellation), so the caller
    /// tears the whole thing down just by cancelling its loop task.
    func paths() -> AsyncStream<Network.NWPath> {
        let queue = self.queue
        return AsyncStream(Network.NWPath.self, bufferingPolicy: .unbounded) { continuation in
            let monitor = NWPathMonitor()
            monitor.pathUpdateHandler = { continuation.yield($0) }
            continuation.onTermination = { _ in monitor.cancel() }
            monitor.start(queue: queue)
        }
    }

#if os(iOS)
    /// The current Wi-Fi network's SSID, or `nil` (no Wi-Fi, or the "Access WiFi Information"
    /// entitlement is absent). Bridges `NEHotspotNetwork.fetchCurrent`'s single-shot callback.
    func currentWiFiSSID() async -> String? {
        await withCheckedContinuation { continuation in
            NEHotspotNetwork.fetchCurrent { network in
                continuation.resume(returning: network?.ssid)
            }
        }
    }
#endif
}
