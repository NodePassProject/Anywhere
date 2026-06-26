//
//  AWNotificationCenter.swift
//  Anywhere
//
//  Created by NodePassProject on 6/26/26.
//

import Foundation

actor AWNotificationCenter {
    // MARK: - Darwin Notification Names

    enum Notification {
        static let tunnelSettingsChanged = "\(AWCore.Identifier.bundle).tunnelSettingsChanged" as CFString
        static let routingChanged = "\(AWCore.Identifier.bundle).routingChanged" as CFString
        static let certificatePolicyChanged = "\(AWCore.Identifier.bundle).certificatePolicyChanged" as CFString
        static let mitmChanged = "\(AWCore.Identifier.bundle).mitmChanged" as CFString
    }

    // MARK: - Public API

    static func notifyTunnelSettingsChanged() {
        post(Notification.tunnelSettingsChanged)
    }

    static func notifyRoutingChanged() {
        post(Notification.routingChanged)
    }

    static func notifyCertificatePolicyChanged() {
        post(Notification.certificatePolicyChanged)
    }

    static func notifyMITMChanged() {
        post(Notification.mitmChanged)
    }

    // MARK: - Throttled Posting

    private static let shared = AWNotificationCenter()
    private static let throttleInterval: Duration = .seconds(1)

    private var lastPostTimes: [String: ContinuousClock.Instant] = [:]
    private var pendingTasks: [String: Task<Void, Never>] = [:]

    private static func post(_ name: CFString) {
        let key = name as String
        Task { await shared.schedule(key) }
    }

    private func schedule(_ name: String) {
        pendingTasks[name]?.cancel()
        pendingTasks[name] = nil

        let now = ContinuousClock.now
        if let last = lastPostTimes[name], now - last < Self.throttleInterval {
            // Within the throttle window: coalesce into a single trailing post.
            let delay = Self.throttleInterval - (now - last)
            pendingTasks[name] = Task {
                try? await Task.sleep(for: delay)
                guard !Task.isCancelled else { return }
                self.fire(name)
            }
        } else {
            // Leading edge: enough time has elapsed, post immediately.
            lastPostTimes[name] = now
            Self.emit(name)
        }
    }

    private func fire(_ name: String) {
        lastPostTimes[name] = ContinuousClock.now
        pendingTasks[name] = nil
        Self.emit(name)
    }

    private static func emit(_ name: String) {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(name as CFString),
            nil, nil, true
        )
    }
}
