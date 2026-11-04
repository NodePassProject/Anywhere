//
//  AppIntentSupport.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation
import NetworkExtension

// MARK: - Errors

nonisolated enum AnywhereIntentError: Error, CustomLocalizedStringResourceConvertible {
    case storeNotReady
    case tunnelNotReady
    case noProxySelected
    case proxyNotFound
    case chainUnavailable(String)
    case connectFailed(String)
    case tunnelStopped
    case timedOut
    case subscriptionNotFound
    case refreshFailed(String, String)
    case refreshAllFailed(String)

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .storeNotReady:
            "Anywhere is still loading. Please try again."
        case .tunnelNotReady:
            "The VPN configuration isn't ready. Open Anywhere once to finish setting it up."
        case .noProxySelected:
            "No proxy is selected. Add or select a proxy in Anywhere first."
        case .proxyNotFound:
            "That proxy no longer exists."
        case .chainUnavailable(let name):
            "The chain \(name) can't be used because one of its proxies is missing."
        case .connectFailed(let reason):
            "Anywhere couldn't connect: \(reason)"
        case .tunnelStopped:
            "The VPN stopped before it finished connecting."
        case .timedOut:
            "Anywhere didn't respond in time."
        case .subscriptionNotFound:
            "That subscription no longer exists."
        case .refreshFailed(let name, let reason):
            "Couldn't update \(name): \(reason)"
        case .refreshAllFailed(let details):
            "Couldn't update any subscription: \(details)"
        }
    }
}

// MARK: - Polling

@MainActor
enum IntentPolling {
    static let interval: Duration = .milliseconds(100)

    static func wait(upTo timeout: Duration, until condition: () -> Bool) async -> Bool {
        let deadline = ContinuousClock.now + timeout
        while !condition() {
            guard ContinuousClock.now < deadline else { return false }
            try? await Task.sleep(for: interval, precision: .prompt)
        }
        return true
    }
}

// MARK: - Readiness

extension AppContainer {
    func awaitStoresLoaded() async throws {
        guard await IntentPolling.wait(upTo: .seconds(10), until: { configurationStore.isLoaded }) else {
            throw AnywhereIntentError.storeNotReady
        }
    }

    func awaitTunnelReady() async throws {
        guard await IntentPolling.wait(upTo: .seconds(10), until: { tunnel.isManagerReady }) else {
            throw AnywhereIntentError.tunnelNotReady
        }
    }
}

// MARK: - Tunnel Transitions

extension TunnelController {
    func awaitSettled(timeout: Duration) async {
        _ = await IntentPolling.wait(upTo: timeout, until: { !rawStatus.isTransitioning })
    }

    func awaitConnected(timeout: Duration) async throws {
        let deadline = ContinuousClock.now + timeout
        var sawConnecting = false
        while ContinuousClock.now < deadline {
            if let error = startError {
                throw AnywhereIntentError.connectFailed(error)
            }
            switch rawStatus {
            case .connected:
                return
            case .connecting, .reasserting:
                sawConnecting = true
            case .disconnected, .invalid:
                if sawConnecting { throw AnywhereIntentError.tunnelStopped }
            case .disconnecting:
                break
            @unknown default:
                break
            }
            try? await Task.sleep(for: IntentPolling.interval, precision: .prompt)
        }
        throw AnywhereIntentError.timedOut
    }

    func awaitDisconnected(timeout: Duration) async throws {
        let done = await IntentPolling.wait(upTo: timeout) {
            rawStatus == .disconnected || rawStatus == .invalid
        }
        guard done else { throw AnywhereIntentError.timedOut }
    }
}
