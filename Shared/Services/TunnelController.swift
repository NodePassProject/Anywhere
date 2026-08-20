//
//  TunnelController.swift
//  Anywhere
//
//  Created by NodePassProject on 8/3/26.
//

import Foundation
import NetworkExtension
import Observation

nonisolated private let logger = AnywhereLogger(category: "TunnelController")

@MainActor
@Observable
final class TunnelController {
    private(set) var rawStatus: NEVPNStatus = .disconnected
    var status: VPNStatus { VPNStatus(rawStatus) }
    private(set) var isManagerReady = false
    var startError: String?
    private(set) var pendingReconnect = false

    @ObservationIgnored private let provider: TunnelProviding
    @ObservationIgnored private var statusObserver: Task<Void, Never>?
    @ObservationIgnored private var reassertingDebounceTask: Task<Void, Never>?
    private static let reassertingDebounceInterval: Duration = .seconds(5)

    init(provider: TunnelProviding) {
        self.provider = provider
    }

    deinit {
        statusObserver?.cancel()
        reassertingDebounceTask?.cancel()
    }

    func start() {
        guard statusObserver == nil else { return }
        statusObserver = Task { [weak self, provider] in
            await provider.prepare()
            if let self {
                self.rawStatus = provider.status
                self.isManagerReady = true
            }
            for await status in provider.statusUpdates() {
                guard !Task.isCancelled, let self else { return }
                self.handleStatusChange(status)
            }
        }
    }

    // MARK: - Actions

    func connect(using configuration: ProxyConfiguration) {
        guard isManagerReady else { return }
        Task {
            let resolved = await Self.withResolvedIP(configuration)

            if let configData = try? JSONEncoder().encode(resolved) {
                AWCore.setLastConfigurationData(configData)
            }

            do {
                let messageData = try JSONEncoder().encode(TunnelMessage.setConfiguration(resolved))
                var request = TunnelStartRequest(startMessage: messageData)
                #if !os(tvOS)
                request.includeAllNetworks = AWCore.getTunnelIncludeAllNetworks()
                request.excludeLocalNetworks = AWCore.getTunnelExcludeLocalNetworks()
                request.excludeAPNs = AWCore.getTunnelExcludeAPNs()
                request.excludeCellularServices = AWCore.getTunnelExcludeCellularServices()
                #endif
                request.alwaysOn = AWCore.getAlwaysOnEnabled()
                try await provider.start(request)
            } catch {
                self.startError = error.localizedDescription
            }
        }
    }

    func disconnect() {
        pendingReconnect = false
        Task { await provider.stop(disablingAlwaysOn: true) }
    }
    
    func reconnect() {
        guard rawStatus == .connected || rawStatus == .connecting else { return }
        pendingReconnect = true
        Task { await provider.stop(disablingAlwaysOn: true) }
    }
    
    func consumePendingReconnect() -> Bool {
        guard pendingReconnect else { return false }
        pendingReconnect = false
        return true
    }

    // MARK: - Provider IPC

    func pushConfiguration(_ configuration: ProxyConfiguration) {
        guard rawStatus == .connected else { return }
        Task {
            let resolved = await Self.withResolvedIP(configuration)

            if let configData = try? JSONEncoder().encode(resolved) {
                AWCore.setLastConfigurationData(configData)
            }

            guard let data = try? JSONEncoder().encode(TunnelMessage.setConfiguration(resolved)) else { return }
            _ = await provider.send(data)
        }
    }

    func send(_ message: TunnelMessage) async -> Data? {
        guard let data = try? JSONEncoder().encode(message) else { return nil }
        return await provider.send(data)
    }

    func sendRaw(_ data: Data) async -> Data? {
        await provider.send(data)
    }

    // MARK: - Status Pipeline

    private func handleStatusChange(_ status: NEVPNStatus) {
        reassertingDebounceTask?.cancel()
        reassertingDebounceTask = nil

        if status == .reasserting, rawStatus == .connected {
            reassertingDebounceTask = Task { [weak self] in
                try? await Task.sleep(for: Self.reassertingDebounceInterval)
                guard !Task.isCancelled, let self else { return }
                // Re-check the live status: apply only if it never recovered.
                guard self.provider.status == .reasserting else { return }
                self.rawStatus = .reasserting
            }
            return
        }

        rawStatus = status
    }

    // MARK: - DNS

    nonisolated static func withResolvedIP(
        _ configuration: ProxyConfiguration,
        fallback: String? = nil
    ) async -> ProxyConfiguration {
        if configuration.resolvedIP != nil { return configuration }
        let resolvedIP: String?
        if let fallback {
            resolvedIP = fallback
        } else {
            resolvedIP = await DNSResolver.shared.resolveHost(configuration.serverAddress)
        }
        guard let resolved = resolvedIP else {
            return configuration
        }
        return ProxyConfiguration(
            id: configuration.id,
            name: configuration.name,
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            resolvedIP: resolved,
            subscriptionId: configuration.subscriptionId,
            outbound: configuration.outbound,
            chain: configuration.chain
        )
    }
}

extension TunnelController: LatencyTransport {
    var isTunnelActive: Bool { rawStatus == .connected }
}

#if DEBUG
extension TunnelController {
    func setStatusForPreview(_ status: NEVPNStatus) {
        rawStatus = status
    }
}
#endif

extension NEVPNStatus {
    var isTransitioning: Bool {
        self == .connecting || self == .disconnecting || self == .reasserting
    }
}

extension VPNStatus {
    init(_ status: NEVPNStatus) {
        switch status {
        case .invalid: self = .invalid
        case .disconnected: self = .disconnected
        case .connecting: self = .connecting
        case .connected: self = .connected
        case .reasserting: self = .reasserting
        case .disconnecting: self = .disconnecting
        @unknown default: self = .invalid
        }
    }
}
