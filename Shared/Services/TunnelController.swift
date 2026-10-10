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
    @ObservationIgnored private var publishQueue: Task<Void, Never>?
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
            await publish(configuration, refreshingIP: true)
            do {
                var request = TunnelStartRequest()
                #if !os(tvOS)
                request.includeAllNetworks = AWCore.getTunnelIncludeAllNetworks()
                request.excludeLocalNetworks = AWCore.getTunnelExcludeLocalNetworks()
                request.excludeAPNs = AWCore.getTunnelExcludeAPNs()
                request.excludeCellularServices = AWCore.getTunnelExcludeCellularServices()
                request.excludeDeviceCommunication = AWCore.getTunnelExcludeDeviceCommunication()
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

    // MARK: - Active Configuration
    
    func publish(_ configuration: ProxyConfiguration?, refreshingIP: Bool = false) async {
        let previous = publishQueue
        let task = Task {
            await previous?.value
            await Self.reconcileActiveConfiguration(configuration, refreshingIP: refreshingIP)
        }
        publishQueue = task
        await task.value
    }

    nonisolated private static func reconcileActiveConfiguration(
        _ configuration: ProxyConfiguration?,
        refreshingIP: Bool
    ) async {
        guard let configuration else {
            guard AWCore.getActiveConfigurationData() != nil else { return }
            try? ActiveConfiguration.store(nil)
            AWNotificationCenter.notifyActiveConfigurationChanged()
            return
        }

        let stored = try? ActiveConfiguration.load()
        if !refreshingIP, let stored,
           stored.withResolvedIP(nil) == configuration.withResolvedIP(nil) {
            return
        }

        let resolvedIP = await DNSResolver.proxies.resolveHost(configuration.serverAddress, forceFresh: refreshingIP)
        let resolved = configuration.withResolvedIP(resolvedIP ?? configuration.resolvedIP)
        do {
            try ActiveConfiguration.store(resolved)
        } catch {
            logger.report("[Tunnel] Active configuration encode failed", error: error)
            return
        }
        AWNotificationCenter.notifyActiveConfigurationChanged()
    }

    // MARK: - Provider IPC

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
