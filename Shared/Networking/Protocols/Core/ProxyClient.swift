//
//  ProxyClient.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import Synchronization

nonisolated final class ProxyClient: Sendable {
    let configuration: ProxyConfiguration
    let useResolvedAddressForDirectDial: Bool

    private enum Phase: PhaseTransitionable {
        case idle
        case delivered(ProxyConnection)
        case cancelled

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .delivered),
                 (.idle, .cancelled),
                 (.delivered, .cancelled):
                return true
            default:
                return false
            }
        }
    }

    private struct State: PhaseHolding {
        var phase: Phase = .idle
        var tunnel: ProxyConnection?
    }

    private let state: Mutex<State>

    var tunnel: ProxyConnection? { state.withLock { $0.tunnel } }

    func setChainTunnel(_ tunnel: ProxyConnection?) {
        state.withLock { $0.tunnel = tunnel }
    }
    
    func takeChainTunnel() -> ProxyConnection? {
        state.withLock { state in
            let tunnel = state.tunnel
            state.tunnel = nil
            return tunnel
        }
    }
    let parentChain: [ProxyConfiguration]

    let isDefaultProxy: Bool

    var directDialHost: String {
        useResolvedAddressForDirectDial ? configuration.connectAddress : configuration.serverAddress
    }

    var isCancelled: Bool {
        state.withLock { if case .cancelled = $0.phase { true } else { false } }
    }

    init(
        configuration: ProxyConfiguration,
        tunnel: ProxyConnection? = nil,
        useResolvedAddressForDirectDial: Bool = false,
        parentChain: [ProxyConfiguration] = [],
        isDefaultProxy: Bool = false
    ) {
        self.configuration = configuration
        self.state = Mutex(State(tunnel: tunnel))
        self.useResolvedAddressForDirectDial = useResolvedAddressForDirectDial
        self.parentChain = parentChain
        self.isDefaultProxy = isDefaultProxy
    }

    // MARK: - Delivery / teardown

    private func deliver(_ dial: () async throws -> ProxyConnection) async throws -> ProxyConnection {
        let connection = try await dial()
        enum Publication { case published, cancelled, alreadyDelivered }
        let publication: Publication = state.withLock { s in
            switch s.phase {
            case .idle:
                s.transition(to: .delivered(connection))
                return .published
            case .delivered:
                return .alreadyDelivered
            case .cancelled:
                return .cancelled
            }
        }
        switch publication {
        case .published:
            return connection
        case .cancelled:
            connection.cancel()
            throw AnywhereError.transport(.terminated)
        case .alreadyDelivered:
            connection.cancel()
            throw AnywhereError.transport(.connectionFailed(
                endpoint: configuration.serverAddress,
                detail: "proxy client already delivered a connection"
            ))
        }
    }

    // MARK: - Public API

    private func withOutboundMetrics(
        _ dial: () async throws -> ProxyConnection
    ) async throws -> ProxyConnection {
        guard isDefaultProxy, let attempt = ConnectionMetrics.shared.beginAttempt() else {
            return try await dial()
        }
        let connection = try await ConnectionMetrics.$currentAttempt.withValue(attempt) {
            try await dial()
        }
        return MeteredProxyConnection(connection, attempt: attempt)
    }

    func connect(
        to destinationHost: String,
        port destinationPort: UInt16,
        initialData: Data? = nil
    ) async throws -> ProxyConnection {
        try await dial(.tcp(destinationHost, port: destinationPort, initialData: initialData))
    }

    func connectUDP(
        to destinationHost: String,
        port destinationPort: UInt16
    ) async throws -> ProxyConnection {
        try await dial(.udp(destinationHost, port: destinationPort))
    }
    
    func dial(_ request: ProxyRequest) async throws -> ProxyConnection {
        try await withOutboundMetrics {
            try await self.deliver {
                try await self.connectThroughChainIfNeeded(request)
            }
        }
    }

    private func connectThroughChainIfNeeded(_ request: ProxyRequest) async throws -> ProxyConnection {
        guard let chain = configuration.chain, !chain.isEmpty, tunnel == nil else {
            return try await connectWithOutbound(request)
        }
        
        if configuration.isQUICTransport {
            return try await connectWithOutbound(request)
        }

        guard let lastDeliver = configuration.upstreamNetwork(for: request.network) else {
            throw AnywhereError.proxy(configuration.outboundProtocol.wire, .protocolViolation(
                detail: "\(configuration.outboundProtocol.name) doesn't support \(request.network)"
            ))
        }

        let hopNetworks = try Self.computeChainHopNetworks(chain: chain, lastDeliver: lastDeliver).get()

        let chainTunnel = try await buildChainTunnel(
            chain: chain, index: 0, currentTunnel: nil, hopNetworks: hopNetworks
        )
        let installed: Bool = state.withLock { s in
            if case .cancelled = s.phase { return false }
            s.tunnel = chainTunnel
            return true
        }
        guard installed else {
            chainTunnel.cancel()
            throw AnywhereError.transport(.terminated)
        }
        return try await connectWithOutbound(request)
    }

    static func computeChainHopNetworks(
        chain: [ProxyConfiguration],
        outerProtocol: OutboundProtocol,
        outerNetwork: ProxyNetwork
    ) -> Result<[ProxyNetwork], Error> {
        guard !chain.isEmpty else { return .success([]) }

        guard let lastDeliver = outerProtocol.upstreamNetwork(for: outerNetwork) else {
            return .failure(AnywhereError.proxy(outerProtocol.wire, .protocolViolation(
                detail: "\(outerProtocol.name) doesn't support \(outerNetwork)"
            )))
        }

        return computeChainHopNetworks(chain: chain, lastDeliver: lastDeliver)
    }
    
    static func computeChainHopNetworks(
        chain: [ProxyConfiguration],
        lastDeliver: ProxyNetwork
    ) -> Result<[ProxyNetwork], Error> {
        guard !chain.isEmpty else { return .success([]) }

        var networks = [ProxyNetwork](repeating: .tcp, count: chain.count)
        networks[chain.count - 1] = lastDeliver

        if chain.count > 1 {
            for i in stride(from: chain.count - 2, through: 0, by: -1) {
                let nextHop = chain[i + 1]
                let downstream = networks[i + 1]
                guard let upstream = nextHop.upstreamNetwork(for: downstream) else {
                    return .failure(AnywhereError.proxy(nextHop.outboundProtocol.wire, .protocolViolation(
                        detail: "Chain hop \(nextHop.outboundProtocol.name) doesn't support \(downstream) downstream — needed by the hop above it"
                    )))
                }
                networks[i] = upstream
            }
        }
        return .success(networks)
    }

    @discardableResult
    func buildChainTunnel(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        hopNetworks: [ProxyNetwork],
        finalDestination: (host: String, port: UInt16)? = nil,
        track: ((ProxyClient) -> Void)? = nil
    ) async throws -> ProxyConnection {
        let resolvedDestination: (host: String, port: UInt16)
        if let finalDestination {
            resolvedDestination = finalDestination
        } else {
            resolvedDestination = (configuration.serverAddress, configuration.serverPort)
        }
        let resolvedTrack: (ProxyClient) -> Void = track ?? { _ in }
        return try await Self.dialChain(
            chain: chain,
            index: index,
            currentTunnel: currentTunnel,
            hopNetworks: hopNetworks,
            finalDestination: resolvedDestination,
            useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
            track: resolvedTrack
        )
    }

    static func buildDetachedChainTunnel(
        chain: [ProxyConfiguration],
        hopNetworks: [ProxyNetwork],
        finalDestination: (host: String, port: UInt16),
        useResolvedAddressForDirectDial: Bool,
        track: @escaping (ProxyClient) -> Void
    ) async throws -> ProxyConnection {
        try await dialChain(
            chain: chain,
            index: 0,
            currentTunnel: nil,
            hopNetworks: hopNetworks,
            finalDestination: finalDestination,
            useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
            track: track
        )
    }

    private static func dialChain(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        hopNetworks: [ProxyNetwork],
        finalDestination: (host: String, port: UInt16),
        useResolvedAddressForDirectDial: Bool,
        track: @escaping (ProxyClient) -> Void
    ) async throws -> ProxyConnection {
        var currentTunnel = currentTunnel
        do {
            for hopIndex in index..<chain.count {
                let isLastHop = (hopIndex + 1 == chain.count)
                let nextHost: String
                let nextPort: UInt16
                if !isLastHop {
                    let nextConfiguration = chain[hopIndex + 1]
                    nextHost = nextConfiguration.serverAddress
                    nextPort = nextConfiguration.serverPort
                } else {
                    nextHost = finalDestination.host
                    nextPort = finalDestination.port
                }

                let chainClient = ProxyClient(
                    configuration: chain[hopIndex],
                    tunnel: currentTunnel,
                    useResolvedAddressForDirectDial: useResolvedAddressForDirectDial,
                    parentChain: Array(chain[0..<hopIndex])
                )
                track(chainClient)

                switch hopNetworks[hopIndex] {
                case .tcp:
                    currentTunnel = try await chainClient.connect(to: nextHost, port: nextPort)
                case .udp:
                    currentTunnel = try await chainClient.connectUDP(to: nextHost, port: nextPort)
                }
            }
        } catch {
            currentTunnel?.cancel()
            throw error
        }
        guard let tunnel = currentTunnel else {
            throw AnywhereError.transport(.connectionFailed(endpoint: nil, detail: "Empty proxy chain"))
        }
        return tunnel
    }

    func cancel() {
        tearDown()
    }

    func cancel() async {
        tearDown()
    }

    private func tearDown() {
        let (delivered, tunnel) = state.withLock { s -> (ProxyConnection?, ProxyConnection?) in
            let delivered: ProxyConnection? = if case .delivered(let connection) = s.phase {
                connection
            } else {
                nil
            }
            s.transition(to: .cancelled)
            let pair = (delivered, s.tunnel)
            s.tunnel = nil
            return pair
        }
        delivered?.cancel()
        tunnel?.cancel()
    }

    // MARK: - Connection Routing

    private func connectWithOutbound(_ request: ProxyRequest) async throws -> ProxyConnection {
        switch configuration.outboundProtocol {
        case .nowhere:
            return try await connectWithNowhere(request)
        case .vless:
            return try await connectWithVLESS(request)
        case .hysteria:
            return try await connectWithHysteria(request)
        case .sudoku:
            return try await connectWithSudoku(request)
        case .trojan:
            return try await connectWithTrojan(request)
        case .anytls:
            return try await connectWithAnyTLS(request)
        case .socks5:
            return try await connectWithSOCKS5(request)
        case .rfc:
            return try await connectWithRFC(request)
        case .shadowsocks:
            return try await connectWithShadowsocks(request)
        }
    }
    
    func dialServerTransport() async throws -> TCPTransport {
        let transport = TCPTransport(host: directDialHost, port: configuration.serverPort, resolution: .proxies)
        try await transport.connect()
        return transport
    }
    
    func dialDirectProxyConnection() async throws -> ProxyConnection {
        if let tunnel = self.tunnel {
            return DirectProxyConnection(transport: TunneledTransport(tunnel: tunnel))
        }
        return DirectProxyConnection(transport: try await dialServerTransport())
    }
    
    func connectTLSRecord(_ tlsClient: TLSClient) async throws -> TLSRecordConnection {
        if let tunnel = self.tunnel {
            return try await tlsClient.connect(overTunnel: tunnel)
        } else {
            return try await tlsClient.connect(host: self.directDialHost, port: self.configuration.serverPort)
        }
    }
}

// MARK: - Wire Mapping

nonisolated extension OutboundProtocol {
    var wire: AnywhereError.Wire {
        switch self {
        case .nowhere: .nowhere
        case .vless: .vless
        case .hysteria: .hysteria
        case .sudoku: .sudoku
        case .trojan: .trojan
        case .anytls: .anyTLS
        case .shadowsocks: .shadowsocks
        case .socks5: .socks5
        case .rfc: .rfc
        }
    }
}
