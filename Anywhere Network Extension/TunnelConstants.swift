//
//  TunnelConstants.swift
//  Anywhere Network Extension
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation

enum TunnelConstants {

    // MARK: - Tunnel Network Settings

    /// Remote address for the TUN interface.
    static let tunnelRemoteAddress = "10.8.0.1"
    /// Local IPv4 address assigned to the TUN interface.
    static let tunnelLocalIPv4Address = "10.8.0.2"
    /// Subnet mask for the TUN IPv4 address.
    static let tunnelSubnetMask = "255.255.255.0"
    /// Local IPv6 address assigned to the TUN interface (when IPv6 is enabled).
    static let tunnelLocalIPv6Address = "fd00::2"
    /// Prefix length for the TUN IPv6 address.
    static let tunnelIPv6PrefixLength: NSNumber = 64
    /// Maximum transmission unit for the TUN interface.
    static let tunnelMTU: NSNumber = 1400

    // MARK: - DNS Servers

    /// IPv4 DNS servers (Cloudflare).
    static let dnsServersIPv4 = ["1.1.1.1", "1.0.0.1"]
    /// IPv6 DNS servers (Cloudflare).
    static let dnsServersIPv6 = ["2606:4700:4700::1111", "2606:4700:4700::1001"]
    /// Default encrypted DNS protocol when no preference is stored.
    static let defaultEncryptedDNSProtocol = "doh"

    // MARK: - Connection Timeouts

    /// Inactivity timeout for TCP connections (Xray-core `connIdle`, default 300s).
    static let connectionIdleTimeout: TimeInterval = 300
    /// Timeout after uplink (local → remote) finishes (Xray-core `downlinkOnly`, default 1s).
    static let downlinkOnlyTimeout: TimeInterval = 1
    /// Timeout after downlink (remote → local) finishes (Xray-core `uplinkOnly`, default 1s).
    static let uplinkOnlyTimeout: TimeInterval = 1
    /// Handshake timeout matching Xray-core's `Timeout.Handshake` (60 seconds).
    /// Bounds the entire connection setup phase (TCP + TLS + WS/HTTPUpgrade + VLESS header).
    static let handshakeTimeout: TimeInterval = 60

    // MARK: - TCP Buffer Sizes

    /// Maximum bytes per tcp_write call (16 KB ≈ 12 TCP segments at TCP_MSS=1360).
    /// With MEMP_NUM_TCP_SEG=4096, this lets many connections make progress without
    /// exhausting the segment pool. Must stay in sync with lwipopts.h.
    static let tcpMaxWriteSize = 16 * 1024
    /// Maximum upload coalesce buffer size, capped at UInt16.max because downstream
    /// protocols (Vision padding) use 2-byte content length fields.
    static let tcpMaxCoalesceSize = Int(UInt16.max)

    // MARK: - UDP Settings

    /// Maximum buffer size for queued UDP datagrams.
    static let udpMaxBufferSize = 16 * 1024
    /// Idle timeout for UDP flows (seconds).
    static let udpIdleTimeout: CFAbsoluteTime = 60

    // MARK: - Log Buffer

    /// Retention interval for log entries (seconds).
    static let logRetentionInterval: CFAbsoluteTime = 300
    /// Maximum number of log entries in the buffer.
    static let logMaxEntries = 50
    /// Time window (seconds) to attribute connection errors to a recent tunnel interruption.
    static let recentTunnelInterruptionWindow: CFAbsoluteTime = 8

    // MARK: - Timer Intervals

    /// lwIP periodic timeout interval (milliseconds).
    static let lwipTimeoutIntervalMs = 250
    /// UDP flow cleanup timer interval (seconds).
    static let udpCleanupIntervalSec = 1
    /// Retry delay when TCP overflow drain makes no progress (milliseconds).
    static let drainRetryDelayMs = 250

    // MARK: - UserDefaults Keys

    enum UserDefaultsKey {
        static let lastConfigurationData = "lastConfigurationData"
        static let ipv6DNSEnabled = "ipv6DNSEnabled"
        static let encryptedDNSEnabled = "encryptedDNSEnabled"
        static let encryptedDNSProtocol = "encryptedDNSProtocol"
        static let encryptedDNSServer = "encryptedDNSServer"
        static let bypassCountryCode = "bypassCountryCode"
        static let proxyMode = "proxyMode"
        static let proxyServerAddresses = "proxyServerAddresses"
        static let routingData = "routingData"
        static let bypassCountryDomainRules = "bypassCountryDomainRules"
    }

    // MARK: - Darwin Notification Names

    enum Notification {
        static let settingsChanged = "com.argsment.Anywhere.settingsChanged" as CFString
        static let routingChanged = "com.argsment.Anywhere.routingChanged" as CFString
    }
}
