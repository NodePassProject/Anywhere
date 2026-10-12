//
//  TunnelConstants.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

nonisolated enum TunnelConstants {

    // MARK: - Connection Timeouts
    
    static let connectionIdleTimeout: TimeInterval = 300
    static let drainBeforeCloseTimeout: TimeInterval = 5
    static let handshakeTimeout: TimeInterval = 10
    static let sniffDeadline: TimeInterval = 0.5
    static let pressureIdleTimeout: TimeInterval = 10

    // MARK: - TCP Buffer Sizes
    
    static let tcpGlobalBufferBudget = 16 * 1024 * 1024
    static let tcpWindowSize = 64 * 1460
    static let tcpMaximumWindow = 768 * 1024
    static let tcpMaximumSendBuffer = 512 * 1024
    static let tcpBufferGrowthBudget = 6 * 1024 * 1024
    static let tcpAcknowledgmentDelay: Duration = .milliseconds(5)

    // MARK: - UDP Settings
    
    static let udpGlobalBufferBudget = 16 * 1024 * 1024
    static let udpPendingResolutionMaxBytes = 32 * 1024
    static let udpIdleTimeoutUnreplied: TimeInterval = 30
    static let udpIdleTimeoutStream: TimeInterval = 120
    static let udpStreamMinReplies = 4
    static let udpIntakeBacklog = 256

    // MARK: - Log Buffer

    static let logRetentionInterval: CFAbsoluteTime = 300
    static let logMaxEntries = 50
    static let recentTunnelInterruptionWindow: CFAbsoluteTime = 8

    // MARK: - Request Log
    
    static let requestLogRetentionInterval: CFAbsoluteTime = 300
    static let requestLogMaxEntries = 50

    // MARK: - Activity Pool

    static let tcpActivityPoolCapacity = TunnelLimits.tcpMaxConnections + 64
    static let udpActivityPoolCapacity = TunnelLimits.udpMaxFlows + 64

    // MARK: - Timer Intervals

    static let udpCleanupCoalescingSec = 1

    // MARK: - Stack Lifecycle
    
    static let restartThrottleInterval: CFAbsoluteTime = 2.0

    // MARK: - TLS Sniffer
    
    static let tlsSnifferBufferLimit = 8192

    // MARK: - HTTP Sniffer
    
    static let httpSnifferBufferLimit = 64 * 1024

    // MARK: - Fake-IP Pool
    
    static let fakeIPPoolBaseIPv4: UInt32 = 0xC612_0000
    static let fakeIPPoolSize = 16_384

    // MARK: - Synthesized DNS answers
    
    static let dnsFakeIPAnswerTTL: UInt32 = 300
    static let dnsBlockedAnswerTTL: UInt32 = 10
}
