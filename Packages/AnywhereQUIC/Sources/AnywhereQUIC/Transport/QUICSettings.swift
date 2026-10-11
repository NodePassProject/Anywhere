//
//  QUICSettings.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

public struct QUICSettings: Sendable {
    public static let defaultInitialRTT: Duration = .milliseconds(333)
    public static let defaultMaxSendUDPPayloadSize = 1452
    public static let minimumUDPPayloadSize = 1200
    public static let maximumUDPPayloadSize = 65527
    public static let defaultPMTUDProbes: [UInt16] = [1454 - 48, 1390 - 48, 1280 - 48, 1492 - 48]
    public static let defaultACKThreshold = 2
    public static let defaultMaxStreamSendBufferSize = 4 * 1024 * 1024

    public var initialRTT: Duration
    public var maxSendUDPPayloadSize: Int
    public var handshakeTimeout: Duration?
    public var maxStreamWindow: UInt64
    public var maxConnectionWindow: UInt64
    public var ackThreshold: Int
    public var pmtudProbes: [UInt16]
    public var isPMTUDEnabled: Bool
    public var keepAliveTimeout: Duration?
    public var maxStreamSendBufferSize: Int
    public var maxPendingDatagrams: Int
    public var localConnectionIDLength: Int

    public init(
        initialRTT: Duration = QUICSettings.defaultInitialRTT,
        maxSendUDPPayloadSize: Int = QUICSettings.defaultMaxSendUDPPayloadSize,
        handshakeTimeout: Duration? = nil,
        maxStreamWindow: UInt64 = 0,
        maxConnectionWindow: UInt64 = 0,
        ackThreshold: Int = QUICSettings.defaultACKThreshold,
        pmtudProbes: [UInt16] = QUICSettings.defaultPMTUDProbes,
        isPMTUDEnabled: Bool = true,
        keepAliveTimeout: Duration? = nil,
        maxStreamSendBufferSize: Int = QUICSettings.defaultMaxStreamSendBufferSize,
        localConnectionIDLength: Int = 8,
        maxPendingDatagrams: Int = QUICConnection.maximumPendingDatagrams
    ) {
        self.initialRTT = initialRTT
        self.maxSendUDPPayloadSize = maxSendUDPPayloadSize
        self.handshakeTimeout = handshakeTimeout
        self.maxStreamWindow = maxStreamWindow
        self.maxConnectionWindow = maxConnectionWindow
        self.ackThreshold = ackThreshold
        self.pmtudProbes = pmtudProbes
        self.isPMTUDEnabled = isPMTUDEnabled
        self.keepAliveTimeout = keepAliveTimeout
        self.maxStreamSendBufferSize = maxStreamSendBufferSize
        self.localConnectionIDLength = localConnectionIDLength
        self.maxPendingDatagrams = Swift.max(0, maxPendingDatagrams)
    }
}
