//
//  ConnectionCore.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

struct KeyUpdateState {
    var currentPhase = false
    var nextRead: PacketKeys?
    var nextWrite: PacketKeys?
    var oldRead: PacketKeys?
    var isPending = false
    var isInitiator = false
    var confirmedAt: Nanoseconds = Time.never
    var readFirstPacketNumber: UInt64 = 0
    var writeFirstPacketNumber: UInt64 = 0
    var encryptionCount: UInt64 = 0
}

final class ConnectionCore {
    static let minimumPacketExpansion = 22
    static let maxLocalConnectionIDs = 8
    static let maxPendingPathResponses = 4
    static let flowWindowRTTFactor: UInt64 = 2
    static let flowWindowScalingFactor: UInt64 = 2
    static let minimumCoalescedPayload = 128

    enum HandshakePhase {
        case initial
        case waitingForHandshake
    }

    let settings: QUICSettings
    var localTransportParameters: QUICTransportParameters
    var remoteTransportParameters: QUICTransportParameters? {
        didSet {
            let remote = self.remoteTransportParameters
            self.peerMaxUDPPayloadSize = remote.map { Int(Swift.min($0.maxUDPPayloadSize, UInt64(Int.max))) } ?? Int.max
            self.peerMaxACKDelay = remote?.maxACKDelay.clampedNanoseconds ?? 0
            self.peerACKDelayExponent = remote?.ackDelayExponent ?? QUICTransportParameters.defaultACKDelayExponent
            self.peerMaxIdleTimeout = remote?.maxIdleTimeout.clampedNanoseconds ?? 0
            self.peerMaxDatagramFrameSize = remote?.maxDatagramFrameSize ?? 0
            self.peerActiveConnectionIDLimit = remote?.activeConnectionIDLimit ?? 0
        }
    }
    private(set) var peerMaxUDPPayloadSize = Int.max
    private(set) var peerMaxACKDelay: Nanoseconds = 0
    private(set) var peerACKDelayExponent = QUICTransportParameters.defaultACKDelayExponent
    private(set) var peerMaxIdleTimeout: Nanoseconds = 0
    private(set) var peerMaxDatagramFrameSize: UInt64 = 0
    private(set) var peerActiveConnectionIDLimit: UInt64 = 0
    var state: QUICConnectionState = .handshaking
    var isHandshakeComplete = false
    var isHandshakeConfirmed = false
    var keepAliveTimeout: Duration? {
        didSet {
            self.keepAliveTimeoutNanoseconds = Self.keepAliveTimeoutNanoseconds(for: self.keepAliveTimeout)
        }
    }

    let tls: any QUICTLSProvider
    var congestionController: any QUICCongestionController
    let version = QUICVersion.v1

    var handshakePhase: HandshakePhase = .initial
    var isTLSHandshakeComplete = false
    var isServerAddressVerified = false
    var hasProcessedInitialPacket = false
    var hasReceivedTransportParameters = false
    var hasReceivedRetry = false
    var shouldRestartIdleTimerOnWrite = false
    var hasStartedHandshake = false
    var isAwaitingPeerVerification = false
    var crumblesInitialCrypto = true
    var pcg = PCG32()

    var initialSpace: PacketNumberSpace?
    var handshakeSpace: PacketNumberSpace?
    let applicationSpace = PacketNumberSpace(level: .application)

    let originalDestinationID: QUICConnectionID
    let originalSourceID: QUICConnectionID
    var retrySourceID: QUICConnectionID?
    var retryToken: [UInt8] = []
    var localIDs: [LocalConnectionID]
    var localLastSequence: UInt64 = 0
    var localInFlightCount = 0
    var localRetiredCount: Int { self.localIDs.reduce(0) { $1.isRetired ? $0 + 1 : $0 } }
    var active: ActivePath
    var destinationIDs = DestinationIDTracker()

    var pathValidation: PathValidation?
    var pendingPathResponses: [(data: UInt64, path: QUICPath)] = []
    var pathMTUDiscovery: PMTUDiscovery?

    var keyUpdate = KeyUpdateState()
    var decryptionFailures: UInt64 = 0
    var shouldProcessBufferedHandshakePackets = false
    var shouldProcessBufferedApplicationPackets = false

    var streams: [QUICStreamID: Stream] = [:]
    var streamSendQueue = FIFOQueue<QUICStreamID>()
    var pendingDatagrams = FIFOQueue<Data>()
    var localBidirectionalNextIndex: UInt64 = 0
    var localUnidirectionalNextIndex: UInt64 = 0
    var localBidirectionalMaxStreams: UInt64 = 0
    var localUnidirectionalMaxStreams: UInt64 = 0
    var remoteBidirectionalMaxStreams: UInt64
    var remoteBidirectionalUnsentMaxStreams: UInt64
    var remoteUnidirectionalMaxStreams: UInt64
    var remoteUnidirectionalUnsentMaxStreams: UInt64
    var remoteBidirectionalOpened = RangeSet()
    var remoteUnidirectionalOpened = RangeSet()

    var receiveOffset: UInt64 = 0
    var receiveMaxOffset: UInt64
    var receiveUnsentMaxOffset: UInt64
    var receiveWindow: UInt64
    var lastMaxDataSentAt: Nanoseconds = Time.never
    var sendOffset: UInt64 = 0
    var sendMaxOffset: UInt64 = 0
    var sendLastBlockedOffset: UInt64 = .max

    var congestionState: QUICCongestionState
    var ptoCount = 0
    var lossDetectionTimer: Nanoseconds = Time.never
    var handshakeConfirmedAt: Nanoseconds = Time.never
    var pacer = Pacer()
    var deliveryRateSampler = DeliveryRateSampler()
    var idleTimestamp: Nanoseconds
    var keepAliveLastSentAt: Nanoseconds = Time.never
    var keepAliveTimeoutNanoseconds: Nanoseconds
    var isKeepAliveCancelled = false
    let startTime: Nanoseconds
    var latestTime: Nanoseconds

    var closeReason: QUICConnectionCloseReason?
    var pendingClose: (isApplication: Bool, errorCode: UInt64, frameType: FrameType, reason: String)?
    var closePacket: [UInt8]?
    var closePacketCount: UInt64 = 0
    var closePacketPath: QUICPath?
    var isCloseResendPending = false
    var packetsSinceCloseResend = 0
    var closeResendThreshold = 1
    var closingEndsAt: Nanoseconds = Time.never

    var events: [QUICEvent] = []
    var eventsHead = 0

    var decryptBuffer: [UInt8]
    var headerScratch = [UInt8](repeating: 0, count: 128)
    var arena: PlaintextArena
    var acknowledgedScratch: [SentPacket] = []

    var packetsSent: UInt64 = 0
    var packetsReceived: UInt64 = 0
    var packetsLost: UInt64 = 0
    var packetsDiscarded: UInt64 = 0
    var bytesSent: UInt64 = 0
    var bytesReceived: UInt64 = 0

    init(
        settings: QUICSettings = QUICSettings(),
        transportParameters: QUICTransportParameters,
        destinationID: QUICConnectionID? = nil,
        sourceID: QUICConnectionID? = nil,
        path: QUICPath,
        tls: any QUICTLSProvider,
        congestionController: any QUICCongestionController = QUICNewRenoCongestionController(),
        now: QUICInstant
    ) {
        var settings = settings
        settings.maxSendUDPPayloadSize = Swift.min(
            Swift.max(settings.maxSendUDPPayloadSize, QUICSettings.minimumUDPPayloadSize),
            QUICSettings.maximumUDPPayloadSize
        )
        settings.localConnectionIDLength = Swift.min(
            Swift.max(settings.localConnectionIDLength, 0),
            QUICConnectionID.maxLength
        )
        settings.maxPendingDatagrams = Swift.max(0, settings.maxPendingDatagrams)
        settings.maxStreamSendBufferSize = Swift.max(0, settings.maxStreamSendBufferSize)
        self.settings = settings
        self.tls = tls
        self.congestionController = congestionController
        let destinationID = destinationID ?? QUICConnectionID.random(length: 8)
        precondition(
            destinationID.count >= PacketHeader.minimumInitialDestinationIDLength,
            "initial destination connection ID must be at least 8 bytes"
        )
        let sourceID = sourceID ?? QUICConnectionID.random(length: settings.localConnectionIDLength)
        self.originalDestinationID = destinationID
        self.originalSourceID = sourceID
        var parameters = transportParameters
        parameters.initialSourceConnectionID = sourceID
        parameters.originalDestinationConnectionID = nil
        parameters.retrySourceConnectionID = nil
        parameters.statelessResetToken = nil
        parameters.preferredAddress = nil
        parameters.maxUDPPayloadSize = Swift.max(
            parameters.maxUDPPayloadSize,
            QUICTransportParameters.minimumMaxUDPPayloadSize
        )
        parameters.activeConnectionIDLimit = Swift.max(
            parameters.activeConnectionIDLimit,
            QUICTransportParameters.defaultActiveConnectionIDLimit
        )
        self.localTransportParameters = parameters
        self.localIDs = [LocalConnectionID(id: sourceID, sequence: 0, token: .random())]
        self.active = ActivePath(
            connectionID: RemoteConnectionID(id: destinationID, sequence: 0, token: nil),
            path: path,
            isValidated: true,
            maxUDPPayloadSize: QUICSettings.minimumUDPPayloadSize
        )
        self.remoteBidirectionalMaxStreams = parameters.initialMaxStreamsBidirectional
        self.remoteBidirectionalUnsentMaxStreams = parameters.initialMaxStreamsBidirectional
        self.remoteUnidirectionalMaxStreams = parameters.initialMaxStreamsUnidirectional
        self.remoteUnidirectionalUnsentMaxStreams = parameters.initialMaxStreamsUnidirectional
        self.receiveMaxOffset = parameters.initialMaxData
        self.receiveUnsentMaxOffset = parameters.initialMaxData
        self.receiveWindow = parameters.initialMaxData
        let initialRTT = Swift.max(settings.initialRTT.clampedNanoseconds, Time.millisecond)
        self.congestionState = QUICCongestionState(
            initialRTT: initialRTT,
            maxSendUDPPayloadSize: QUICSettings.minimumUDPPayloadSize
        )
        self.startTime = now.nanoseconds
        self.latestTime = now.nanoseconds
        self.idleTimestamp = now.nanoseconds
        self.keepAliveTimeout = settings.keepAliveTimeout
        self.keepAliveTimeoutNanoseconds = Self.keepAliveTimeoutNanoseconds(for: settings.keepAliveTimeout)
        self.decryptBuffer = [UInt8](repeating: 0, count: Swift.max(settings.maxSendUDPPayloadSize, 1500))
        self.arena = PlaintextArena(packetCapacity: Swift.max(settings.maxSendUDPPayloadSize, 1500))
        let initial = PacketNumberSpace(level: .initial)
        let keys = PacketKeys.initial(destinationID: destinationID, isClient: true)
        initial.readKeys = keys.read
        initial.writeKeys = keys.write
        self.initialSpace = initial
        self.handshakeSpace = PacketNumberSpace(level: .handshake)
        congestionController.reset(state: &self.congestionState, now: now)
    }

    var path: QUICPath { self.active.path }

    var destinationConnectionID: QUICConnectionID { self.active.connectionID.id }

    var sourceConnectionIDs: [QUICConnectionID] { self.localIDs.filter { !$0.isRetired }.map(\.id) }

    var negotiatedVersion: UInt32 { self.version.rawValue }

    var sendQuantum: Int { self.congestionState.sendQuantum }

    var pathMaxSendUDPPayloadSize: Int {
        return Swift.min(self.active.maxUDPPayloadSize, self.peerMaxUDPPayloadSize, self.settings.maxSendUDPPayloadSize)
    }

    func nextEvent() -> QUICEvent? {
        guard self.eventsHead < self.events.count else {
            if !self.events.isEmpty {
                self.events.removeAll(keepingCapacity: true)
                self.eventsHead = 0
            }
            return nil
        }
        let event = self.events[self.eventsHead]
        self.eventsHead += 1
        if self.eventsHead == self.events.count {
            self.events.removeAll(keepingCapacity: true)
            self.eventsHead = 0
        }
        return event
    }

    var hasPendingEvents: Bool { self.eventsHead < self.events.count }

    func drainEvents(into buffer: inout [QUICEvent]) {
        buffer.removeAll(keepingCapacity: true)
        if self.eventsHead > 0 {
            self.events.removeFirst(self.eventsHead)
            self.eventsHead = 0
        }
        swap(&self.events, &buffer)
    }

    func emit(_ event: QUICEvent) {
        self.events.append(event)
    }

    @discardableResult
    func updateTimestamp(_ now: Nanoseconds) -> Nanoseconds {
        if now > self.latestTime {
            self.latestTime = now
        }
        return self.latestTime
    }

    var isClientInitiated: Bool { true }

    func isLocalStream(_ id: QUICStreamID) -> Bool {
        return id.isClientInitiated
    }

    func pto(for space: PacketNumberSpace) -> Nanoseconds {
        let maxACKDelay = space.isApplication ? self.peerMaxACKDelay : 0
        return self.congestionState.pto(maxACKDelay: maxACKDelay)
    }

    var localMaxACKDelay: Nanoseconds {
        return self.localTransportParameters.maxACKDelay.clampedNanoseconds
    }

    var initialPTO: Nanoseconds {
        let initialRTT = self.congestionState.initialRTTNanoseconds
        return initialRTT + Swift.max(4 * (initialRTT / 2), Recovery.granularity) + self.peerMaxACKDelay
    }

    func computeACKDelay() -> Nanoseconds {
        return Swift.min(
            self.localMaxACKDelay,
            Swift.max(self.congestionState.smoothedRTTNanoseconds / 8, Time.nanosecond)
        )
    }

    var minimumPacketLength: Int {
        return self.originalSourceID.count + Self.minimumPacketExpansion
    }

    var isCongestionWindowExhausted: Bool {
        return self.congestionState.bytesInFlight >= self.congestionState.congestionWindow
    }

    func space(for level: QUICEncryptionLevel) -> PacketNumberSpace? {
        switch level {
        case .initial:
            return self.initialSpace
        case .handshake:
            return self.handshakeSpace
        case .application:
            return self.applicationSpace
        }
    }

    func restartIdleTimerOnRead(_ now: Nanoseconds) {
        self.idleTimestamp = now
        self.shouldRestartIdleTimerOnWrite = true
    }

    func restartIdleTimerOnWriteIfNeeded(_ now: Nanoseconds) {
        guard self.shouldRestartIdleTimerOnWrite else {
            return
        }
        self.idleTimestamp = now
        self.shouldRestartIdleTimerOnWrite = false
    }

    static func keepAliveTimeoutNanoseconds(for timeout: Duration?) -> Nanoseconds {
        guard let timeout else {
            return Time.never
        }
        let nanoseconds = timeout.clampedNanoseconds
        return nanoseconds == 0 ? Time.never : nanoseconds
    }

    func updateKeepAlive(_ now: Nanoseconds) {
        self.keepAliveLastSentAt = now
        self.isKeepAliveCancelled = false
    }

    var isKeepAliveEnabled: Bool {
        return self.keepAliveLastSentAt != Time.never && self.keepAliveTimeoutNanoseconds != Time.never
    }

    func isKeepAliveExpired(_ now: Nanoseconds) -> Bool {
        return self.isKeepAliveEnabled
            && Time.elapsed(self.keepAliveLastSentAt, self.keepAliveTimeoutNanoseconds, now)
    }

    var keepAliveExpiry: Nanoseconds {
        guard !self.isKeepAliveCancelled, self.isHandshakeComplete, self.isKeepAliveEnabled else {
            return Time.never
        }
        return self.keepAliveLastSentAt.addingClamped(self.keepAliveTimeoutNanoseconds)
    }

    func cancelExpiredKeepAliveTimer(now: Nanoseconds) {
        if !self.isKeepAliveCancelled, self.isKeepAliveExpired(now) {
            self.isKeepAliveCancelled = true
        }
    }

    func ensureDecryptBuffer(_ count: Int) {
        if self.decryptBuffer.count < count {
            self.decryptBuffer = [UInt8](repeating: 0, count: count)
        }
    }

    func findLocalID(_ id: QUICConnectionID) -> Int? {
        return self.localIDs.firstIndex { $0.id == id }
    }

    func verifyDestinationID(_ id: QUICConnectionID) -> Bool {
        guard let index = self.findLocalID(id) else {
            return false
        }
        self.localIDs[index].isUsed = true
        return true
    }

    func isKnownPath(_ path: QUICPath) -> Bool {
        if self.active.path == path {
            return true
        }
        if let pathValidation = self.pathValidation, pathValidation.path == path {
            return true
        }
        return self.destinationIDs.isRetiredPath(path)
    }
}
