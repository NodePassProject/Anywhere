//
//  QUICConnection.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation
import Synchronization

public struct QUICOutgoingDatagram: Sendable {
    public var count: Int
    public var path: QUICPath
}

public final class QUICConnection: Sendable {
    private let core: Mutex<ConnectionCore>

    public init(
        settings: QUICSettings = QUICSettings(),
        transportParameters: QUICTransportParameters,
        destinationID: QUICConnectionID? = nil,
        sourceID: QUICConnectionID? = nil,
        path: QUICPath,
        tls: sending any QUICTLSProvider,
        congestionController: sending any QUICCongestionController = QUICNewRenoCongestionController(),
        now: QUICInstant
    ) {
        core = Mutex(ConnectionCore(
            settings: settings, transportParameters: transportParameters,
            destinationID: destinationID, sourceID: sourceID, path: path,
            tls: tls, congestionController: congestionController, now: now
        ))
    }

    public var settings: QUICSettings { core.withLock { $0.settings } }
    public var localTransportParameters: QUICTransportParameters { core.withLock { $0.localTransportParameters } }
    public var remoteTransportParameters: QUICTransportParameters? { core.withLock { $0.remoteTransportParameters } }
    public var state: QUICConnectionState { core.withLock { $0.state } }
    public var isHandshakeComplete: Bool { core.withLock { $0.isHandshakeComplete } }
    public var isHandshakeConfirmed: Bool { core.withLock { $0.isHandshakeConfirmed } }
    public var keepAliveTimeout: Duration? {
        get { core.withLock { $0.keepAliveTimeout } }
        set { core.withLock { $0.keepAliveTimeout = newValue } }
    }
    public var congestionState: QUICCongestionState { core.withLock { $0.congestionState } }
    public var packetsSent: UInt64 { core.withLock { $0.packetsSent } }
    public var packetsReceived: UInt64 { core.withLock { $0.packetsReceived } }
    public var packetsLost: UInt64 { core.withLock { $0.packetsLost } }
    public var packetsDiscarded: UInt64 { core.withLock { $0.packetsDiscarded } }
    public var bytesSent: UInt64 { core.withLock { $0.bytesSent } }
    public var bytesReceived: UInt64 { core.withLock { $0.bytesReceived } }
    public var path: QUICPath { core.withLock { $0.path } }
    public var destinationConnectionID: QUICConnectionID { core.withLock { $0.destinationConnectionID } }
    public var sourceConnectionIDs: [QUICConnectionID] { core.withLock { $0.sourceConnectionIDs } }
    public var negotiatedVersion: UInt32 { core.withLock { $0.negotiatedVersion } }
    public var sendQuantum: Int { core.withLock { $0.sendQuantum } }
    public var pathMaxSendUDPPayloadSize: Int { core.withLock { $0.pathMaxSendUDPPayloadSize } }
    public var hasPendingEvents: Bool { core.withLock { $0.hasPendingEvents } }
    public var nextTimeout: QUICInstant? { core.withLock { $0.nextTimeout } }
    public func nextTimeout(_ kind: QUICTimeoutKind) -> QUICInstant? { core.withLock { $0.nextTimeout(kind) } }
    public var nextPreciseTimeout: QUICInstant? {
        core.withLock { core in
            var earliest: QUICInstant?
            for kind in QUICTimeoutKind.allCases where !kind.isCoarse {
                guard let expiry = core.nextTimeout(kind) else { continue }
                if earliest.map({ expiry < $0 }) ?? true { earliest = expiry }
            }
            return earliest
        }
    }
    public var nextCoarseTimeout: QUICInstant? {
        core.withLock { core in
            var earliest: QUICInstant?
            for kind in QUICTimeoutKind.allCases where kind.isCoarse {
                guard let expiry = core.nextTimeout(kind) else { continue }
                if earliest.map({ expiry < $0 }) ?? true { earliest = expiry }
            }
            return earliest
        }
    }
    public var closeReasonIfClosed: QUICConnectionCloseReason? { core.withLock { $0.closeReasonIfClosed } }
    public var maxDatagramPayloadSize: Int { core.withLock { $0.maxDatagramPayloadSize } }
    public var pendingDatagramCount: Int { core.withLock { $0.pendingDatagramCount } }
    public var availableBidirectionalStreams: UInt64 { core.withLock { $0.availableBidirectionalStreams } }
    public var availableUnidirectionalStreams: UInt64 { core.withLock { $0.availableUnidirectionalStreams } }
    public static let maximumPendingDatagrams = ConnectionCore.maximumPendingDatagrams

    public func nextEvent() -> QUICEvent? { core.withLock { $0.nextEvent() } }

    public func drainEvents() -> [QUICEvent] {
        var events: [QUICEvent] = []
        drainEvents(into: &events)
        return events
    }

    public func drainEvents(into events: inout [QUICEvent]) {
        core.withLock { $0.drainEvents(into: &events) }
    }

    public func receive(_ datagram: Data, from path: QUICPath, now: QUICInstant) {
        core.withLock { $0.receive(datagram, from: path, now: now) }
    }
    public func receive(_ datagram: [UInt8], from path: QUICPath, now: QUICInstant) {
        core.withLock { $0.receive(datagram, from: path, now: now) }
    }
    public func receive(_ datagram: UnsafeRawBufferPointer, from path: QUICPath, now: QUICInstant) {
        let bytes = BorrowedBytes(buffer: datagram)
        core.withLock { $0.receive(bytes.buffer, from: path, now: now) }
    }
    public func write(into buffer: UnsafeMutableBufferPointer<UInt8>, now: QUICInstant) -> QUICOutgoingDatagram? {
        let bytes = BorrowedOutput(buffer: buffer)
        return core.withLock { $0.write(into: bytes.buffer, now: now) }
    }
    public func write(now: QUICInstant) -> (datagram: Data, path: QUICPath)? {
        core.withLock { $0.write(now: now) }
    }
    public func finishWriting(now: QUICInstant) { core.withLock { $0.finishWriting(now: now) } }
    public func handleTimeout(now: QUICInstant) { core.withLock { $0.handleTimeout(now: now) } }
    public func close(applicationErrorCode: UInt64, reason: String = "", now: QUICInstant) {
        core.withLock { $0.close(applicationErrorCode: applicationErrorCode, reason: reason, now: now) }
    }
    public func completePeerVerification(error: (any Error)?, now: QUICInstant) throws(QUICError) {
        try core.withLock { (core) throws(QUICError) in try core.completePeerVerification(error: error, now: now) }
    }
    public func exportKeyingMaterial(label: String, context: Data, length: Int) throws -> Data {
        try core.withLock { try $0.exportKeyingMaterial(label: label, context: context, length: length) }
    }
    @discardableResult
    public func cancelPendingMigration(now: QUICInstant) -> Bool {
        core.withLock { $0.cancelPendingMigration(now: now) }
    }
    public func migrate(to path: QUICPath, immediately: Bool, now: QUICInstant) throws(QUICError) {
        try core.withLock { (core) throws(QUICError) in try core.migrate(to: path, immediately: immediately, now: now) }
    }
    public func setCongestionController(_ controller: sending any QUICCongestionController, now: QUICInstant) {
        let replacement = Mutex<(any QUICCongestionController)?>(controller)
        core.withLock { connection in
            let owned = replacement.withLock { value -> sending (any QUICCongestionController) in
                let owned = value!
                value = nil
                return owned
            }
            connection.setCongestionController(owned, now: now)
        }
    }
    @discardableResult
    public func setBrutalBandwidth(_ bytesPerSecond: UInt64) -> Bool {
        core.withLock {
            guard let controller = $0.congestionController as? QUICBrutalCongestionController else { return false }
            controller.bytesPerSecond = bytesPerSecond
            return true
        }
    }
    public func openStream(bidirectional: Bool) throws(QUICError) -> QUICStreamID {
        try core.withLock { (core) throws(QUICError) in try core.openStream(bidirectional: bidirectional) }
    }
    public func sendCapacity(on streamID: QUICStreamID) -> Int { core.withLock { $0.sendCapacity(on: streamID) } }
    @discardableResult
    public func send(_ data: Data, on streamID: QUICStreamID, fin: Bool = false) throws(QUICError) -> Int {
        try core.withLock { (core) throws(QUICError) in try core.send(data, on: streamID, fin: fin) }
    }
    public func finishSending(on streamID: QUICStreamID) throws(QUICError) {
        try core.withLock { (core) throws(QUICError) in try core.finishSending(on: streamID) }
    }
    public func resetStream(_ streamID: QUICStreamID, errorCode: UInt64) throws(QUICError) {
        try core.withLock { (core) throws(QUICError) in try core.resetStream(streamID, errorCode: errorCode) }
    }
    public func stopSending(on streamID: QUICStreamID, errorCode: UInt64) throws(QUICError) {
        try core.withLock { (core) throws(QUICError) in try core.stopSending(on: streamID, errorCode: errorCode) }
    }
    public func shutdownStream(_ streamID: QUICStreamID, errorCode: UInt64) {
        core.withLock { $0.shutdownStream(streamID, errorCode: errorCode) }
    }
    @discardableResult
    public func extendReceiveWindow(for streamID: QUICStreamID, by count: Int) -> Bool {
        core.withLock { $0.extendReceiveWindow(for: streamID, by: count) }
    }
    public func sendDatagram(_ data: Data) throws(QUICError) {
        try core.withLock { (core) throws(QUICError) in try core.sendDatagram(data) }
    }
    public func sendDatagrams(_ datagrams: [Data]) throws(QUICError) {
        try core.withLock { (core) throws(QUICError) in try core.sendDatagrams(datagrams) }
    }
}

private struct BorrowedBytes: @unchecked Sendable { let buffer: UnsafeRawBufferPointer }
private struct BorrowedOutput: @unchecked Sendable { let buffer: UnsafeMutableBufferPointer<UInt8> }
