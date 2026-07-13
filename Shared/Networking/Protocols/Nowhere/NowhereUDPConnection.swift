//
//  NowhereUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

nonisolated final class NowhereUDPConnection: ProxyConnection {

    enum State { case idle, ready, closed }

    private let session: NowhereSession
    private let destination: String
    private let requestedFlowID: UInt64?
    private let downlink: NowhereNetwork
    private let reopensExpiredFlow: Bool

    private var _state: State = .idle
    private var state: State {
        get { _state }
        set {
            _state = newValue
            _isReady.store(newValue == .ready, ordering: .relaxed)
        }
    }
    private let _isReady = Atomic<Bool>(false)

    private var flowID: UInt64 = 0
    private var packetQueue: [Data] = []
    private static let maxQueuedPackets = 1024
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var closureError: Error?
    private var openAcknowledged = false

    private struct DefragSlot {
        var fragments: [Data?]
        var received: Int
        let fragmentCount: Int
        let totalLength: Int
        let createdAt: DispatchTime
    }
    private var defragSlots: [UInt16: DefragSlot] = [:]
    private static let maxDefragSlots = 64
    private static let defragSlotTTLNanos: UInt64 = 10 * 1_000_000_000
    private var nextPacketID: UInt16 = 1

    init(
        session: NowhereSession,
        destination: String,
        requestedFlowID: UInt64? = nil,
        downlink: NowhereNetwork = .udp,
        reopensExpiredFlow: Bool = true
    ) {
        self.session = session
        self.destination = destination
        self.requestedFlowID = requestedFlowID
        self.downlink = downlink
        self.reopensExpiredFlow = reopensExpiredFlow
        super.init()
    }

    override var isConnected: Bool {
        _isReady.load(ordering: .relaxed)
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }
    override var deliversDatagrams: Bool { true }

    func open(completion: @escaping (Error?) -> Void) {
        session.registerUDPSession(self, requestedFlowID: requestedFlowID) { [weak self] result in
            guard let self else {
                completion(NowhereError.streamClosed)
                return
            }
            switch result {
            case .failure(let error):
                completion(error)
            case .success(let flowID):
                self.flowID = flowID
                self.state = .ready
                completion(nil)
            }
        }
    }

    func handleOpenAck() { openAcknowledged = true }

    func handleFlowClose() {
        guard state == .ready else { return }
        if reopensExpiredFlow {
            openAcknowledged = false
            defragSlots.removeAll()
        } else {
            handleSessionClose()
        }
    }

    func handleIncomingDatagram(_ message: NowhereProtocol.UDPMessage) {
        guard state != .closed else { return }
        let payload: Data?
        if message.fragmentCount == 1 {
            payload = message.payload
        } else {
            payload = assembleFragment(message)
        }
        guard let payload else { return }
        if let callback = pendingReceive {
            pendingReceive = nil
            callback(payload, nil)
            return
        }
        if packetQueue.count >= Self.maxQueuedPackets {
            packetQueue.removeFirst()
        }
        packetQueue.append(payload)
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            guard self.state == .ready else {
                completion(self.state == .closed ? NowhereError.streamClosed : NowhereError.notReady)
                return
            }
            self.attemptSend(data: data, maxSizeOverride: nil, retriesLeft: 1, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    private func attemptSend(
        data: Data,
        maxSizeOverride: Int?,
        retriesLeft: Int,
        completion: @escaping (Error?) -> Void
    ) {
        let maxSize = maxSizeOverride ?? session.maxDatagramPayloadSize
        let packetID = newPacketID()
        let frames: [Data]
        do {
            if openAcknowledged {
                frames = try NowhereProtocol.encodeUDPDataFragments(
                    flowID: flowID,
                    packetID: packetID,
                    payload: data,
                    maxDatagramSize: maxSize
                )
            } else {
                frames = try NowhereProtocol.encodeUDPOpenFragments(
                    flowID: flowID,
                    packetID: packetID,
                    downlink: downlink,
                    target: destination,
                    payload: data,
                    maxDatagramSize: maxSize
                )
            }
        } catch {
            completion(error)
            return
        }
        session.writeDatagrams(frames) { [weak self] error in
            if let quicError = error as? QUICConnection.QUICError,
               case .datagramTooLarge(let maxBound) = quicError,
               retriesLeft > 0,
               let self {
                guard self.state == .ready else {
                    completion(self.state == .closed ? NowhereError.streamClosed : NowhereError.notReady)
                    return
                }
                self.attemptSend(
                    data: data,
                    maxSizeOverride: maxBound,
                    retriesLeft: retriesLeft - 1,
                    completion: completion
                )
                return
            }
            completion(error)
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else {
                completion(nil, NowhereError.streamClosed)
                return
            }
            if !self.packetQueue.isEmpty {
                let packet = self.packetQueue.removeFirst()
                completion(packet, nil)
                return
            }
            if let error = self.closureError {
                self.closureError = nil
                completion(nil, error)
                return
            }
            if self.state == .closed {
                completion(nil, nil)
                return
            }
            let stale = self.pendingReceive
            self.pendingReceive = completion
            stale?(nil, NowhereError.connectionFailed("overlapping receiveRaw on Nowhere UDP"))
        }
    }

    override func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.sendCloseFrame()
            self.session.releaseUDPSession(self.flowID)
            let callback = self.pendingReceive
            self.pendingReceive = nil
            self.packetQueue.removeAll()
            self.defragSlots.removeAll()
            callback?(nil, nil)
        }
    }

    private func sendCloseFrame() {
        guard flowID != 0 else { return }
        let frame = try? NowhereProtocol.encodeUDPControl(
            type: .close,
            flowID: flowID
        )
        if let frame {
            session.writeDatagram(frame) { _ in }
        }
    }

    func handleSessionError(_ error: Error) {
        if let quicError = error as? QUICConnection.QUICError, case .closedOK = quicError {
            handleSessionClose()
            return
        }
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            let callback = self.pendingReceive
            self.pendingReceive = nil
            if callback == nil {
                self.closureError = error
            }
            callback?(nil, error)
        }
    }

    func handleSessionClose() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.session.releaseUDPSession(self.flowID)
            self.defragSlots.removeAll()
            let callback = self.pendingReceive
            self.pendingReceive = nil
            callback?(nil, nil)
        }
    }

    private func assembleFragment(_ message: NowhereProtocol.UDPMessage) -> Data? {
        guard message.fragmentCount > 1,
              message.fragmentID < message.fragmentCount else { return nil }
        let now = DispatchTime.now()
        let nowNanos = now.uptimeNanoseconds
        let existing = defragSlots[message.packetID]
        let expired = existing.map {
            nowNanos &- $0.createdAt.uptimeNanoseconds > Self.defragSlotTTLNanos
        } ?? false

        var slot: DefragSlot
        if let existing, !expired,
           existing.fragmentCount == Int(message.fragmentCount),
           existing.totalLength == Int(message.totalLength) {
            slot = existing
        } else {
            if defragSlots.count >= Self.maxDefragSlots {
                let victim = defragSlots.min { lhs, rhs in
                    lhs.value.createdAt < rhs.value.createdAt
                }?.key
                if let victim { defragSlots.removeValue(forKey: victim) }
            }
            slot = DefragSlot(
                fragments: Array(repeating: nil, count: Int(message.fragmentCount)),
                received: 0,
                fragmentCount: Int(message.fragmentCount),
                totalLength: Int(message.totalLength),
                createdAt: now
            )
        }

        let index = Int(message.fragmentID)
        if let existing = slot.fragments[index] {
            if existing != message.payload {
                defragSlots.removeValue(forKey: message.packetID)
                return nil
            }
        } else {
            slot.fragments[index] = message.payload
            slot.received += 1
        }
        if slot.received < slot.fragmentCount {
            defragSlots[message.packetID] = slot
            return nil
        }

        defragSlots.removeValue(forKey: message.packetID)
        var full = Data(capacity: slot.totalLength)
        for fragment in slot.fragments {
            guard let fragment else { return nil }
            full.append(fragment)
        }
        return full.count == slot.totalLength ? full : nil
    }

    private func newPacketID() -> UInt16 {
        dispatchPrecondition(condition: .onQueue(session.queue))
        let packetID = nextPacketID
        nextPacketID = nextPacketID == UInt16.max ? 1 : nextPacketID + 1
        return packetID
    }
}
