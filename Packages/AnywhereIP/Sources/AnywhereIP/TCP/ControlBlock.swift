//
//  ControlBlock.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation

final class ControlBlock {
    enum State: Comparable {
        case synReceived
        case established
        case finWait1
        case finWait2
        case closeWait
        case closing
        case lastAck
        case timeWait
        case closed
    }

    struct Flags: OptionSet {
        let rawValue: UInt16

        static let ackNow = Flags(rawValue: 0x02)
        static let inFastRecovery = Flags(rawValue: 0x04)
        static let receiveClosed = Flags(rawValue: 0x10)
        static let fin = Flags(rawValue: 0x20)
        static let windowScale = Flags(rawValue: 0x100)
        static let rto = Flags(rawValue: 0x800)
    }

    struct ReceiveFlags: OptionSet {
        let rawValue: UInt8

        static let reset = ReceiveFlags(rawValue: 0x08)
        static let closed = ReceiveFlags(rawValue: 0x10)
        static let gotFin = ReceiveFlags(rawValue: 0x20)
        static let push = ReceiveFlags(rawValue: 0x40)
    }

    let source: IPEndpoint
    let destination: IPEndpoint
    private(set) var isAttached = true

    let stack: Context
    let arena: SegmentArena
    let key: ConnectionKey
    let delaysAcknowledgment: Bool
    let receiveMSS: Int
    private(set) var acknowledgmentHeld = false
    var state = State.synReceived
    var flags: Flags = []
    var tmr: UInt32
    var rcvNxt: UInt32
    var rcvWnd: UInt32 = 0xFFFF
    var rcvAnnWnd: UInt32 = 0xFFFF
    var rcvAnnRightEdge: UInt32
    var rtoStart: UInt32?
    var rto = Constants.initialRTO
    var sa: Int16 = 0
    var sv = Constants.initialRTO
    var nrtx: UInt8 = 0
    var dupacks: UInt8 = 0
    var mss = Constants.initialMSS
    var rttest: UInt32 = 0
    var rtseq: UInt32 = 0
    var lastAck: UInt32
    var rtoEnd: UInt32 = 0
    var sndNxt: UInt32
    var sndWl1: UInt32
    var sndWl2: UInt32
    var sndLbb: UInt32
    var sndWnd: UInt32
    var sndWndMax: UInt32
    var sndBuf = Constants.sendBufferSize
    var unsent = SegmentList()
    var unacked = SegmentList()
    var unsentOversize = 0
    var persistStart: UInt32 = 0
    var persistBackoff: UInt8 = 0
    var persistProbes: UInt8 = 0
    var sndScale: UInt8 = 0
    var rcvScale: UInt8 = 0
    var isProcessingInput = false
    var closeAfterInput = false

    init(stack: Context, key: ConnectionKey, initialSequenceNumber: UInt32, peerWindow: UInt16, options: UnsafeRawBufferPointer, delaysAcknowledgment: Bool) {
        self.stack = stack
        arena = stack.arena
        self.key = key
        self.delaysAcknowledgment = delaysAcknowledgment
        receiveMSS = min(Int(Constants.maximumSegmentSize), Constants.mtu - (key.local.address.isIPv6 ? IPv6Header.length : IPv4Header.length) - TCPHeader.length)
        source = key.remote
        destination = key.local
        tmr = stack.ticks
        let iss = stack.initialSequenceNumber
        rcvNxt = initialSequenceNumber &+ 1
        rcvAnnRightEdge = rcvNxt
        sndWl2 = iss
        sndNxt = iss
        lastAck = iss
        sndLbb = iss
        sndWl1 = initialSequenceNumber &- 1
        sndWnd = UInt32(peerWindow)
        sndWndMax = sndWnd
        parseOptions(options)
        mss = effectiveSendMSS(mss)
    }

    var sendBufferSpace: Int {
        Int(sndBuf)
    }

    var sendQueueLength: Int {
        unsent.count + unacked.count
    }

    @discardableResult
    func write(_ bytes: UnsafeRawBufferPointer) -> Int {
        guard isAttached, let base = bytes.baseAddress else { return 0 }
        let segmentSize = sendSegmentSize
        let tailRoom = min(unsentOversize, max(0, segmentSize - (unsent.last?.length ?? segmentSize)))
        let queueRoom = max(0, Constants.sendQueueLimit - sendQueueLength) * segmentSize + tailRoom
        let count = min(bytes.count, Int(sndBuf), queueRoom)
        guard count > 0, enqueue(UnsafeRawBufferPointer(start: base, count: count)) else { return 0 }
        return count
    }

    func didConsume(_ count: Int) {
        guard isAttached, state != .timeWait, state != .closed, count > 0 else { return }
        let announced = Sequence.lessThan(rcvNxt, rcvAnnRightEdge) ? rcvAnnRightEdge &- rcvNxt : 0
        rcvWnd = UInt32(min(UInt64(rcvWnd) + UInt64(count), UInt64(windowMax)))
        updateAnnouncedWindow()
        guard announced <= windowMax / 2, rcvAnnWnd > 0, rcvAnnWnd >= announced * 2 else { return }
        flags.insert(.ackNow)
        output()
    }

    func flushHeldAcknowledgment() {
        guard acknowledgmentHeld else { return }
        acknowledgmentHeld = false
        flags.insert(.ackNow)
        output()
    }

    func shutdownSend() {
        guard isAttached else { return }
        switch state {
        case .synReceived, .established, .closeWait:
            closeSendSide(resetOnUnreadData: false)
        default:
            break
        }
    }

    func close() {
        guard isAttached else { return }
        detach()
        flags.insert(.receiveClosed)
        closeSendSide(resetOnUnreadData: true)
    }

    var windowMax: UInt32 {
        flags.contains(.windowScale) ? Constants.window : 0xFFFF
    }

    func detach() {
        isAttached = false
    }

    private func effectiveSendMSS(_ value: UInt16) -> UInt16 {
        let overhead = (destination.address.isIPv6 ? IPv6Header.length : IPv4Header.length) + TCPHeader.length
        return min(value, UInt16(Constants.mtu - overhead))
    }

    private func parseOptions(_ bytes: UnsafeRawBufferPointer) {
        let options = TCPHeader.Options(parsing: bytes)
        if let value = options.maximumSegmentSize {
            mss = (value > Constants.maximumSegmentSize || value == 0) ? Constants.maximumSegmentSize : value
        }
        if let scale = options.windowScale, !flags.contains(.windowScale) {
            sndScale = min(scale, 14)
            rcvScale = Constants.receiveScale
            flags.insert(.windowScale)
            rcvWnd = Constants.window
            rcvAnnWnd = Constants.window
        }
    }

    func sendSynAck() {
        var options = TCPHeader.Options(maximumSegmentSize: effectiveSendMSS(Constants.maximumSegmentSize))
        if flags.contains(.windowScale) {
            options.windowScale = Constants.receiveScale
        }
        enqueueControl(flags: [.syn, .ack], options: options)
        output()
    }

    private func enqueueControl(flags controlFlags: TCPHeader.Flags, options: TCPHeader.Options = TCPHeader.Options()) {
        unsent.append(arena.allocate(sequenceNumber: sndLbb, flags: controlFlags, options: options))
        unsentOversize = 0
        sndLbb &+= 1
        if controlFlags.contains(.fin) {
            flags.insert(.fin)
        }
    }

    private func enqueueFin() {
        if let last = unsent.last, last.flags.isDisjoint(with: [.syn, .fin, .rst]) {
            last.flags.insert(.fin)
            flags.insert(.fin)
            return
        }
        enqueueControl(flags: [.fin])
    }

    private func enqueue(_ bytes: UnsafeRawBufferPointer) -> Bool {
        switch state {
        case .synReceived, .established, .closeWait:
            break
        default:
            return false
        }
        let length = bytes.count
        guard length > 0 else { return true }
        guard length <= Int(sndBuf) else { return false }
        let segmentSize = sendSegmentSize
        var oversize = unsentOversize
        var position = 0
        if let last = unsent.last, oversize > 0 {
            position = min(segmentSize - last.length, min(oversize, length))
            oversize -= position
        }
        guard sendQueueLength + (length - position + segmentSize - 1) / segmentSize <= Constants.sendQueueLimit else { return false }
        if position > 0 {
            unsent.last.unsafelyUnwrapped.appendPayload(UnsafeRawBufferPointer(rebasing: bytes[..<position]))
        }
        while position < length {
            let count = min(length - position, segmentSize)
            let segment = arena.allocate(sequenceNumber: sndLbb &+ UInt32(position), flags: [])
            segment.setPayload(UnsafeRawBufferPointer(rebasing: bytes[position..<(position + count)]))
            unsent.append(segment)
            oversize = segmentSize - count
            position += count
        }
        unsent.last.unsafelyUnwrapped.flags.insert(.psh)
        unsentOversize = oversize
        sndLbb &+= UInt32(length)
        sndBuf -= UInt32(length)
        return true
    }

    private var sendSegmentSize: Int {
        let limited = Int(min(UInt32(mss), min(sndWndMax / 2, 0xFFFF)))
        return limited == 0 ? Int(mss) : limited
    }

    private func closeSendSide(resetOnUnreadData: Bool) {
        if resetOnUnreadData, state == .established || state == .closeWait, rcvWnd != windowMax {
            if isProcessingInput {
                closeAfterInput = true
            } else {
                terminate(sendingReset: true, error: nil)
            }
            return
        }
        switch state {
        case .synReceived, .established:
            enqueueFin()
            state = .finWait1
        case .closeWait:
            enqueueFin()
            state = .lastAck
        default:
            return
        }
        output()
    }

    func terminate(sendingReset: Bool, error: ConnectionError?) {
        guard state != .closed else { return }
        if sendingReset, state != .timeWait {
            sendReset(sequenceNumber: sndNxt, acknowledgmentNumber: rcvNxt)
        }
        purge()
        state = .closed
        stack.effects.append(.removed)
        if let error, isAttached {
            detach()
            stack.effects.append(.failed(error))
        }
    }

    private func purge() {
        while let segment = unsent.removeFirst() {
            arena.recycle(segment)
        }
        while let segment = unacked.removeFirst() {
            arena.recycle(segment)
        }
        unsentOversize = 0
        rtoStart = nil
    }

    private func enterTimeWait() {
        purge()
        state = .timeWait
        stack.effects.append(.timeWait)
    }

    private func updateAnnouncedWindow() {
        if Sequence.lessThanOrEqual(rcvAnnRightEdge &+ min(Constants.window / 2, UInt32(mss)), rcvNxt &+ rcvWnd) {
            rcvAnnWnd = rcvWnd
        } else if Sequence.lessThan(rcvAnnRightEdge, rcvNxt) {
            rcvAnnWnd = 0
        } else {
            rcvAnnWnd = rcvAnnRightEdge &- rcvNxt
        }
    }

    private var announcedWindow: UInt16 {
        UInt16(min(rcvAnnWnd >> rcvScale, 0xFFFF))
    }

    private func sendReset(sequenceNumber: UInt32, acknowledgmentNumber: UInt32) {
        stack.sendReset(from: destination, to: source, sequenceNumber: sequenceNumber, acknowledgmentNumber: acknowledgmentNumber)
    }

    private func sendEmptyAck(_ stack: Context) {
        let segment = arena.allocate(sequenceNumber: sndNxt, flags: [.ack])
        rcvAnnRightEdge = rcvNxt &+ rcvAnnWnd
        stack.transmit(segment, acknowledgmentNumber: rcvNxt, window: announcedWindow)
        flags.remove(.ackNow)
        acknowledgmentHeld = false
    }

    private func transmit(_ segment: Segment, _ stack: Context) {
        if rtoStart == nil {
            rtoStart = stack.ticks
        }
        if rttest == 0, Sequence.lessThanOrEqual(sndNxt, segment.sequenceNumber) {
            rttest = stack.ticks
            rtseq = segment.sequenceNumber
        }
        let window = segment.options.windowScale != nil ? UInt16(min(rcvAnnWnd, 0xFFFF)) : announcedWindow
        rcvAnnRightEdge = rcvNxt &+ rcvAnnWnd
        acknowledgmentHeld = false
        stack.transmit(segment, acknowledgmentNumber: rcvNxt, window: window)
    }

    func output() {
        guard state != .closed, !isProcessingInput else { return }
        let wnd = sndWnd
        guard let first = unsent.first else {
            if flags.contains(.ackNow) {
                sendEmptyAck(stack)
            }
            return
        }
        if first.sequenceNumber &- lastAck &+ UInt32(first.length) > wnd {
            if unacked.isEmpty, persistBackoff == 0 {
                persistStart = stack.ticks
                persistBackoff = 1
                persistProbes = 0
            }
            if flags.contains(.ackNow) {
                sendEmptyAck(stack)
            }
            return
        }
        persistBackoff = 0
        let stack = self.stack
        while let segment = unsent.first, segment.sequenceNumber &- lastAck &+ UInt32(segment.length) <= wnd {
            segment.flags.insert(.ack)
            transmit(segment, stack)
            _ = unsent.removeFirst()
            flags.remove(.ackNow)
            let next = segment.sequenceNumber &+ segment.tcpLength
            if Sequence.lessThan(sndNxt, next) {
                sndNxt = next
            }
            if segment.tcpLength > 0 {
                insertUnacked(segment)
            } else {
                arena.recycle(segment)
            }
        }
        if unsent.isEmpty {
            unsentOversize = 0
        }
    }

    private func insertUnacked(_ segment: Segment) {
        if let last = unacked.last, Sequence.lessThan(segment.sequenceNumber, last.sequenceNumber) {
            unacked.insertOrdered(segment)
        } else {
            unacked.append(segment)
        }
    }

    private func moveFirstUnackedToUnsent() -> Bool {
        guard let segment = unacked.first else { return false }
        _ = unacked.removeFirst()
        unsent.insertOrdered(segment)
        if unsent.last == segment {
            unsentOversize = 0
        }
        if nrtx < UInt8.max {
            nrtx += 1
        }
        rttest = 0
        return true
    }

    private func fastRetransmit() {
        guard !unacked.isEmpty, !flags.contains(.inFastRecovery) else { return }
        if moveFirstUnackedToUnsent() {
            flags.insert(.inFastRecovery)
            rtoStart = stack.ticks
        }
    }

    private func prepareRetransmission() -> Bool {
        guard let last = unacked.last else { return false }
        unsent.prepend(contentsOf: unacked.detachAll())
        flags.insert(.rto)
        rtoEnd = last.sequenceNumber &+ last.tcpLength
        rttest = 0
        return true
    }

    private func splitFirstUnsent(at split: Int) -> Bool {
        guard let head = unsent.first, split > 0 else { return false }
        guard head.length > split else { return true }
        var remainderFlags: TCPHeader.Flags = []
        if head.flags.contains(.psh) {
            head.flags.remove(.psh)
            remainderFlags.insert(.psh)
        }
        if head.flags.contains(.fin) {
            head.flags.remove(.fin)
            remainderFlags.insert(.fin)
        }
        let segment = arena.allocate(sequenceNumber: head.sequenceNumber &+ UInt32(split), flags: remainderFlags)
        segment.setPayload(UnsafeRawBufferPointer(rebasing: head.payload[split...]))
        head.truncatePayload(to: split)
        unsent.insert(segment, after: head)
        if unsent.last == segment {
            unsentOversize = 0
        }
        return true
    }

    private func zeroWindowProbe() {
        guard let head = unsent.first else { return }
        if persistProbes < UInt8.max {
            persistProbes += 1
        }
        let offset = Int(lastAck &- head.sequenceNumber)
        let isFin = offset == head.length
        guard offset < head.length || (isFin && head.flags.contains(.fin)) else { return }
        let probe = arena.allocate(sequenceNumber: lastAck, flags: isFin ? [.ack, .fin] : [.ack])
        if !isFin {
            probe.setPayload(UnsafeRawBufferPointer(rebasing: head.payload[offset..<(offset + 1)]))
        }
        let next = lastAck &+ 1
        if Sequence.lessThan(sndNxt, next) {
            sndNxt = next
        }
        rcvAnnRightEdge = rcvNxt &+ rcvAnnWnd
        acknowledgmentHeld = false
        stack.transmit(probe, acknowledgmentNumber: rcvNxt, window: announcedWindow)
    }

    func slowTick(ticks: UInt32) {
        var remove = false
        if nrtx >= Constants.maximumRetransmissions {
            remove = true
        } else if persistBackoff > 0 {
            if persistProbes >= Constants.maximumRetransmissions {
                remove = true
            } else if ticks &- persistStart >= UInt32(Constants.persistBackoff[Int(persistBackoff) - 1]) {
                var nextSlot = true
                if sndWnd == 0 {
                    zeroWindowProbe()
                } else if splitFirstUnsent(at: Int(min(sndWnd, 0xFFFF))) {
                    output()
                    nextSlot = false
                }
                if nextSlot {
                    persistStart = ticks
                    if persistBackoff < UInt8(Constants.persistBackoff.count) {
                        persistBackoff += 1
                    }
                }
            }
        } else if let start = rtoStart, Int(ticks &- start) >= Int(rto) {
            if prepareRetransmission() || (unacked.isEmpty && !unsent.isEmpty) {
                let backoff = Constants.retransmissionBackoff[min(Int(nrtx), Constants.retransmissionBackoff.count - 1)]
                rto = Int16(min(Int32((sa >> 3) &+ sv) << Int32(backoff), Int32(Int16.max)))
                rtoStart = ticks
                if nrtx < UInt8.max {
                    nrtx += 1
                }
                output()
            }
        }
        if state == .finWait2, flags.contains(.receiveClosed), ticks &- tmr > Constants.finWait2Timeout {
            remove = true
        }
        if state == .synReceived, ticks &- tmr > Constants.synReceivedTimeout {
            remove = true
        }
        if state == .lastAck, ticks &- tmr > Constants.lastAckTimeout {
            remove = true
        }
        if remove {
            terminate(sendingReset: false, error: .aborted)
        } else {
            output()
        }
    }

    var nextDeadline: UInt32? {
        var deadline: UInt32?
        func include(_ start: UInt32, after interval: UInt32) {
            let candidate = TickClock.align(start, after: interval)
            if deadline.map({ Sequence.lessThan(candidate, $0) }) ?? true { deadline = candidate }
        }
        switch state {
        case .closed:
            return nil
        case .timeWait:
            include(tmr, after: Constants.timeWaitTimeout + 1)
            return deadline
        case .synReceived:
            include(tmr, after: Constants.synReceivedTimeout + 1)
        case .finWait2 where flags.contains(.receiveClosed):
            include(tmr, after: Constants.finWait2Timeout + 1)
        case .lastAck:
            include(tmr, after: Constants.lastAckTimeout + 1)
        default:
            break
        }
        if nrtx >= Constants.maximumRetransmissions {
            include(stack.ticks, after: 0)
        } else if persistBackoff > 0 {
            if persistProbes >= Constants.maximumRetransmissions {
                include(stack.ticks, after: 0)
            } else {
                include(persistStart, after: UInt32(Constants.persistBackoff[Int(persistBackoff) - 1]))
            }
        } else if let rtoStart, !unacked.isEmpty || !unsent.isEmpty {
            include(rtoStart, after: UInt32(max(0, rto)))
        }
        return deadline
    }

    func timeWaitInput(header: TCPHeader, payloadCount: Int) {
        if header.flags.contains(.rst) { return }
        let tcpLength = UInt32(payloadCount) + (header.flags.contains(.syn) || header.flags.contains(.fin) ? 1 : 0)
        if header.flags.contains(.syn) {
            if Sequence.between(header.sequenceNumber, rcvNxt, rcvNxt &+ rcvWnd) {
                sendReset(sequenceNumber: header.acknowledgmentNumber, acknowledgmentNumber: header.sequenceNumber &+ tcpLength)
                return
            }
        } else if header.flags.contains(.fin) {
            tmr = stack.ticks
        }
        if tcpLength > 0 {
            flags.insert(.ackNow)
            sendEmptyAck(stack)
        }
    }

    func input(header: TCPHeader, options: UnsafeRawBufferPointer, payload: UnsafeRawBufferPointer) {
        let seqno = header.sequenceNumber
        let ackno = header.acknowledgmentNumber
        let segmentFlags = header.flags
        var tcpLength = UInt32(payload.count) + (segmentFlags.contains(.syn) || segmentFlags.contains(.fin) ? 1 : 0)
        var received: ReceiveFlags = []
        var acked: UInt32 = 0
        var data: UnsafeRawBufferPointer?
        let stack = self.stack
        isProcessingInput = true
        defer { isProcessingInput = false }

        if segmentFlags.contains(.rst) {
            if seqno == rcvNxt {
                purge()
                state = .closed
                stack.effects.append(.removed)
                detach()
                stack.effects.append(.failed(.reset))
                return
            }
            if Sequence.between(seqno, rcvNxt, rcvNxt &+ rcvWnd) {
                flags.insert(.ackNow)
            }
            finishInput(stack)
            return
        }
        if segmentFlags.contains(.syn), state != .synReceived {
            flags.insert(.ackNow)
            finishInput(stack)
            return
        }
        if !flags.contains(.receiveClosed) {
            tmr = stack.ticks
        }
        persistProbes = 0
        if segmentFlags.contains(.syn) {
            parseOptions(options)
        }

        switch state {
        case .synReceived:
            if segmentFlags.contains(.syn) {
                if seqno == rcvNxt &- 1 {
                    _ = moveFirstUnackedToUnsent()
                }
            } else if segmentFlags.contains(.ack) {
                if Sequence.between(ackno, lastAck &+ 1, sndNxt) {
                    state = .established
                    stack.effects.append(.ready)
                    receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
                    if acked != 0 {
                        acked -= 1
                    }
                    if received.contains(.gotFin) {
                        flags.insert(.ackNow)
                        state = .closeWait
                    }
                } else {
                    sendReset(sequenceNumber: ackno, acknowledgmentNumber: seqno &+ tcpLength)
                }
            }
        case .established, .closeWait:
            receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
            if received.contains(.gotFin) {
                flags.insert(.ackNow)
                state = .closeWait
            }
        case .finWait1:
            receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
            if received.contains(.gotFin) {
                flags.insert(.ackNow)
                if segmentFlags.contains(.ack), ackno == sndNxt, unsent.isEmpty {
                    enterTimeWait()
                } else {
                    state = .closing
                }
            } else if segmentFlags.contains(.ack), ackno == sndNxt, unsent.isEmpty {
                state = .finWait2
            }
        case .finWait2:
            receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
            if received.contains(.gotFin) {
                flags.insert(.ackNow)
                enterTimeWait()
            }
        case .closing:
            receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
            if segmentFlags.contains(.ack), ackno == sndNxt, unsent.isEmpty {
                enterTimeWait()
            }
        case .lastAck:
            receive(header: header, payload: payload, sequenceNumber: seqno, tcpLength: &tcpLength, received: &received, acked: &acked, data: &data, stack: stack)
            if segmentFlags.contains(.ack), ackno == sndNxt, unsent.isEmpty {
                received.insert(.closed)
            }
        case .timeWait, .closed:
            break
        }

        if acked > 0 {
            stack.effects.append(.acknowledged(Int(acked)))
            if state == .closed { return }
        }
        if received.contains(.closed) {
            purge()
            state = .closed
            stack.effects.append(.removed)
            if isAttached, !flags.contains(.receiveClosed) {
                detach()
                stack.effects.append(.ended)
            }
            return
        }
        if let data {
            if flags.contains(.receiveClosed) {
                terminate(sendingReset: true, error: nil)
                return
            }
            stack.receive(data, push: received.contains(.push))
            if state == .closed { return }
        }
        if received.contains(.gotFin) {
            if rcvWnd != windowMax {
                rcvWnd += 1
            }
            stack.effects.append(.fin)
            if state == .closed { return }
        }
        finishInput(stack)
    }

    private func finishInput(_ stack: Context) {
        isProcessingInput = false
        if closeAfterInput {
            closeAfterInput = false
            terminate(sendingReset: true, error: nil)
            return
        }
        if state == .timeWait {
            if flags.contains(.ackNow) {
                sendEmptyAck(stack)
            }
            return
        }
        if !stack.batching { output() }
    }

    private func receive(
        header: TCPHeader,
        payload: UnsafeRawBufferPointer,
        sequenceNumber: UInt32,
        tcpLength: inout UInt32,
        received: inout ReceiveFlags,
        acked: inout UInt32,
        data: inout UnsafeRawBufferPointer?,
        stack: Context
    ) {
        let ackno = header.acknowledgmentNumber
        var seqno = sequenceNumber
        var segmentFlags = header.flags
        var dataOffset = 0
        var dataLength = payload.count

        if segmentFlags.contains(.ack) {
            let rightWindowEdge = sndWnd &+ sndWl2
            let scaledWindow = UInt32(header.window) << UInt32(sndScale)
            if Sequence.lessThan(sndWl1, seqno)
                || (sndWl1 == seqno && Sequence.lessThan(sndWl2, ackno))
                || (sndWl2 == ackno && scaledWindow > sndWnd) {
                sndWnd = scaledWindow
                if sndWndMax < sndWnd {
                    sndWndMax = sndWnd
                }
                sndWl1 = seqno
                sndWl2 = ackno
            }
            if Sequence.lessThanOrEqual(ackno, lastAck) {
                if tcpLength == 0, sndWl2 &+ sndWnd == rightWindowEdge, rtoStart != nil, lastAck == ackno {
                    if dupacks < UInt8.max {
                        dupacks += 1
                    }
                    if dupacks >= 3 {
                        fastRetransmit()
                    }
                }
            } else if Sequence.between(ackno, lastAck &+ 1, sndNxt) {
                flags.remove(.inFastRecovery)
                nrtx = 0
                rto = (sa >> 3) &+ sv
                dupacks = 0
                lastAck = ackno
                acked += freeAcknowledged(&unacked)
                acked += freeAcknowledged(&unsent)
                acked += releaseAcknowledgedPrefix(of: unacked.first)
                acked += releaseAcknowledgedPrefix(of: unsent.first)
                if unsent.isEmpty {
                    unsentOversize = 0
                }
                rtoStart = unacked.isEmpty ? nil : stack.ticks
                sndBuf += acked
                if flags.contains(.rto), (unacked.first ?? unsent.first).map({ Sequence.lessThanOrEqual(rtoEnd, $0.sequenceNumber) }) ?? true {
                    flags.remove(.rto)
                }
            } else {
                sendEmptyAck(stack)
            }
            if rttest != 0, Sequence.lessThan(rtseq, ackno) {
                var m = Int16(truncatingIfNeeded: stack.ticks &- rttest)
                m = m &- (sa >> 3)
                sa = sa &+ m
                if m < 0 {
                    m = 0 &- m
                }
                m = m &- (sv >> 2)
                sv = sv &+ m
                rto = (sa >> 3) &+ sv
                rttest = 0
            }
        }

        if tcpLength > 0, state < .closeWait {
            if Sequence.between(rcvNxt, seqno &+ 1, seqno &+ tcpLength &- 1) {
                let offset = Int(rcvNxt &- seqno)
                dataOffset += offset
                dataLength -= offset
                seqno = rcvNxt
            } else if Sequence.lessThan(seqno, rcvNxt) {
                flags.insert(.ackNow)
            }
            if Sequence.between(seqno, rcvNxt, rcvNxt &+ rcvWnd &- 1) {
                if rcvNxt == seqno {
                    tcpLength = UInt32(dataLength) + (segmentFlags.contains(.syn) || segmentFlags.contains(.fin) ? 1 : 0)
                    if tcpLength > rcvWnd {
                        segmentFlags.remove(.fin)
                        segmentFlags.remove(.psh)
                        dataLength = Int(rcvWnd)
                        if segmentFlags.contains(.syn) {
                            dataLength -= 1
                        }
                        tcpLength = UInt32(dataLength) + (segmentFlags.contains(.syn) ? 1 : 0)
                    }
                    rcvNxt = seqno &+ tcpLength
                    rcvWnd -= tcpLength
                    updateAnnouncedWindow()
                    if dataLength > 0 {
                        data = UnsafeRawBufferPointer(rebasing: payload[dataOffset..<(dataOffset + dataLength)])
                        if segmentFlags.contains(.psh) {
                            received.insert(.push)
                        }
                    }
                    if segmentFlags.contains(.fin) {
                        received.insert(.gotFin)
                    }
                    if delaysAcknowledgment, !acknowledgmentHeld, state == .established, dataLength >= receiveMSS,
                       segmentFlags.isDisjoint(with: [.psh, .fin]), rcvWnd >= windowMax / 2 {
                        acknowledgmentHeld = true
                    } else {
                        flags.insert(.ackNow)
                    }
                } else {
                    sendEmptyAck(stack)
                }
            } else {
                sendEmptyAck(stack)
            }
        } else if !Sequence.between(seqno, rcvNxt, rcvNxt &+ rcvWnd &- 1) {
            flags.insert(.ackNow)
        }
    }

    private func releaseAcknowledgedPrefix(of segment: Segment?) -> UInt32 {
        guard let segment, Sequence.lessThan(segment.sequenceNumber, lastAck) else { return 0 }
        let count = Int(lastAck &- segment.sequenceNumber)
        guard count <= segment.length else { return 0 }
        segment.dropPayloadPrefix(count)
        return UInt32(count)
    }

    private func freeAcknowledged(_ queue: inout SegmentList) -> UInt32 {
        var freed: UInt32 = 0
        while let first = queue.first, Sequence.lessThanOrEqual(first.sequenceNumber &+ first.tcpLength, lastAck) {
            freed += UInt32(first.length)
            _ = queue.removeFirst()
            arena.recycle(first)
        }
        return freed
    }
}
