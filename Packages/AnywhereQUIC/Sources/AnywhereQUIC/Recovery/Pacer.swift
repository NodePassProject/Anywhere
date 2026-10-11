//
//  Pacer.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct Pacer {
    private(set) var nextSendTime: Nanoseconds = Time.never
    private(set) var pendingBytes = 0
    private var compensation: Nanoseconds = 0

    func allowsSending(at now: Nanoseconds) -> Bool {
        return self.nextSendTime == Time.never || self.nextSendTime <= now
    }

    mutating func cancelExpired(at now: Nanoseconds) {
        guard self.nextSendTime != Time.never, self.nextSendTime <= now else {
            return
        }
        if now > self.nextSendTime {
            self.compensation = self.compensation.addingClamped(now - self.nextSendTime)
        }
        self.nextSendTime = Time.never
    }

    mutating func recordSent(bytes: Int) {
        self.pendingBytes += bytes
    }

    mutating func finishBatch(now: Nanoseconds, pacingRate: UInt64, sendQuantum: Int) {
        guard self.pendingBytes > 0 else {
            return
        }
        defer {
            self.pendingBytes = 0
        }
        guard pacingRate > 0 else {
            self.nextSendTime = self.pendingBytes >= sendQuantum ? now : Time.never
            return
        }
        let wait = UInt64(self.pendingBytes).multipliedFullWidth(by: Time.second)
        var waitNanoseconds = pacingRate == 0 ? 0 : wait.high == 0 ? wait.low / pacingRate : (UInt64.max / pacingRate)
        if wait.high != 0 {
            waitNanoseconds = UInt64(Double(self.pendingBytes) * Double(Time.second) / Double(pacingRate))
        }
        let discount = Swift.min(waitNanoseconds / 2, self.compensation)
        waitNanoseconds -= discount
        self.compensation -= discount
        self.nextSendTime = now.addingClamped(waitNanoseconds)
    }

    mutating func reset() {
        self.nextSendTime = Time.never
        self.compensation = 0
        self.pendingBytes = 0
    }
}
