//
//  PathValidation.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct PathValidation {
    static let maxEntries = 8
    static let probesPerRound = 2
    static let maxRound = 10

    struct Entry {
        var data: UInt64
        var expiry: Nanoseconds
    }

    var connectionID: RemoteConnectionID
    var path: QUICPath
    var entries: [Entry] = []
    var timeout: Nanoseconds
    var startedAt: Nanoseconds = Time.never
    var round = 0
    var probesLeft = Self.probesPerRound
    var isTimerCancelled = false
    var ignoresResult = false

    init(connectionID: RemoteConnectionID, path: QUICPath, timeout: Nanoseconds, ignoresResult: Bool = false) {
        self.connectionID = connectionID
        self.path = path
        self.timeout = timeout
        self.ignoresResult = ignoresResult
    }

    mutating func addEntry(data: UInt64, expiry: Nanoseconds, now: Nanoseconds) {
        precondition(self.probesLeft > 0)
        if self.entries.isEmpty {
            self.startedAt = now
        }
        self.entries.append(Entry(data: data, expiry: expiry))
        if self.entries.count > Self.maxEntries {
            self.entries.removeFirst()
        }
        self.isTimerCancelled = false
        self.probesLeft -= 1
    }

    func validate(_ data: UInt64) -> Bool {
        return self.entries.contains { $0.data == data }
    }

    mutating func handleEntryExpiry(now: Nanoseconds) {
        guard let last = self.entries.last, last.expiry <= now else {
            return
        }
        self.round = Swift.min(self.round + 1, Self.maxRound)
        self.probesLeft = Self.probesPerRound
    }

    var shouldSendProbe: Bool { self.probesLeft > 0 }

    func hasTimedOut(now: Nanoseconds) -> Bool {
        guard self.startedAt != Time.never, let last = self.entries.last else {
            return false
        }
        let deadline = Swift.max(self.startedAt.addingClamped(self.timeout), last.expiry)
        return deadline <= now
    }

    var nextExpiry: Nanoseconds {
        guard !self.isTimerCancelled, let last = self.entries.last else {
            return Time.never
        }
        return last.expiry
    }

    mutating func cancelExpiredTimer(now: Nanoseconds) {
        guard self.nextExpiry <= now else {
            return
        }
        self.isTimerCancelled = true
    }
}

struct PMTUDiscovery {
    static let maxProbesPerSize = 3

    private let probes: [UInt16]
    private var index = 0
    private var packetsSent = 0
    private(set) var expiry: Nanoseconds = Time.never
    let firstPacketNumber: UInt64
    private(set) var currentMaxUDPPayloadSize: Int
    private let hardMaxUDPPayloadSize: Int
    private var minimumFailedSize = Int.max

    init(probes: [UInt16], currentMaxUDPPayloadSize: Int, hardMaxUDPPayloadSize: Int, firstPacketNumber: UInt64) {
        self.probes = probes.isEmpty ? QUICSettings.defaultPMTUDProbes : probes
        self.currentMaxUDPPayloadSize = currentMaxUDPPayloadSize
        self.hardMaxUDPPayloadSize = hardMaxUDPPayloadSize
        self.firstPacketNumber = firstPacketNumber
        while self.index < self.probes.count {
            let probe = Int(self.probes[self.index])
            if probe > hardMaxUDPPayloadSize {
                self.index += 1
                continue
            }
            if probe > currentMaxUDPPayloadSize {
                break
            }
            self.index += 1
        }
    }

    var isFinished: Bool { self.index >= self.probes.count }

    var probeLength: Int {
        precondition(!self.isFinished)
        return Int(self.probes[self.index])
    }

    var requiresProbe: Bool { self.expiry == Time.never }

    mutating func probeSent(pto: Nanoseconds, now: Nanoseconds) {
        self.packetsSent += 1
        let timeout = self.packetsSent < Self.maxProbesPerSize ? pto : 3 * pto
        self.expiry = now.addingClamped(timeout)
    }

    private mutating func advance() {
        self.index += 1
        self.packetsSent = 0
        self.expiry = Time.never
        while self.index < self.probes.count {
            let probe = Int(self.probes[self.index])
            if probe <= self.currentMaxUDPPayloadSize || probe > self.hardMaxUDPPayloadSize {
                self.index += 1
                continue
            }
            if probe < self.minimumFailedSize {
                break
            }
            self.index += 1
        }
    }

    mutating func probeSucceeded(size: Int) {
        self.currentMaxUDPPayloadSize = Swift.max(self.currentMaxUDPPayloadSize, size)
        guard !self.isFinished, self.probeLength <= self.currentMaxUDPPayloadSize else {
            return
        }
        self.advance()
    }

    mutating func handleExpiry(now: Nanoseconds) {
        guard self.expiry != Time.never, self.expiry <= now else {
            return
        }
        self.expiry = Time.never
        guard self.packetsSent >= Self.maxProbesPerSize else {
            return
        }
        self.minimumFailedSize = Swift.min(self.minimumFailedSize, self.probeLength)
        self.advance()
    }
}
