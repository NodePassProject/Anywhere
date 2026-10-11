//
//  ConnectionIDs.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct LocalConnectionID {
    var id: QUICConnectionID
    var sequence: UInt64
    var token: QUICStatelessResetToken
    var isUsed = false
    var retiredAt: Nanoseconds?

    var isRetired: Bool { self.retiredAt != nil }
}

struct RemoteConnectionID: Equatable {
    var id: QUICConnectionID
    var sequence: UInt64
    var token: QUICStatelessResetToken?
}

struct ActivePath {
    var connectionID: RemoteConnectionID
    var path: QUICPath
    var isValidated: Bool
    var maxUDPPayloadSize: Int
    var bytesSent: UInt64 = 0
    var bytesReceived: UInt64 = 0
}

struct RetiredRemoteConnectionID {
    var connectionID: RemoteConnectionID
    var path: QUICPath
    var retiredAt: Nanoseconds
}

struct DestinationIDTracker {
    static let maxUnused = 8
    static let maxRetired = 2
    static let maxTrackedSequences = 32
    static let maxRetireSequencesInFlight = Self.maxUnused * 2

    private(set) var unused: [RemoteConnectionID] = []
    private(set) var retired: [RetiredRemoteConnectionID] = []
    var retirePriorTo: UInt64 = 0
    private(set) var seenSequences = RangeSet()
    private(set) var retireSequencesInFlight = RangeSet()

    var hasUnused: Bool { !self.unused.isEmpty }
    var unusedCount: Int { self.unused.count }

    mutating func markSeen(_ sequence: UInt64) -> Bool {
        if self.seenSequences.contains(sequence) {
            return false
        }
        self.seenSequences.insert(sequence)
        if self.seenSequences.count > Self.maxTrackedSequences {
            self.seenSequences.fillFirstGap()
        }
        return true
    }

    mutating func pushUnused(_ id: RemoteConnectionID) {
        self.unused.append(id)
    }

    mutating func popUnused() -> RemoteConnectionID? {
        return self.unused.isEmpty ? nil : self.unused.removeFirst()
    }

    mutating func retireUnused(priorTo sequence: UInt64) -> [UInt64] {
        var retiredSequences: [UInt64] = []
        self.unused.removeAll { candidate in
            if candidate.sequence < sequence {
                retiredSequences.append(candidate.sequence)
                return true
            }
            return false
        }
        return retiredSequences
    }

    mutating func addRetired(_ id: RemoteConnectionID, path: QUICPath, now: Nanoseconds) {
        self.retired.append(RetiredRemoteConnectionID(connectionID: id, path: path, retiredAt: now))
        if self.retired.count > Self.maxRetired {
            self.retired.removeFirst()
        }
    }

    mutating func removeStaleRetired(timeout: Nanoseconds, now: Nanoseconds) {
        self.retired.removeAll { Time.elapsed($0.retiredAt, timeout, now) }
    }

    func isRetiredPath(_ path: QUICPath) -> Bool {
        return self.retired.contains { $0.path == path }
    }

    mutating func trackRetireSequence(_ sequence: UInt64) -> Bool {
        if self.retireSequencesInFlight.contains(sequence) {
            return false
        }
        self.retireSequencesInFlight.insert(sequence)
        return true
    }

    var isRetireSequenceLimitExceeded: Bool {
        return self.retireSequencesInFlight.totalLength > UInt64(Self.maxRetireSequencesInFlight)
    }

    mutating func untrackRetireSequence(_ sequence: UInt64) {
        self.retireSequencesInFlight.remove(sequence..<sequence + 1)
    }

    func verifyUniqueness(
        sequence: UInt64,
        id: QUICConnectionID,
        token: QUICStatelessResetToken,
        against candidate: RemoteConnectionID
    ) -> Bool {
        if candidate.sequence == sequence {
            return candidate.id == id && candidate.token == token
        }
        return candidate.id != id
    }

    func verifyUniqueness(
        sequence: UInt64,
        id: QUICConnectionID,
        token: QUICStatelessResetToken
    ) -> (ok: Bool, found: Bool) {
        var found = false
        for candidate in self.unused {
            guard self.verifyUniqueness(sequence: sequence, id: id, token: token, against: candidate) else {
                return (false, false)
            }
            if candidate.id == id {
                found = true
            }
        }
        for candidate in self.retired {
            guard self.verifyUniqueness(sequence: sequence, id: id, token: token, against: candidate.connectionID) else {
                return (false, false)
            }
            if candidate.connectionID.id == id {
                found = true
            }
        }
        return (true, found)
    }

    var nextRetirementExpiry: Nanoseconds {
        return self.retired.first?.retiredAt ?? Time.never
    }
}
