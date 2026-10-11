//
//  QUICStreamID.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

public struct QUICStreamID: Hashable, Sendable {
    public var rawValue: UInt64

    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    public init(index: UInt64, bidirectional: Bool, clientInitiated: Bool) {
        self.rawValue = index << 2 | (clientInitiated ? 0 : 1) | (bidirectional ? 0 : 2)
    }

    public var isBidirectional: Bool { self.rawValue & 0x2 == 0 }
    public var isUnidirectional: Bool { !self.isBidirectional }
    public var isClientInitiated: Bool { self.rawValue & 0x1 == 0 }
    public var isServerInitiated: Bool { !self.isClientInitiated }
    public var index: UInt64 { self.rawValue >> 2 }

    public var ordinal: UInt64 { self.index + 1 }
}

extension QUICStreamID: Comparable {
    public static func < (lhs: QUICStreamID, rhs: QUICStreamID) -> Bool {
        return lhs.rawValue < rhs.rawValue
    }
}

extension QUICStreamID: CustomStringConvertible {
    public var description: String {
        return String(self.rawValue)
    }
}

extension QUICStreamID: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: UInt64) {
        self.rawValue = value
    }
}
