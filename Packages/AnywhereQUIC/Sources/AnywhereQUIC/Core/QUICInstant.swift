//
//  QUICInstant.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Dispatch
#if canImport(Darwin)
import Darwin
#endif

public struct QUICInstant: Hashable, Sendable {
    public static let distantFuture = QUICInstant(nanoseconds: .max)

    public var nanoseconds: UInt64

    public init(nanoseconds: UInt64) {
        self.nanoseconds = nanoseconds
    }

    public static var now: QUICInstant {
        return QUICInstant(nanoseconds: DispatchTime.now().uptimeNanoseconds)
    }

    public static var continuousNow: QUICInstant {
        #if canImport(Darwin)
        return QUICInstant(nanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC))
        #else
        return Self.now
        #endif
    }

    public static func + (lhs: QUICInstant, rhs: Duration) -> QUICInstant {
        return QUICInstant(nanoseconds: lhs.nanoseconds.addingClamped(rhs.clampedNanoseconds))
    }

    public static func - (lhs: QUICInstant, rhs: Duration) -> QUICInstant {
        return QUICInstant(nanoseconds: lhs.nanoseconds.subtractingClamped(rhs.clampedNanoseconds))
    }

    public func duration(since earlier: QUICInstant) -> Duration {
        return Duration.nanoseconds(Int64(clamping: self.nanoseconds.subtractingClamped(earlier.nanoseconds)))
    }
}

extension QUICInstant: Comparable {
    public static func < (lhs: QUICInstant, rhs: QUICInstant) -> Bool {
        return lhs.nanoseconds < rhs.nanoseconds
    }
}

typealias Nanoseconds = UInt64

enum Time {
    static let nanosecond: Nanoseconds = 1
    static let microsecond: Nanoseconds = 1_000
    static let millisecond: Nanoseconds = 1_000_000
    static let second: Nanoseconds = 1_000_000_000
    static let never: Nanoseconds = .max

    static func elapsed(_ base: Nanoseconds, _ duration: Nanoseconds, _ now: Nanoseconds) -> Bool {
        return base != Self.never && base.addingClamped(duration) <= now
    }

    static func notElapsed(_ base: Nanoseconds, _ duration: Nanoseconds, _ now: Nanoseconds) -> Bool {
        return base != Self.never && base.addingClamped(duration) > now
    }
}

extension UInt64 {
    func addingClamped(_ other: UInt64) -> UInt64 {
        let (result, overflow) = self.addingReportingOverflow(other)
        return overflow ? .max : result
    }

    func subtractingClamped(_ other: UInt64) -> UInt64 {
        return self > other ? self - other : 0
    }
}

extension Duration {
    var clampedNanoseconds: Nanoseconds {
        if self <= .zero {
            return 0
        }
        let (seconds, attoseconds) = self.components
        if seconds >= Int64(UInt64.max / Time.second) {
            return .max
        }
        return UInt64(seconds) * Time.second + UInt64(attoseconds / 1_000_000_000)
    }

    init(nanoseconds: Nanoseconds) {
        self = .nanoseconds(Int64(clamping: nanoseconds))
    }
}
