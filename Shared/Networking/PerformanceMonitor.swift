//
//  PerformanceMonitor.swift
//  Anywhere
//
//  Created by NodePassProject on 6/9/26.
//

import Foundation

/// Debug-only instrument for the data plane: timed spans, sampled gauges, and
/// overwhelm counters, opt-in by category. The lock is a leaf lock never held
/// across timed work or logging, so nested spans cannot self-deadlock.
nonisolated final class PerformanceMonitor: @unchecked Sendable {

    // MARK: - Category (the print/enable filter)

    /// Gates recording and printing; enable via `defaultEnabledCategories` or
    /// the `ANYWHERE_PERF` env var.
    struct Category: OptionSet, Sendable {
        let rawValue: Int
        static let socket       = Category(rawValue: 1 << 0)
        static let tls          = Category(rawValue: 1 << 1)
        static let proxy        = Category(rawValue: 1 << 2)
        static let routing      = Category(rawValue: 1 << 3)
        static let mitm         = Category(rawValue: 1 << 4)
        /// Per-connection TCP pipeline health (backlogs, stalls).
        static let pipeline     = Category(rawValue: 1 << 5)
        /// System-wide overwhelm (output queue depth, UDP flow table, drops).
        static let backpressure = Category(rawValue: 1 << 6)

        static let all: Category = [
            .socket, .tls, .proxy, .routing, .mitm, .pipeline, .backpressure
        ]
    }

    // MARK: - Component (timed spans)

    /// A timed stage in the send/receive path.
    enum Component: Int, CaseIterable, Sendable {
        case socketSendTCP
        case socketReceiveTCP
        case socketSendUDP
        case socketReceiveUDP
        case socketSendQUIC
        case socketReceiveQUIC
        case tlsEncrypt
        case tlsDecrypt
        case tlsHandshake
        case proxyHandshake
        case proxySend
        case proxyReceive
        case routingDomain
        case routingIP
        case mitmRewrite
        case mitmScript

        var category: Category {
            switch self {
            case .socketSendTCP, .socketReceiveTCP, .socketSendUDP,
                 .socketReceiveUDP, .socketSendQUIC, .socketReceiveQUIC:
                return .socket
            case .tlsEncrypt, .tlsDecrypt, .tlsHandshake:
                return .tls
            case .proxyHandshake, .proxySend, .proxyReceive:
                return .proxy
            case .routingDomain, .routingIP:
                return .routing
            case .mitmRewrite, .mitmScript:
                return .mitm
            }
        }

        var displayName: String {
            switch self {
            case .socketSendTCP:     return "socket.send.tcp"
            case .socketReceiveTCP:  return "socket.recv.tcp"
            case .socketSendUDP:     return "socket.send.udp"
            case .socketReceiveUDP:  return "socket.recv.udp"
            case .socketSendQUIC:    return "socket.send.quic"
            case .socketReceiveQUIC: return "socket.recv.quic"
            case .tlsEncrypt:        return "tls.encrypt"
            case .tlsDecrypt:        return "tls.decrypt"
            case .tlsHandshake:      return "tls.handshake"
            case .proxyHandshake:    return "proxy.handshake"
            case .proxySend:         return "proxy.send"
            case .proxyReceive:      return "proxy.recv"
            case .routingDomain:     return "routing.domain"
            case .routingIP:         return "routing.ip"
            case .mitmRewrite:       return "mitm.rewrite"
            case .mitmScript:        return "mitm.script"
            }
        }

        /// Spans slower than this log a rate-limited warning; `.max` disables
        /// it for network-bound spans that legitimately wait on the wire.
        var slowThresholdNanos: UInt64 {
            switch self {
            case .socketSendTCP, .socketReceiveTCP, .socketSendUDP,
                 .socketReceiveUDP, .socketSendQUIC, .socketReceiveQUIC:
                return 2_000_000          // 2 ms — non-blocking syscall
            case .tlsEncrypt, .tlsDecrypt:
                return 1_000_000          // 1 ms per record
            case .routingDomain, .routingIP:
                return 500_000            // 500 µs
            case .mitmRewrite:
                return 5_000_000          // 5 ms per rewrite pass
            case .mitmScript:
                return 5_000_000_000      // 5 s — MITMScriptWatchdog owns the hard cap
            case .tlsHandshake, .proxyHandshake, .proxySend, .proxyReceive:
                return .max               // network-bound: aggregate, never warn
            }
        }
    }

    // MARK: - Gauge (sampled levels)

    /// A sampled level (backlog, queue depth). High-water thresholds come from
    /// call sites so this `Shared` type stays free of NE-only symbols.
    enum Gauge: Int, CaseIterable, Sendable {
        case tcpDownlinkBacklog
        case tcpUploadBacklog
        case outputQueueDepth
        case udpFlowCount
        case udpFlowPendingBytes

        var category: Category {
            switch self {
            case .tcpDownlinkBacklog, .tcpUploadBacklog:
                return .pipeline
            case .outputQueueDepth, .udpFlowCount, .udpFlowPendingBytes:
                return .backpressure
            }
        }

        var displayName: String {
            switch self {
            case .tcpDownlinkBacklog:  return "tcp.downlink.backlog"
            case .tcpUploadBacklog:    return "tcp.upload.backlog"
            case .outputQueueDepth:    return "output.queue.depth"
            case .udpFlowCount:        return "udp.flow.count"
            case .udpFlowPendingBytes: return "udp.flow.pending.bytes"
            }
        }
    }

    // MARK: - Event (overwhelm counters)

    /// A counted overwhelm incident (drop, stall retry, eviction).
    enum Event: Int, CaseIterable, Sendable {
        case downlinkStallRetry
        case lwipWriteFatal
        case pendingDataCapAbort
        case udpBufferOverflow
        case udpFlowEvicted

        var category: Category {
            switch self {
            case .downlinkStallRetry, .lwipWriteFatal, .pendingDataCapAbort:
                return .pipeline
            case .udpBufferOverflow, .udpFlowEvicted:
                return .backpressure
            }
        }

        var displayName: String {
            switch self {
            case .downlinkStallRetry:  return "downlink.stall.retry"
            case .lwipWriteFatal:      return "lwip.write.fatal"
            case .pendingDataCapAbort: return "pending.data.cap.abort"
            case .udpBufferOverflow:   return "udp.buffer.overflow"
            case .udpFlowEvicted:      return "udp.flow.evicted"
            }
        }
    }

    // MARK: - Configuration (what prints)

    /// Edit to control what prints (empty = silent); `ANYWHERE_PERF` overrides.
    static let defaultEnabledCategories: Category = []

    /// Resolved once at launch; always empty in release.
    static let enabledCategories: Category = {
        #if DEBUG
        return Category.resolveFromEnvironment(default: defaultEnabledCategories)
        #else
        return []
        #endif
    }()

    // MARK: - Public API — spans

    /// Times `body` as a span; in release (or a disabled category) this is exactly `body()`.
    @inline(__always)
    static func measure<T>(_ component: Component, _ body: () throws -> T) rethrows -> T {
        #if DEBUG
        guard enabledCategories.contains(component.category) else { return try body() }
        let start = PerfClock.nowTicks
        let result = try body()
        shared.recordSpan(component, elapsedTicks: PerfClock.nowTicks &- start)
        return result
        #else
        return try body()
        #endif
    }

    /// Opens a span across a completion-handler boundary; balance with exactly one `stop()`.
    @inline(__always)
    static func span(_ component: Component) -> Span {
        #if DEBUG
        return Span(component: component, startTicks: PerfClock.nowTicks)
        #else
        return Span()
        #endif
    }

    /// A half-open span token; zero-size in release so the optimizer elides it.
    struct Span: Sendable {
        #if DEBUG
        fileprivate let component: Component
        fileprivate let startTicks: UInt64
        #endif

        @inline(__always)
        func stop() {
            #if DEBUG
            guard PerformanceMonitor.enabledCategories.contains(component.category) else { return }
            PerformanceMonitor.shared.recordSpan(component, elapsedTicks: PerfClock.nowTicks &- startTicks)
            #endif
        }
    }

    // MARK: - Public API — gauges & events

    /// Samples a gauge; `highWater > 0` arms a rising-edge warning. No-op in release.
    @inline(__always)
    static func gauge(_ gauge: Gauge, _ value: Int, highWater: Int = 0) {
        #if DEBUG
        guard enabledCategories.contains(gauge.category) else { return }
        shared.recordGauge(gauge, value: value, highWater: highWater)
        #endif
    }

    /// Increments an event counter; no-op in release.
    @inline(__always)
    static func event(_ event: Event) {
        #if DEBUG
        guard enabledCategories.contains(event.category) else { return }
        shared.recordEvent(event)
        #endif
    }

    // MARK: - Public API — lifecycle

    /// Clears aggregates and arms the periodic report; no-op in release.
    static func start() {
        #if DEBUG
        shared.startReporting()
        #endif
    }

    /// Prints a final report and resets.
    static func stop() {
        #if DEBUG
        shared.stopReporting()
        #endif
    }

    /// Prints the current report immediately without disturbing the periodic window.
    static func report() {
        #if DEBUG
        shared.emitReport(reason: "on-demand", resetAfter: false)
        #endif
    }

    // MARK: - Internals (DEBUG only)

#if DEBUG

    static let shared = PerformanceMonitor()

    /// Log2 histogram: bucket `i` holds `[2^(i-1), 2^i)` ns, bucket 0 holds zero;
    /// 34 buckets cover ~8.6 s (top bucket saturates).
    private static let bucketCount = 34
    private static let reportInterval: DispatchTimeInterval = .seconds(5)

    private let lock = UnfairLock()
    private let logger = AnywhereLogger(category: "PerformanceMonitor")

    private var spanStats: [SpanStat]
    /// Flat array indexed `component.rawValue * bucketCount + bucket`.
    private var spanBuckets: [UInt32]
    private var gaugeStats: [GaugeStat]
    private var eventCounts: [UInt64]
    private var lastSlowWarnTicks: [UInt64]          // per-component rate-limiting
    private let slowWarnIntervalTicks: UInt64          // 1 s floor between slow warns

    private let timerQueue = DispatchQueue(label: "com.argsment.Anywhere.perf", qos: .utility)
    private var reportTimer: DispatchSourceTimer?

    private init() {
        let components = Component.allCases.count
        spanStats = Array(repeating: SpanStat(), count: components)
        spanBuckets = Array(repeating: 0, count: components * Self.bucketCount)
        gaugeStats = Array(repeating: GaugeStat(), count: Gauge.allCases.count)
        eventCounts = Array(repeating: 0, count: Event.allCases.count)
        lastSlowWarnTicks = Array(repeating: 0, count: components)
        slowWarnIntervalTicks = UInt64(1.0 / PerfClock.secondsPerTick)
    }

    // MARK: Recording

    private func recordSpan(_ component: Component, elapsedTicks: UInt64) {
        let nanos = PerfClock.nanos(elapsedTicks)
        let idx = component.rawValue
        var shouldWarn = false

        lock.lock()
        spanStats[idx].record(nanos: nanos)
        spanBuckets[idx * Self.bucketCount + Self.bucketIndex(forNanos: nanos)] += 1
        if nanos > component.slowThresholdNanos {
            let now = PerfClock.nowTicks
            if now &- lastSlowWarnTicks[idx] >= slowWarnIntervalTicks {
                lastSlowWarnTicks[idx] = now
                shouldWarn = true
            }
        }
        lock.unlock()

        if shouldWarn {
            logger.debug("[perf] slow \(component.displayName): \(Self.humanNanos(nanos)) (> \(Self.humanNanos(component.slowThresholdNanos)))")
        }
    }

    private func recordGauge(_ gauge: Gauge, value: Int, highWater: Int) {
        let idx = gauge.rawValue
        var shouldWarn = false

        lock.lock()
        gaugeStats[idx].record(value)
        if highWater > 0 {
            if value >= highWater {
                if !gaugeStats[idx].highWaterLatched {
                    gaugeStats[idx].highWaterLatched = true
                    shouldWarn = true
                }
            } else if gaugeStats[idx].highWaterLatched {
                // Fell back below the mark — re-arm so a later spike warns again.
                gaugeStats[idx].highWaterLatched = false
            }
        }
        lock.unlock()

        if shouldWarn {
            logger.debug("[perf] high-water \(gauge.displayName): \(value) (>= \(highWater))")
        }
    }

    private func recordEvent(_ event: Event) {
        lock.lock()
        eventCounts[event.rawValue] += 1
        lock.unlock()
    }

    // MARK: Reporting

    private func startReporting() {
        guard !Self.enabledCategories.isEmpty else { return }
        lock.lock()
        resetLocked()
        lock.unlock()

        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: .now() + Self.reportInterval,
                       repeating: Self.reportInterval,
                       leeway: .seconds(1))
        timer.setEventHandler { [weak self] in
            // Reset each window so reports aren't diluted lifetime averages.
            self?.emitReport(reason: "window", resetAfter: true)
        }
        reportTimer = timer
        timer.resume()
    }

    private func stopReporting() {
        reportTimer?.cancel()
        reportTimer = nil
        emitReport(reason: "final", resetAfter: true)
    }

    /// Snapshots (and optionally resets) in one critical section; string-building
    /// and logging happen after the lock is released.
    private func emitReport(reason: String, resetAfter: Bool) {
        let enabled = Self.enabledCategories
        guard !enabled.isEmpty else { return }

        lock.lock()
        let spans = spanStats
        let buckets = spanBuckets
        let gauges = gaugeStats
        let events = eventCounts
        if resetAfter { resetLocked() }
        lock.unlock()

        var lines: [String] = []

        for component in Component.allCases where enabled.contains(component.category) {
            let s = spans[component.rawValue]
            guard s.count > 0 else { continue }
            let base = component.rawValue * Self.bucketCount
            let avg = s.sumNanos / s.count
            let p50 = Self.percentileNanos(buckets, base: base, count: s.count, max: s.maxNanos, p: 0.50)
            let p99 = Self.percentileNanos(buckets, base: base, count: s.count, max: s.maxNanos, p: 0.99)
            lines.append("  \(Self.pad(component.displayName)) n=\(s.count) avg=\(Self.humanNanos(avg)) p50=\(Self.humanNanos(p50)) p99=\(Self.humanNanos(p99)) max=\(Self.humanNanos(s.maxNanos))")
        }

        for gauge in Gauge.allCases where enabled.contains(gauge.category) {
            let g = gauges[gauge.rawValue]
            guard g.sampleCount > 0 else { continue }
            let avg = g.sum / Int64(g.sampleCount)
            lines.append("  \(Self.pad(gauge.displayName)) cur=\(g.current) peak=\(g.peak) avg=\(avg)")
        }

        for event in Event.allCases where enabled.contains(event.category) {
            let c = events[event.rawValue]
            guard c > 0 else { continue }
            lines.append("  \(Self.pad(event.displayName)) count=\(c)")
        }

        guard !lines.isEmpty else { return }
        logger.debug("[perf] ── report (\(reason)) ──\n" + lines.joined(separator: "\n"))
    }

    /// Zeroes all aggregates. Caller must hold `lock`.
    private func resetLocked() {
        for i in spanStats.indices { spanStats[i] = SpanStat() }
        for i in spanBuckets.indices { spanBuckets[i] = 0 }
        for i in gaugeStats.indices { gaugeStats[i] = GaugeStat() }
        for i in eventCounts.indices { eventCounts[i] = 0 }
        for i in lastSlowWarnTicks.indices { lastSlowWarnTicks[i] = 0 }
    }

    // MARK: Aggregate storage

    private struct SpanStat {
        var count: UInt64 = 0
        var sumNanos: UInt64 = 0
        var minNanos: UInt64 = .max
        var maxNanos: UInt64 = 0

        mutating func record(nanos: UInt64) {
            count &+= 1
            sumNanos &+= nanos
            if nanos < minNanos { minNanos = nanos }
            if nanos > maxNanos { maxNanos = nanos }
        }
    }

    private struct GaugeStat {
        var current: Int = 0
        var peak: Int = 0
        var sum: Int64 = 0
        var sampleCount: UInt64 = 0
        var highWaterLatched = false

        mutating func record(_ value: Int) {
            current = value
            if value > peak { peak = value }
            sum &+= Int64(value)
            sampleCount &+= 1
        }
    }

    // MARK: Histogram & formatting helpers

    @inline(__always)
    private static func bucketIndex(forNanos v: UInt64) -> Int {
        if v == 0 { return 0 }
        let bits = 64 - v.leadingZeroBitCount   // 1...64
        return min(bucketCount - 1, bits)
    }

    /// Approximate percentile: the midpoint of the log2 bucket holding the p-th
    /// sample, clamped to the observed `max` — treat as a band, not exact.
    private static func percentileNanos(_ buckets: [UInt32], base: Int, count: UInt64, max maxNanos: UInt64, p: Double) -> UInt64 {
        guard count > 0 else { return 0 }
        let target = UInt64((Double(count) * p).rounded(.up))
        var cumulative: UInt64 = 0
        for i in 0..<bucketCount {
            cumulative &+= UInt64(buckets[base + i])
            if cumulative >= target {
                guard i > 0 else { return 0 }
                let lower = UInt64(1) << UInt64(i - 1)
                let upper = UInt64(1) << UInt64(i)
                return Swift.min((lower + upper) / 2, maxNanos)
            }
        }
        return maxNanos
    }

    private static func humanNanos(_ ns: UInt64) -> String {
        if ns == .max { return "∞" }
        if ns < 1_000 { return "\(ns)ns" }
        if ns < 1_000_000 { return String(format: "%.1fµs", Double(ns) / 1_000) }
        if ns < 1_000_000_000 { return String(format: "%.1fms", Double(ns) / 1_000_000) }
        return String(format: "%.2fs", Double(ns) / 1_000_000_000)
    }

    private static func pad(_ name: String) -> String {
        let width = 24
        return name.count >= width ? name : name + String(repeating: " ", count: width - name.count)
    }

    // MARK: Monotonic clock (local copy; MonotonicClock is NE-target-only)

    private enum PerfClock {
        static let secondsPerTick: Double = {
            var info = mach_timebase_info_data_t()
            mach_timebase_info(&info)
            return (Double(info.numer) / Double(info.denom)) / 1_000_000_000
        }()
        private static let nanosPerTick: Double = secondsPerTick * 1_000_000_000

        @inline(__always)
        static var nowTicks: UInt64 { mach_continuous_time() }

        @inline(__always)
        static func nanos(_ ticks: UInt64) -> UInt64 {
            UInt64(Double(ticks) * nanosPerTick)
        }
    }

#endif
}

#if DEBUG
private extension PerformanceMonitor.Category {
    /// Parses `ANYWHERE_PERF` (comma/space-separated names, or `all`/`none`);
    /// falls back when unset.
    static func resolveFromEnvironment(default fallback: PerformanceMonitor.Category) -> PerformanceMonitor.Category {
        guard let raw = ProcessInfo.processInfo.environment["ANYWHERE_PERF"]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased(), !raw.isEmpty else {
            return fallback
        }
        if raw == "none" { return [] }
        if raw == "all" { return .all }

        let byName: [String: PerformanceMonitor.Category] = [
            "socket": .socket, "tls": .tls, "proxy": .proxy, "routing": .routing,
            "mitm": .mitm, "pipeline": .pipeline, "backpressure": .backpressure
        ]
        var result: PerformanceMonitor.Category = []
        for token in raw.split(whereSeparator: { $0 == "," || $0 == " " }) {
            if let category = byName[String(token)] { result.insert(category) }
        }
        return result
    }
}
#endif
