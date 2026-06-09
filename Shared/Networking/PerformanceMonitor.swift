//
//  PerformanceMonitor.swift
//  Anywhere
//
//  Created by NodePassProject on 6/9/26.
//

import Foundation

/// Debug-only instrument for the data plane's send/receive path.
///
/// Throughput and latency are governed by a chain of "heavy load" stages —
/// socket syscalls, TLS record crypto, routing-rule evaluation, the MITM
/// engine, the proxy transports — plus several bounded buffers/queues that
/// silently throttle or drop when overwhelmed. ``ConnectionMetrics`` only tracks
/// connection *establishment* (dial/handshake) for the home-screen cards; it
/// says nothing about which stage is slow once data is flowing, or where
/// backpressure builds. This fills that gap with three record types:
///
/// - **Spans** (``Component``) — a timed interval around a stage. ``measure(_:_:)``
///   wraps a synchronous body; ``span(_:)`` + ``Span/stop()`` brackets a
///   completion-handler boundary. Aggregated into count / avg / p50 / p99 / max.
/// - **Gauges** (``Gauge``) — a sampled level (a backlog size, a queue depth),
///   tracked as current / peak / mean with rising-edge high-water warnings.
/// - **Events** (``Event``) — a counter for discrete overwhelm incidents
///   (a drop, a stall retry, an eviction).
///
/// Design constraints
/// ==================
/// - **Debug-only, zero-cost in release.** Every recording body is `#if DEBUG`.
///   The public API (``measure(_:_:)`` / ``span(_:)`` / ``gauge(_:_:highWater:)``
///   / ``event(_:)`` / ``start()`` / ``stop()``) exists in all builds but, in
///   release, compiles to the bare work / a no-op — call sites need no
///   `#if DEBUG`. ``Span`` is an empty, zero-size struct in release so the
///   optimizer elides it entirely (mirrors how ``MetricTimer`` is used
///   unconditionally at call sites).
/// - **Opt-in by category, to control noise.** ``enabledCategories`` gates *both*
///   recording and printing, so a disabled ``Category`` costs ~nothing even in
///   debug. Set it via the ``defaultEnabledCategories`` constant in this file, or
///   launch with the `ANYWHERE_PERF` environment variable (e.g.
///   `ANYWHERE_PERF=tls,backpressure`, or `all`). The constant is the reliable
///   control for the system-launched Network Extension, where a shell/scheme env
///   var may not reach the tunnel process.
/// - **Thread-safe leaf lock, never held across work or logging.** Recorded from
///   every data-plane queue (`lwipQueue`, `udpQueue`, per-socket `ioQueue`, the
///   QUIC queue, `scriptQueue`). A single ``UnfairLock`` guards the aggregates;
///   it is taken/released *inside each record call* — never across the timed
///   body (so nested spans can't self-deadlock os_unfair_lock) and never across
///   an ``AnywhereLogger`` call. ``report()`` snapshots under the lock, releases,
///   then formats and logs (like ``ConnectionMetrics/snapshot()``).
///
/// `nonisolated` (like the other networking primitives) so it stays off the main
/// actor under the project's default-`MainActor` isolation; safety comes from the
/// lock, not the actor.
nonisolated final class PerformanceMonitor: @unchecked Sendable {

    // MARK: - Category (the print/enable filter)

    /// Coarse groupings used to opt instrumentation in and out. Each ``Component``
    /// / ``Gauge`` / ``Event`` belongs to exactly one. Flip categories on via
    /// ``defaultEnabledCategories`` or the `ANYWHERE_PERF` env var so you only see
    /// the stages you're investigating.
    struct Category: OptionSet, Sendable {
        let rawValue: Int
        /// Raw socket send/receive syscalls (TCP / UDP / QUIC).
        static let socket       = Category(rawValue: 1 << 0)
        /// TLS record crypto and the TLS handshake.
        static let tls          = Category(rawValue: 1 << 1)
        /// Proxy dial/handshake and per-chunk proxy send/receive latency.
        static let proxy        = Category(rawValue: 1 << 2)
        /// Domain/IP routing-rule evaluation.
        static let routing      = Category(rawValue: 1 << 3)
        /// The MITM engine — rewrite passes and user-script execution.
        static let mitm         = Category(rawValue: 1 << 4)
        /// Per-connection TCP up/downlink pipeline health (backlogs, stalls).
        static let pipeline     = Category(rawValue: 1 << 5)
        /// System-wide overwhelm — output queue depth, UDP flow table, drops.
        static let backpressure = Category(rawValue: 1 << 6)

        static let all: Category = [
            .socket, .tls, .proxy, .routing, .mitm, .pipeline, .backpressure
        ]
    }

    // MARK: - Component (timed spans)

    /// A timed stage in the send/receive path. To add one: append a case, then a
    /// row in ``category``, ``displayName``, and ``slowThresholdNanos`` — storage
    /// (sized to `allCases.count`) and reporting then pick it up unchanged.
    ///
    /// Some spans are **network-bound** (a handshake round-trip, a proxy
    /// send/receive that waits on a flow-control window): their elapsed time is
    /// dominated by the wire, not by CPU, so a per-span "slow" warning would be
    /// noise. Those carry `slowThresholdNanos == .max` (never warn) but are still
    /// aggregated — the p50/p99/max of `proxy.recv` is exactly how you spot an
    /// unresponsive upstream.
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

        /// A single span slower than this logs an inline warning (rate-limited).
        /// `.max` disables the warning for network-bound spans that legitimately
        /// wait on the wire (handshakes, proxy send/receive).
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
                return 5_000_000_000      // 5 s — heavy JS is legitimate; the
                                          // MITMScriptWatchdog owns the hard cap
            case .tlsHandshake, .proxyHandshake, .proxySend, .proxyReceive:
                return .max               // network-bound: aggregate, never warn
            }
        }
    }

    // MARK: - Gauge (sampled levels)

    /// A sampled level — a backlog or queue depth. The high-water threshold is
    /// supplied at the *call site* (from `TunnelConstants`, which is
    /// Network-Extension-only), so this `Shared` type stays free of NE symbols.
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

    /// A discrete overwhelm incident: a drop, a stall retry, an eviction. These
    /// already drive a one-off log line in the data plane; counting them here
    /// turns "it happened" into "it happened N times this session".
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

    /// **Edit this to choose what you want to see.** Empty = silent (the default,
    /// so the monitor never adds noise until asked). Examples:
    /// `[.tls, .backpressure]`, or `.all`. Overridden at launch by the
    /// `ANYWHERE_PERF` env var when present.
    static let defaultEnabledCategories: Category = []

    /// The resolved filter: ``defaultEnabledCategories``, overridden by the
    /// `ANYWHERE_PERF` environment variable when set (comma/space-separated
    /// category names, or `all` / `none`). Resolved once, on first use. Empty in
    /// release — nothing records or prints.
    static let enabledCategories: Category = {
        #if DEBUG
        return Category.resolveFromEnvironment(default: defaultEnabledCategories)
        #else
        return []
        #endif
    }()

    // MARK: - Public API — spans

    /// Times `body` as a ``Component`` span. In release (and for a disabled
    /// category) this is exactly `body()` — no timing, no overhead. Use for any
    /// synchronous stage (crypto, routing, a non-blocking syscall, a rewrite pass).
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

    /// Opens a ``Component`` span for a completion-handler / async boundary;
    /// balance it with exactly one ``Span/stop()`` (typically inside the single
    /// completion wrapper). In release ``Span`` is a zero-size no-op.
    @inline(__always)
    static func span(_ component: Component) -> Span {
        #if DEBUG
        return Span(component: component, startTicks: PerfClock.nowTicks)
        #else
        return Span()
        #endif
    }

    /// A half-open span token. Created by ``PerformanceMonitor/span(_:)``, closed
    /// by ``stop()``. Empty (zero-size) in release so it and its `stop()` are
    /// elided at the call site.
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

    /// Samples a ``Gauge`` level. `highWater` (from a `TunnelConstants` value at
    /// the call site) triggers a one-shot rising-edge warning when crossed; pass
    /// `0` to disable that warning. No-op in release / disabled category.
    @inline(__always)
    static func gauge(_ gauge: Gauge, _ value: Int, highWater: Int = 0) {
        #if DEBUG
        guard enabledCategories.contains(gauge.category) else { return }
        shared.recordGauge(gauge, value: value, highWater: highWater)
        #endif
    }

    /// Increments an ``Event`` counter. No-op in release / disabled category.
    @inline(__always)
    static func event(_ event: Event) {
        #if DEBUG
        guard enabledCategories.contains(event.category) else { return }
        shared.recordEvent(event)
        #endif
    }

    // MARK: - Public API — lifecycle

    /// Begins a measurement session: clears prior aggregates and arms the
    /// periodic report. Hooked at tunnel start (alongside `AnywhereLogger.logSink`
    /// install). No-op in release, or when no category is enabled.
    static func start() {
        #if DEBUG
        shared.startReporting()
        #endif
    }

    /// Ends the session: prints a final report and resets. Hooked at tunnel stop.
    static func stop() {
        #if DEBUG
        shared.stopReporting()
        #endif
    }

    /// Prints the current report immediately (in addition to the periodic one).
    static func report() {
        #if DEBUG
        shared.emitReport(reason: "on-demand")
        #endif
    }

    // MARK: - Internals (DEBUG only)

#if DEBUG

    static let shared = PerformanceMonitor()

    /// Log2 histogram resolution: bucket `i` (i ≥ 1) holds spans in
    /// `[2^(i-1), 2^i)` nanoseconds; bucket 0 holds zero. 34 buckets cover up to
    /// ~2^33 ns ≈ 8.6 s, which saturates the top bucket.
    private static let bucketCount = 34
    /// Periodic report cadence.
    private static let reportInterval: DispatchTimeInterval = .seconds(5)

    private let lock = UnfairLock()
    private let logger = AnywhereLogger(category: "Perf")

    private var spanStats: [SpanStat]
    /// Flat `componentCount × bucketCount` histogram, indexed
    /// `component.rawValue * bucketCount + bucket` — one allocation, no per-stat
    /// nested arrays.
    private var spanBuckets: [UInt32]
    private var gaugeStats: [GaugeStat]
    private var eventCounts: [UInt64]
    /// Last slow-warning timestamp per component (ticks), for rate-limiting.
    private var lastSlowWarnTicks: [UInt64]
    /// One second in continuous-time ticks — the per-component slow-warn floor.
    private let slowWarnIntervalTicks: UInt64

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
            self?.emitReport(reason: "periodic")
        }
        reportTimer = timer
        timer.resume()
    }

    private func stopReporting() {
        reportTimer?.cancel()
        reportTimer = nil
        emitReport(reason: "final")
        lock.lock()
        resetLocked()
        lock.unlock()
    }

    /// Snapshots all state under the lock, releases it, then formats and logs —
    /// so string-building and `os_log` never run under the hot-path lock.
    private func emitReport(reason: String) {
        let enabled = Self.enabledCategories
        guard !enabled.isEmpty else { return }

        lock.lock()
        let spans = spanStats
        let buckets = spanBuckets
        let gauges = gaugeStats
        let events = eventCounts
        lock.unlock()

        var lines: [String] = []

        for component in Component.allCases where enabled.contains(component.category) {
            let s = spans[component.rawValue]
            guard s.count > 0 else { continue }
            let base = component.rawValue * Self.bucketCount
            let avg = s.sumNanos / s.count
            let p50 = Self.percentileNanos(buckets, base: base, count: s.count, p: 0.50)
            let p99 = Self.percentileNanos(buckets, base: base, count: s.count, p: 0.99)
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

    /// Zeroes all aggregates. Caller must hold ``lock``.
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

    /// Approximate percentile from the log2 histogram: the upper bound of the
    /// bucket in which the p-th sample falls.
    private static func percentileNanos(_ buckets: [UInt32], base: Int, count: UInt64, p: Double) -> UInt64 {
        guard count > 0 else { return 0 }
        let target = UInt64((Double(count) * p).rounded(.up))
        var cumulative: UInt64 = 0
        for i in 0..<bucketCount {
            cumulative &+= UInt64(buckets[base + i])
            if cumulative >= target {
                return i == 0 ? 0 : (UInt64(1) << UInt64(i))
            }
        }
        return UInt64(1) << UInt64(bucketCount - 1)
    }

    private static func humanNanos(_ ns: UInt64) -> String {
        if ns == .max { return "∞" }
        if ns < 1_000 { return "\(ns)ns" }
        if ns < 1_000_000 { return String(format: "%.1fµs", Double(ns) / 1_000) }
        if ns < 1_000_000_000 { return String(format: "%.1fms", Double(ns) / 1_000_000) }
        return String(format: "%.2fs", Double(ns) / 1_000_000_000)
    }

    /// Right-pads a metric name to a fixed width for legible column alignment.
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
    /// Parses the `ANYWHERE_PERF` env var into a category set. Recognizes
    /// comma/space-separated names (`socket`, `tls`, `proxy`, `routing`, `mitm`,
    /// `pipeline`, `backpressure`), plus `all` and `none`. Falls back to
    /// `fallback` when the variable is unset.
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
