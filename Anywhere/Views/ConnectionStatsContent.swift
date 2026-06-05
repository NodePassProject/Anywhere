//
//  ConnectionStatsContent.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import Foundation
import SwiftUI
import Charts

struct ConnectionStatsContent: View {
    @Environment(ConnectionStatsModel.self) private var stats
    @State private var mode: Mode = .totals
    
    /// The displayed metric, advanced one step per tap (wraps at the end).
    private enum Mode: Int, CaseIterable {
        case totals, speed, connections, memory
        var next: Mode { Mode(rawValue: rawValue + 1) ?? .totals }
    }
    
    var body: some View {
        ZStack {
            switch mode {
            case .totals:
                totalsView
            case .speed:
                speedView
            case .connections:
                connectionsView
            case .memory:
                memoryView
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .animation(.easeInOut(duration: 0.25), value: mode)
        .contentShape(Rectangle())
        .onTapGesture { mode = mode.next }
        .accessibilityAddTraits(.isButton)
        .accessibilityHint("Switches the displayed metric")
    }
    
    // MARK: Totals (running cumulative bytes)
    
    private var totalsView: some View {
        HStack {
            HStack(spacing: 6) {
                Image(systemName: "arrow.up")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.white.opacity(0.7))
                    .accessibilityLabel("Upload")
                Text(Self.formatBytes(stats.bytesOut))
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.white)
                    .contentTransition(.numericText())
            }
            Spacer()
            HStack(spacing: 6) {
                Image(systemName: "arrow.down")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.white.opacity(0.7))
                    .accessibilityLabel("Download")
                Text(Self.formatBytes(stats.bytesIn))
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.white)
                    .contentTransition(.numericText())
            }
        }
        .animation(.default, value: stats.bytesIn)
        .animation(.default, value: stats.bytesOut)
    }
    
    // MARK: Speed
    
    private var speedView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Label("Speed", systemImage: "speedometer")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.white.opacity(0.7))
                Spacer()
                speedReadout(
                    systemImage: "arrow.up",
                    color: .orange,
                    bytes: stats.samples.last?.bytesOut ?? 0
                )
                .animation(.default, value: stats.samples.last?.bytesOut)
                speedReadout(
                    systemImage: "arrow.down",
                    color: .cyan,
                    bytes: stats.samples.last?.bytesIn ?? 0
                )
                .animation(.default, value: stats.samples.last?.bytesIn)
            }
            Chart(stats.samples) { sample in
                LineMark(
                    x: .value("Time", Int(sample.id)),
                    y: .value("Speed", Double(sample.bytesOut)),
                    series: .value("Series", "Upload")
                )
                .foregroundStyle(.orange)
                LineMark(
                    x: .value("Time", Int(sample.id)),
                    y: .value("Speed", Double(sample.bytesIn)),
                    series: .value("Series", "Download")
                )
                .foregroundStyle(.cyan)
            }
            .chartXAxis(.hidden)
            .chartLegend(.hidden)
            .chartXScale(domain: xDomain)
            .chartYAxis { yAxis { Self.formatBytes(Int64($0)) + String(localized: "/s") } }
            .chartYScale(domain: .automatic(includesZero: true))
            .frame(minHeight: 50)
            .animation(.default, value: stats.samples)
        }
    }
    
    private func speedReadout(systemImage: String, color: Color, bytes: Int64) -> some View {
        HStack(spacing: 4) {
            Image(systemName: systemImage)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(color)
            Text(Self.formatSpeed(bytes))
                .font(.caption.monospacedDigit())
                .foregroundStyle(.white)
                .contentTransition(.numericText())
        }
    }
    
    // MARK: Connections
    
    private var connectionsView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Label("Connections", systemImage: "network")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.white.opacity(0.7))
                Spacer()
                connectionReadout(label: "TCP", color: .green, count: stats.tcpConnectionCount)
                    .animation(.default, value: stats.tcpConnectionCount)
                connectionReadout(label: "UDP", color: .purple, count: stats.udpConnectionCount)
                    .animation(.default, value: stats.udpConnectionCount)
            }
            Chart(stats.samples) { sample in
                LineMark(
                    x: .value("Time", Int(sample.id)),
                    y: .value("Count", Double(sample.tcpConnectionCount)),
                    series: .value("Series", "TCP")
                )
                .foregroundStyle(.green)
                .interpolationMethod(.monotone)
                LineMark(
                    x: .value("Time", Int(sample.id)),
                    y: .value("Count", Double(sample.udpConnectionCount)),
                    series: .value("Series", "UDP")
                )
                .foregroundStyle(.purple)
                .interpolationMethod(.monotone)
            }
            .chartXAxis(.hidden)
            .chartLegend(.hidden)
            .chartXScale(domain: xDomain)
            .chartYAxis { yAxis { "\(Int($0.rounded()))" } }
            .chartYScale(domain: .automatic(includesZero: true))
            .frame(minHeight: 50)
            .animation(.default, value: stats.samples)
        }
    }
    
    private func connectionReadout(label: String, color: Color, count: Int) -> some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 7, height: 7)
            Text("\(label) \(count)")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.white)
                .contentTransition(.numericText())
        }
    }
    
    // MARK: Memory

    private var memoryView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Memory", systemImage: "memorychip")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.white.opacity(0.7))
                Spacer()
                Text(Self.formatBytes(Int64(stats.memoryBytes)))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.white)
                    .contentTransition(.numericText())
                    .animation(.default, value: stats.memoryBytes)
            }
            Chart(stats.samples) { sample in
                AreaMark(
                    x: .value("Time", Int(sample.id)),
                    y: .value("Usage", Double(sample.memoryBytes))
                )
                .foregroundStyle(.linearGradient(
                    colors: [Color.yellow.opacity(0.35), Color.yellow.opacity(0.03)],
                    startPoint: .top, endPoint: .bottom))
                .interpolationMethod(.monotone)
                LineMark(
                    x: .value("Time", Int(sample.id)),
                    y: .value("Usage", Double(sample.memoryBytes))
                )
                .foregroundStyle(.yellow)
                .interpolationMethod(.monotone)
            }
            .chartXAxis(.hidden)
            .chartXScale(domain: xDomain)
            .chartYAxis { yAxis { Self.formatBytes(Int64($0)) } }
            .chartYScale(domain: .automatic(includesZero: true))
            .frame(minHeight: 50)
            .animation(.default, value: stats.samples)
        }
    }
    
    // MARK: Chart X axis
    
    private var xDomain: ClosedRange<Int> {
        let latest = Int(stats.samples.last?.id ?? UInt64(ConnectionStatsModel.maxSamples))
        return (latest - (ConnectionStatsModel.maxSamples - 1))...latest
    }
    
    // MARK: Chart Y axis
    
    private func yAxis(_ label: @escaping (Double) -> String) -> some AxisContent {
        AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
            AxisGridLine()
                .foregroundStyle(.white.opacity(0.12))
            AxisValueLabel {
                if let value = value.as(Double.self) {
                    Text(label(value))
                }
            }
            .font(.system(size: 8))
            .foregroundStyle(.white.opacity(0.55))
        }
    }
    
    // MARK: Formatting
    
    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowsNonnumericFormatting = false
        return formatter
    }()
    
    private static func formatBytes(_ bytes: Int64) -> String {
        byteFormatter.string(fromByteCount: bytes)
    }
    
    private static func formatSpeed(_ bytesPerSecond: Int64) -> String {
        byteFormatter.string(fromByteCount: bytesPerSecond) + String(localized: "/s")
    }
}

#if DEBUG
/// Dark, card-like backdrop that mirrors the connected-state Home card, so the
/// white text and colored charts read correctly in the preview canvas.
private struct ConnectionStatsPreviewStage<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.05, green: 0.12, blue: 0.18), .black],
                startPoint: .top, endPoint: .bottom
            )
            .ignoresSafeArea()
            content
                .padding(16)
                .background(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(.white.opacity(0.12))
                )
                .padding(24)
        }
    }
}

// Tap the card to cycle: totals → speed → connections → memory → totals.
#Preview("Live data") {
    ConnectionStatsPreviewStage {
        ConnectionStatsContent()
            .environment(ConnectionStatsModel.previewSeeded())
    }
}

#Preview("Empty") {
    ConnectionStatsPreviewStage {
        ConnectionStatsContent()
            .environment(ConnectionStatsModel())
    }
}
#endif
