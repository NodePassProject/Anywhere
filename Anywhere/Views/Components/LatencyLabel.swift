//
//  LatencyLabel.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import SwiftUI

struct LatencyLabel: View {
    let latency: LatencyResult?

    var body: some View {
        switch latency {
        case .testing:
            ProgressView()
                .controlSize(.small)
                .frame(width: 50, alignment: .trailing)
        case .success(let ms):
            Text("\(ms) ms")
                .font(.caption)
                .monospacedDigit()
                .foregroundStyle(Self.color(ms))
                .frame(minWidth: 50, alignment: .trailing)
        case .failed:
            Text("timeout")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(minWidth: 50, alignment: .trailing)
        case .insecure:
            Text("insecure")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(minWidth: 50, alignment: .trailing)
        case nil:
            EmptyView()
        }
    }

    static func color(_ ms: Int) -> Color {
        if ms < 300 { return .green }
        if ms < 500 { return .yellow }
        return .red
    }
}
