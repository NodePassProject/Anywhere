//
//  DashboardView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI
import NetworkExtension

struct DashboardView: View {
    @Environment(TunnelController.self) private var tunnelController
    @Environment(ConnectionStats.self) private var connectionStats

    private static let horizontalPadding: CGFloat = 20

    @State private var viewportHeight: CGFloat = 0

    private var isConnected: Bool {
        tunnelController.rawStatus == .connected
    }
    
    private var maxGridWidth: CGFloat {
        StatCardSize.gridWidth(
            columns: ConnectionStatsView.maxColumnCount,
            unitLength: StatCardSize.maxUnitLength
        )
    }
    
    var body: some View {
        NavigationStack {
            Group {
                if isConnected {
                    ScrollView {
                        ConnectionStatsView()
                            .frame(maxWidth: maxGridWidth)
                            .padding(.vertical, 16)
                            .padding(.horizontal, Self.horizontalPadding)
                            .frame(maxWidth: .infinity, minHeight: viewportHeight)
                    }
                    .scrollBounceBehavior(.basedOnSize, axes: .vertical)
                    .transition(.blurReplace)
                    .onGeometryChange(for: CGFloat.self) { proxy in
                        proxy.size.height
                    } action: { height in
                        viewportHeight = height
                    }
                } else {
                    ContentUnavailableView("Not Connected", systemImage: "power")
                }
            }
            .containerBackground(.clear, for: .navigation)
            .toolbar {
                if #available(iOS 27.0, *) {
                    ToolbarOverflowMenu {
                        Button {
                            Task { await connectionStats.resetStats() }
                        } label: {
                            Label("Reset Stats", systemImage: "0.circle")
                        }
                        .disabled(!isConnected)
                    }
                } else {
                    ToolbarItem {
                        Menu("More", systemImage: "ellipsis") {
                            Button {
                                Task { await connectionStats.resetStats() }
                            } label: {
                                Label("Reset Stats", systemImage: "0.circle")
                            }
                            .disabled(!isConnected)
                        }
                    }
                }
            }
        }
    }
}

// MARK: - Previews

#if DEBUG
#Preview("Connected") {
    let container = AppContainer.preview()
    container.tunnel.setStatusForPreview(.connected)

    return DashboardView()
        .environment(AppSettings())
        .environment(container.tunnel)
        .environment(container.configurationStore)
        .environment(container.chainStore)
        .environment(ConnectionStats.previewSeeded())
        .colorScheme(.dark)
}

#Preview("Disconnected") {
    let container = AppContainer.preview()

    return DashboardView()
        .environment(AppSettings())
        .environment(container.tunnel)
        .environment(container.configurationStore)
        .environment(container.chainStore)
        .environment(ConnectionStats.previewSeeded())
        .colorScheme(.dark)
}
#endif
