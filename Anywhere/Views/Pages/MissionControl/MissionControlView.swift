//
//  MissionControlView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI
import NetworkExtension

struct MissionControlView: View {
    @Environment(AppSettings.self) private var appSettings
    @Environment(TunnelController.self) private var tunnelController
    @Environment(ConnectionStatsModel.self) private var stats

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
            ZStack {
                BackgroundGradient(isConnected: isConnected)
                    .ignoresSafeArea()
                
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
                } else {
                    ContentUnavailableView("Not Connected", systemImage: "power")
                }
            }
            .navigationTitle("Mission Control")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem {
                    Menu("More", systemImage: "ellipsis") {
                        Button {
                            Task { await stats.resetStats() }
                        } label: {
                            Label("Reset", systemImage: "arrow.clockwise")
                        }
                    }
                }
            }
            .colorScheme(appSettings.homeColorScheme.colorScheme)
            .toolbarColorScheme(appSettings.homeColorScheme.colorScheme, for: .navigationBar)
            .toolbarColorScheme(appSettings.homeColorScheme.colorScheme, for: .tabBar)
            .onGeometryChange(for: CGFloat.self) { proxy in
                proxy.size.height
            } action: { height in
                viewportHeight = height
            }
        }
    }
}

// MARK: - Previews

#if DEBUG
#Preview("Connected") {
    let container = AppContainer.preview()
    container.tunnel.setStatusForPreview(.connected)

    return MissionControlView()
        .environment(AppSettings())
        .environment(container.tunnel)
        .environment(container.configurationStore)
        .environment(container.chainStore)
        .environment(ConnectionStatsModel.previewSeeded())
        .colorScheme(.dark)
}

#Preview("Disconnected") {
    let container = AppContainer.preview()

    return MissionControlView()
        .environment(AppSettings())
        .environment(container.tunnel)
        .environment(container.configurationStore)
        .environment(container.chainStore)
        .environment(ConnectionStatsModel.previewSeeded())
        .colorScheme(.dark)
}
#endif
