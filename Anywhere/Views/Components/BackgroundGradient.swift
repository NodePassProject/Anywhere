//
//  BackgroundGradient.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI

struct BackgroundGradient: View {
    @Environment(AppSettings.self) private var settings

    let isConnected: Bool

    var body: some View {
        if isConnected {
            LinearGradient(
                colors: [
                    color(settings.connectedBackgroundStartData, default: .connectedBackgroundStart),
                    color(settings.connectedBackgroundEndData, default: .connectedBackgroundEnd),
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .transition(.blurReplace)
        } else {
            LinearGradient(
                colors: [
                    color(settings.disconnectedBackgroundStartData, default: .disconnectedBackgroundStart),
                    color(settings.disconnectedBackgroundEndData, default: .disconnectedBackgroundEnd),
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .transition(.blurReplace)
        }
    }

    private func color(_ data: Data?, default fallback: Color) -> Color {
        data.flatMap(Color.init(archivedData:)) ?? fallback
    }
}
