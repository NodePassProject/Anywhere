//
//  VoyagerNotice.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI

struct VoyagerNotice: View {
    @Environment(VoyagerStore.self) private var voyagerStore

    let description: LocalizedStringKey

    init(_ description: LocalizedStringKey) {
        self.description = description
    }

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Image(systemName: "sparkles.2")
                        .foregroundStyle(Color(hex: 0x5060F0))
                    Text("Voyager Only")
                        .font(.headline)
                }
                Text(description)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                JoinVoyagerButton {
                    voyagerStore.isPresentingVoyagerView = true
                }
            }
            .padding(.vertical, 4)
        }
    }
}
