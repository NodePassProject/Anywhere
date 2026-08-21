//
//  VoyagerNotice.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI

struct VoyagerNotice: View {
    let description: LocalizedStringKey

    @State private var isPresentingVoyager = false

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    if #available(iOS 26.0, *) {
                        Image(systemName: "sparkles.2")
                            .foregroundStyle(Color(hex: 0x5060F0))
                    } else {
                        Image(systemName: "sparkles")
                            .foregroundStyle(Color(hex: 0x5060F0))
                    }
                    Text("Voyager Only")
                        .font(.headline)
                }
                Text(description)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                JoinVoyagerButton {
                    isPresentingVoyager = true
                }
            }
            .padding(.vertical, 4)
            .voyagerCover(isPresented: $isPresentingVoyager)
        }
    }
}
