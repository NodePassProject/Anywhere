//
//  AcknowledgementsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI

struct AcknowledgementsView: View {
    private static let trademarks: [(name: String, owner: String)] = [
        ("Telegram", "Telegram FZ-LLC"),
        ("Netflix", "Netflix, Inc."),
        ("YouTube", "Google LLC"),
        ("OpenAI", "OpenAI, Inc."),
        ("Claude", "Anthropic, PBC"),
    ]

    var body: some View {
        List {
            Section {
                Text("Anywhere is an independent project and is not affiliated with, endorsed by, or sponsored by any of the companies listed below.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Section("Trademarks") {
                ForEach(Self.trademarks, id: \.name) { item in
                    HStack(spacing: 12) {
                        AppIconView(item.name)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.name)
                            Text(item.owner)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            Section {
                Text("All trademarks, service marks, and company names are the property of their respective owners.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Acknowledgements")
    }
}
