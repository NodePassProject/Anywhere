//
//  AcknowledgementsView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI

private struct OpenSourceLibrary: Identifiable {
    let id = UUID()
    let name: String
    let licenseType: String
    let licenseText: String
}

struct AcknowledgementsView: View {
    private static let trademarks: [(name: String, owner: String)] = [
        ("Google", "Google LLC"),
        ("Telegram", "Telegram FZ-LLC"),
        ("X", "X Corp."),
        ("Netflix", "Netflix, Inc."),
        ("YouTube", "Google LLC"),
        ("TikTok", "ByteDance Ltd."),
        ("Spotify", "Spotify AB"),
        ("ChatGPT", "OpenAI, Inc."),
        ("Claude", "Anthropic, PBC"),
    ]

    private static let libraries: [OpenSourceLibrary] = [
        OpenSourceLibrary(
            name: "BLAKE2",
            licenseType: "CC0 1.0 / OpenSSL / Apache 2.0",
            licenseText: """
                BLAKE2 reference C implementation, copyright 2012 Samuel Neves.

                This work is triple-licensed under the Creative Commons Zero v1.0 Universal (CC0 1.0) public domain dedication, the OpenSSL License, and the Apache License, Version 2.0. You may use it under the terms of any of these licenses.

                Unless required by applicable law or agreed to in writing, the software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
                """
        ),
        OpenSourceLibrary(
            name: "BLAKE3",
            licenseType: "CC0 1.0 / Apache 2.0",
            licenseText: """
                BLAKE3 reference C implementation, version 1.8.5, by Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O'Hearn.

                This work is dual-licensed under the Creative Commons Zero v1.0 Universal (CC0 1.0) public domain dedication and the Apache License, Version 2.0. You may use it under the terms of either license.

                Unless required by applicable law or agreed to in writing, the software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
                """
        ),
        OpenSourceLibrary(
            name: "MaxMind GeoLite2",
            licenseType: "CC BY-SA 4.0",
            licenseText: """
                This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.

                The GeoLite2 databases are distributed under the Creative Commons Attribution-ShareAlike 4.0 International License. To view a copy of this license, visit https://creativecommons.org/licenses/by-sa/4.0/.
                """
        ),
    ]

    @State private var expandedLibrary: UUID?

    var body: some View {
        List {
            Section {
                Text("Anywhere is an independent project and is not affiliated with, endorsed by, or sponsored by any of the companies listed below.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Section {
                ForEach(Self.trademarks, id: \.name) { item in
                    HStack(spacing: 12) {
                        AppIconView(item.name)
                        VStack(alignment: .leading) {
                            Text(item.name)
                            Text(item.owner)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Trademarks")
            } footer: {
                Text("All trademarks, service marks, and company names are the property of their respective owners.")
            }

            Section("Open Source Libraries") {
                ForEach(Self.libraries) { library in
                    DisclosureGroup(
                        isExpanded: Binding(
                            get: { expandedLibrary == library.id },
                            set: { expandedLibrary = $0 ? library.id : nil }
                        )
                    ) {
                        Text(library.licenseText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .padding(.top, 4)
                    } label: {
                        VStack(alignment: .leading) {
                            Text(library.name)
                            Text(library.licenseType)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .navigationTitle("Acknowledgements")
    }
}
