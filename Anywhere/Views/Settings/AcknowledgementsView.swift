//
//  AcknowledgementsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
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
        ("Telegram", "Telegram FZ-LLC"),
        ("Netflix", "Netflix, Inc."),
        ("YouTube", "Google LLC"),
        ("Disney+", "The Walt Disney Company"),
        ("TikTok", "ByteDance Ltd."),
        ("ChatGPT", "OpenAI, Inc."),
        ("Claude", "Anthropic, PBC"),
        ("Gemini", "Google LLC"),
    ]

    private static let libraries: [OpenSourceLibrary] = [
        OpenSourceLibrary(
            name: "lwIP",
            licenseType: "BSD License",
            licenseText: """
                Copyright (c) 2001-2004 Swedish Institute of Computer Science.
                All rights reserved.

                Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

                1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

                2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

                3. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.

                THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
                        VStack(alignment: .leading, spacing: 2) {
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
                        VStack(alignment: .leading, spacing: 2) {
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
