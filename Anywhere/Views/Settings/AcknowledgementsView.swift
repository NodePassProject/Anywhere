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
        ("Netflix", "Netflix, Inc."),
        ("YouTube", "Google LLC"),
        ("TikTok", "ByteDance Ltd."),
        ("ChatGPT", "OpenAI, Inc."),
        ("Claude", "Anthropic, PBC"),
        ("Spotify", "Spotify AB"),
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
            name: "libyaml",
            licenseType: "MIT License",
            licenseText: """
                Copyright (c) 2017-2020 Ingy döt Net
                Copyright (c) 2006-2016 Kirill Simonov

                Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

                The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

                THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
                """
        ),
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
