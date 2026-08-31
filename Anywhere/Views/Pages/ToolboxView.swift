//
//  ToolboxView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/29/26.
//

import SwiftUI

struct ToolboxView: View {
    @Environment(AppSettings.self) private var settings

    var body: some View {
        NavigationStack {
            List {
                if settings.showVoyagerCard {
                    Section {
                        VoyagerMemberCard()
                            .listRowInsets(EdgeInsets())
                            .listRowBackground(VoyagerCardBackground())
                    }
                }
                
                Section {
                    NavigationLink {
                        DataView()
                    } label: {
                        TextWithColorfulIcon(title: "Data", systemName: "cylinder.split.1x2.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                    }
                    NavigationLink {
                        PersonalizationView()
                    } label: {
                        TextWithColorfulIcon(title: "Personalization", systemName: "paintpalette.fill", foregroundStyle: .white, backgroundStyle: .pink.gradient)
                    }
                }
                
                Section {
                    NavigationLink {
                        TunnelView()
                    } label: {
                        TextWithColorfulIcon(title: "Tunnel", systemName: "hammer.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                    }
                    NavigationLink {
                        PurifyView()
                    } label: {
                        TextWithColorfulIcon(title: "Purify", systemName: "drop.fill", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                    }
                    NavigationLink {
                        RoutingView()
                    } label: {
                        TextWithColorfulIcon(title: "Routing", systemName: "arrow.triangle.branch", foregroundStyle: .white, backgroundStyle: .purple.gradient)
                    }
                    NavigationLink {
                        MITMView()
                    } label: {
                        TextWithColorfulIcon(title: "MITM", systemName: "key.horizontal.fill", foregroundStyle: .white, backgroundStyle: .teal.gradient)
                    }
                }
                
                Section {
                    NavigationLink {
                        TrustedCertificatesView()
                    } label: {
                        TextWithColorfulIcon(title: "Trusted Certificates", systemName: "checkmark.seal.fill", foregroundStyle: .white, backgroundStyle: .green.gradient)
                    }
                    NavigationLink {
                        TrustedNetworkView()
                    } label: {
                        TextWithColorfulIcon(title: "Trusted Network", systemName: "wifi", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                    }
                }
                
                Section {
                    NavigationLink {
                        DiagnosisView()
                    } label: {
                        TextWithColorfulIcon(title: "Diagnosis", systemName: "stethoscope", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                    }
                    NavigationLink {
                        AboutView()
                    } label: {
                        TextWithColorfulIcon(title: "About", systemName: "info.circle.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                    }
                }
            }
            .navigationTitle("Toolbox")
        }
    }
}
