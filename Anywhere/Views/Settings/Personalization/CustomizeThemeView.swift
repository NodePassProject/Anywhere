//
//  CustomizeThemeView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI

struct CustomizeThemeView: View {
    @Environment(VoyagerStore.self) private var voyagerStore
    @Bindable private var settings = AppSettings.shared
    
    var body: some View {
        Form {
            if !voyagerStore.isMember {
                VoyagerNotice("Custom themes are available to Anywhere Voyager members.")
            }
            
            Section {
                Picker(selection: $settings.homeColorScheme) {
                    ForEach(HomeColorScheme.allCases, id: \.self) { scheme in
                        Text(label(for: scheme)).tag(scheme)
                    }
                } label: {
                    TextWithColorfulIcon(title: "Appearance", comment: nil, systemName: "circle.lefthalf.filled", foregroundColor: .white, backgroundColor: .black)
                }
            }
            
            .disabled(!voyagerStore.isMember)
            
            Section {
                ColorPicker(
                    "Top",
                    selection: colorBinding($settings.connectedBackgroundStartData, default: .connectedBackgroundStart),
                    supportsOpacity: false
                )
                ColorPicker(
                    "Bottom",
                    selection: colorBinding($settings.connectedBackgroundEndData, default: .connectedBackgroundEnd),
                    supportsOpacity: false
                )
            } header: {
                Text("Background (Connected)")
            }
            
            .disabled(!voyagerStore.isMember)
            
            Section {
                ColorPicker(
                    "Top",
                    selection: colorBinding($settings.disconnectedBackgroundStartData, default: .disconnectedBackgroundStart),
                    supportsOpacity: false
                )
                ColorPicker(
                    "Bottom",
                    selection: colorBinding($settings.disconnectedBackgroundEndData, default: .disconnectedBackgroundEnd),
                    supportsOpacity: false
                )
            } header: {
                Text("Background (Disconnected)")
            }
            
            .disabled(!voyagerStore.isMember)
            
            Section {
                HStack {
                    Spacer()
                    swatch(
                        title: "Connected",
                        colors: [
                            resolved(settings.connectedBackgroundStartData, default: .connectedBackgroundStart),
                            resolved(settings.connectedBackgroundEndData, default: .connectedBackgroundEnd),
                        ]
                    )
                    Spacer()
                    swatch(
                        title: "Disconnected",
                        colors: [
                            resolved(settings.disconnectedBackgroundStartData, default: .disconnectedBackgroundStart),
                            resolved(settings.disconnectedBackgroundEndData, default: .disconnectedBackgroundEnd),
                        ]
                    )
                    Spacer()
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 4)
            } header: {
                Text("Preview")
            }
        }
        .navigationTitle("Theme")
        .toolbar {
            ToolbarItem {
                Button(role: .destructive) {
                    reset()
                } label: {
                    Label("Reset", systemImage: "arrow.clockwise")
                }
            }
        }
    }
    
    // MARK: - Customization state
    
    private var isCustomized: Bool {
        settings.homeColorScheme != .dark
        || settings.connectedBackgroundStartData != nil
        || settings.connectedBackgroundEndData != nil
        || settings.disconnectedBackgroundStartData != nil
        || settings.disconnectedBackgroundEndData != nil
    }
    
    private func reset() {
        settings.homeColorScheme = .dark
        settings.connectedBackgroundStartData = nil
        settings.connectedBackgroundEndData = nil
        settings.disconnectedBackgroundStartData = nil
        settings.disconnectedBackgroundEndData = nil
    }
    
    // MARK: - Helpers
    
    private func label(for scheme: HomeColorScheme) -> LocalizedStringKey {
        switch scheme {
        case .dark: "Dark"
        case .light: "Light"
        }
    }
    
    private func colorBinding(_ data: Binding<Data?>, default fallback: Color) -> Binding<Color> {
        Binding(
            get: { resolved(data.wrappedValue, default: fallback) },
            set: { data.wrappedValue = $0.archivedData }
        )
    }
    
    private func resolved(_ data: Data?, default fallback: Color) -> Color {
        data.flatMap(Color.init(archivedData:)) ?? fallback
    }
    
    private func swatch(title: LocalizedStringKey, colors: [Color]) -> some View {
        VStack {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(
                    LinearGradient(colors: colors, startPoint: .top, endPoint: .bottom)
                )
                .frame(width: 393 * 0.2, height: 852 * 0.2)
                .overlay {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .strokeBorder(.quaternary, lineWidth: 0.5)
                }
                .overlay {
                    Image(systemName: "power")
                        .font(.system(size: 28, weight: .light))
                }
                .colorScheme(settings.homeColorScheme == .light ? .light : .dark)
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

#Preview {
    NavigationStack {
        CustomizeThemeView()
    }
    .environment(VoyagerStore.shared)
    .environment(AppSettings.shared)
}
