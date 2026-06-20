//
//  CustomizeAppIconView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI
import UIKit

struct AppIconOption: Identifiable {
    let alternateName: String?
    let displayName: String.LocalizationValue
    let previewName: String

    var id: String { alternateName ?? "AppIcon" }

    static let all: [AppIconOption] = [
        AppIconOption(
            alternateName: nil,
            displayName: "Default",
            previewName: "AppIcon-Sample"
        ),
        AppIconOption(
            alternateName: "AppIcon-Classic",
            displayName: "Classic",
            previewName: "AppIcon-Classic-Sample"
        ),
        AppIconOption(
            alternateName: "AppIcon-Muted",
            displayName: "Muted",
            previewName: "AppIcon-Muted-Sample"
        ),
    ]
}

struct CustomizeAppIconView: View {
    @Environment(VoyagerStore.self) private var voyagerStore
    @State private var selectedName: String? = UIApplication.shared.alternateIconName
    @State private var errorMessage: String?

    var body: some View {
        Form {
            if !voyagerStore.isMember {
                VoyagerNotice("Custom app icons are available to Anywhere Voyager members.")
            }
            Section {
                ForEach(AppIconOption.all) { option in
                    Button {
                        select(option)
                    } label: {
                        row(for: option)
                    }
                    .buttonStyle(.plain)
                    .disabled(!voyagerStore.isMember)
                }
            }
        }
        .navigationTitle("App Icon")
        .onAppear {
            selectedName = UIApplication.shared.alternateIconName
        }
        .alert("Error", isPresented: showErrorAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(errorMessage ?? "")
        }
    }

    private var showErrorAlert: Binding<Bool> {
        Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )
    }

    private func row(for option: AppIconOption) -> some View {
        HStack(spacing: 16) {
            preview(for: option)
            Text(String(localized: option.displayName))
                .foregroundStyle(.primary)
            Spacer()
            if option.alternateName == selectedName {
                Image(systemName: "checkmark")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.tint)
            }
        }
        .contentShape(.rect)
    }

    private func preview(for option: AppIconOption) -> some View {
        Image(option.previewName)
            .resizable()
            .scaledToFit()
            .frame(width: 58, height: 58)
            .clipShape(.rect(cornerRadius: 13, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .strokeBorder(.quaternary, lineWidth: 0.5)
            }
            .shadow(color: .black.opacity(0.1), radius: 2, y: 1)
    }

    private func select(_ option: AppIconOption) {
        guard voyagerStore.isMember, selectedName != option.alternateName else { return }
        let previous = selectedName
        selectedName = option.alternateName
        UIApplication.shared.setAlternateIconName(option.alternateName) { error in
            if let error {
                Task { @MainActor in
                    selectedName = previous
                    errorMessage = error.localizedDescription
                }
            }
        }
    }
}

#Preview {
    NavigationStack {
        CustomizeAppIconView()
    }
    .environment(VoyagerStore.shared)
}
