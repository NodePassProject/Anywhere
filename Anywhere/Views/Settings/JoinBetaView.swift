//
//  JoinBetaView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/24/26.
//

import SwiftUI

struct JoinBetaView: View {
    @Environment(VoyagerStore.self) private var voyagerStore

    @State private var copied = false

    var body: some View {
        Form {
            if !voyagerStore.isMember {
                VoyagerNotice("Public Beta is available to Anywhere Voyager members.")
            }

            Section {
                Button {
                    Task { await copyToken() }
                } label: {
                    Label("Copy Verification Token", systemImage: copied ? "checkmark" : "doc.on.doc")
                        .contentTransition(.symbolEffect(.replace))
                }
            }
            .disabled(!voyagerStore.isMember)
        }
        .navigationTitle("Public Beta")
    }

    private func copyToken() async {
        guard let token = await voyagerStore.verificationToken() else { return }
        UIPasteboard.general.string = token
        copied = true
        try? await Task.sleep(for: .seconds(2))
        copied = false
    }
}
