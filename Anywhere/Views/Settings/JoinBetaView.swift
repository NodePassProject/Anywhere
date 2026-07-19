//
//  JoinBetaView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/24/26.
//

import SwiftUI

struct JoinBetaView: View {
    @Environment(VoyagerStore.self) private var voyagerStore

    @State private var token: String?
    @State private var copied = false
    @State private var reverifying = false

    var body: some View {
        Form {
            if !voyagerStore.isMember {
                VoyagerNotice("Public Beta is available to Anywhere Voyager members.")
            }

            Section {
                if voyagerStore.isMember && token != nil {
                    Button {
                        Task { await copyToken() }
                    } label: {
                        Label("Copy Verification Token", systemImage: copied ? "checkmark" : "doc.on.doc")
                            .contentTransition(.symbolEffect(.replace))
                    }
                } else {
                    Button {
                        Task { await reverify() }
                    } label: {
                        if reverifying {
                            ProgressView()
                        } else {
                            Label("Reverify Membership", systemImage: "arrow.clockwise")
                        }
                    }
                }
            }
            .disabled(!voyagerStore.isMember)
        }
        .navigationTitle("Public Beta")
        .task {
            token = await voyagerStore.verificationToken()
        }
    }

    private func copyToken() async {
        guard let token else { return }
        UIPasteboard.general.string = token
        copied = true
        try? await Task.sleep(for: .seconds(2))
        copied = false
    }
    
    private func reverify() async {
        reverifying = true
        defer { reverifying = false }
        await voyagerStore.reverifyMembership()
        token = await voyagerStore.verificationToken()
    }
}
