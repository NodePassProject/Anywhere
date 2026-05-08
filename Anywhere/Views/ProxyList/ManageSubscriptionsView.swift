//
//  ManageSubscriptionsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/8/26.
//

import SwiftUI

struct ManageSubscriptionsView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared

    var body: some View {
        List {
            ForEach(viewModel.subscriptions) { subscription in
                VStack(alignment: .leading, spacing: 4) {
                    Text(subscription.name)
                        .font(.body.weight(.medium))
                    Text(subscription.url)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .truncationMode(.middle)
                        .lineLimit(1)
                }
            }
            .onMove { source, destination in
                viewModel.moveSubscriptions(fromOffsets: source, toOffset: destination)
            }
        }
        .environment(\.editMode, .constant(.active))
        .navigationTitle("Reorder Subscriptions")
    }
}
