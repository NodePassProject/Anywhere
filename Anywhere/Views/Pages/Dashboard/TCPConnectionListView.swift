//
//  TCPConnectionListView.swift
//  Anywhere
//
//  Created by NodePassProject on 9/23/26.
//

import SwiftUI

struct TCPConnectionListView: View {
    var body: some View {
        ActivityListView(
            .tcp,
            emptyTitle: "No TCP Connections",
            emptySystemImage: "arrow.left.arrow.right"
        )
        .navigationTitle("TCP Connections")
    }
}
