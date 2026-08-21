//
//  DiagnosisView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI

struct DiagnosisView: View {
    var body: some View {
        NavigationStack {
            List {
                NavigationLink {
                    RequestsView()
                } label: {
                    TextWithColorfulIcon(title: "Requests", comment: nil, systemName: "mail.fill", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                }
                NavigationLink {
                    LogsView()
                } label: {
                    TextWithColorfulIcon(title: "Logs", comment: nil, systemName: "long.text.page.and.pencil.fill", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                }
            }
            .navigationTitle("Diagnosis")
        }
    }
}
