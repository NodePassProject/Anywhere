//
//  AddProxyView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/14/26.
//

import SwiftUI

private enum LinkType: CaseIterable {
    case subscription
    case http11Proxy
    case http2Proxy
}

struct AddProxyView: View {
    @Environment(\.dismiss) var dismiss
    var onImport: ((ProxyConfiguration) -> Void)?
    var onSubscriptionImport: (([ProxyConfiguration], Subscription) -> Void)?

    @State private var linkURL = ""
    @State private var linkType: LinkType = .subscription
    @State private var isLoading = false
    @State private var showingError = false
    @State private var errorMessage = ""

    var body: some View {
        NavigationStack {
            VStack {
                VStack(spacing: 0) {
                    TextField("Link", text: $linkURL)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                    Text("Supports proxy, subscription and Clash links")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                
                if linkURL.hasPrefix("http://") || linkURL.hasPrefix("https://") {
                    Picker("Link Type", selection: $linkType) {
                        Text("Subscription").tag(LinkType.subscription)
                        Text("HTTPS Proxy").tag(LinkType.http11Proxy)
                        Text("HTTP/2 Proxy").tag(LinkType.http2Proxy)
                    }
                    .pickerStyle(.segmented)
                }
                
                Button {
                    importFromLink()
                } label: {
                    if isLoading {
                        ProgressView()
                    } else {
                        Text("Continue")
                    }
                }
                .disabled(linkURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isLoading)
            }
            .padding(.horizontal)
        }
        .navigationTitle("Add Proxy")
        .alert("Import Failed", isPresented: $showingError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(errorMessage)
        }
    }

    // MARK: - Import

    private func importFromLink() {
        let trimmed = linkURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let isHTTP = trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://")

        if trimmed.hasPrefix("vless://") || trimmed.hasPrefix("ss://") ||
            (isHTTP && linkType != .subscription) {
            let naiveProtocol: OutboundProtocol? = switch linkType {
            case .http11Proxy: .http11
            case .http2Proxy: .http2
            case .subscription: nil
            }
            do {
                let configuration = try ProxyConfiguration.parse(url: trimmed, naiveProtocol: naiveProtocol)
                onImport?(configuration)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
                showingError = true
            }
        } else {
            isLoading = true
            Task {
                do {
                    let result = try await SubscriptionFetcher.fetch(url: trimmed)
                    let subscription = Subscription(
                        name: result.name ?? URL(string: trimmed)?.host ?? String(localized: "Subscription"),
                        url: trimmed,
                        lastUpdate: Date(),
                        upload: result.upload,
                        download: result.download,
                        total: result.total,
                        expire: result.expire
                    )
                    onSubscriptionImport?(result.configurations, subscription)
                    dismiss()
                } catch {
                    errorMessage = error.localizedDescription
                    showingError = true
                }
                isLoading = false
            }
        }
    }
}
