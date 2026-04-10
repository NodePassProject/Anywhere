//
//  AddProxyView.swift
//  Anywhere
//
//  Created by Argsment Limited on 2/16/26.
//

import SwiftUI

fileprivate enum LinkType:  CaseIterable {
    case subscription
    case http11Proxy
    case http2Proxy
}

fileprivate enum Method: String, CaseIterable, Identifiable {
    var id: String { self.rawValue }

    case qrCode = "qrCode"
    case link = "link"
    case manual = "manual"
    case anywherePremiumProxy = "anywherePremiumProxy"
    
    var useCustomSymbol: Bool {
        switch self {
        case .qrCode, .link, .manual: false
        case .anywherePremiumProxy: true
        }
    }

    var image: String {
        switch self {
        case .qrCode: "qrcode.viewfinder"
        case .link: "link"
        case .manual: "hand.point.up.left"
        case .anywherePremiumProxy: "anywhere"
        }
    }

    var title: String {
        switch self {
        case .qrCode: String(localized: "QR Code")
        case .link: String(localized: "Link")
        case .manual: String(localized: "Manual")
        case .anywherePremiumProxy: String(localized: "Anywhere Premium Proxy")
        }
    }
}

struct AddProxyView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared
    @Environment(\.dismiss) var dismiss
    @Binding var showingManualAddSheet: Bool
    var deepLinkAction: DeepLinkAction?

    @State private var selectedMethod: Method?
    @State private var showingQRScanner = false
    @State private var linkURL = ""
    @State private var linkType: LinkType = .subscription
    @State private var isLoading = false
    @State private var showingError = false
    @State private var errorMessage = ""
    
    private var anywherePremiumProxyConfiguration: ProxyConfiguration? {
        viewModel.configurations.first {
            if case .vless(let id, _, _) = $0.outbound {
                if id == $0.id { return true }
            }
            return false
        }
    }
    private var availableMethods: [Method] {
        if anywherePremiumProxyConfiguration == nil { return Method.allCases }
        return Method.allCases.filter { $0 != .anywherePremiumProxy }
    }

    init(showingManualAddSheet: Binding<Bool>, deepLinkAction: DeepLinkAction? = nil) {
        _showingManualAddSheet = showingManualAddSheet
        self.deepLinkAction = deepLinkAction
        switch deepLinkAction {
        case .addProxyWithLink(let url):
            _selectedMethod = State(initialValue: .link)
            _linkURL = State(initialValue: url)
        case .addProxyManual(let url):
            _selectedMethod = State(initialValue: .link)
            _linkURL = State(initialValue: url)
        case nil:
            break
        }
    }

    var body: some View {
        VStack(spacing: 20) {
            header
                .geometryGroup()
            
            VStack {
                methodPicker
                    .geometryGroup()
                
                if selectedMethod == .link {
                    linkInputField
                        .transition(.opacity.combined(with: .move(edge: .bottom)))
                        .geometryGroup()
                }
            }
            
            continueButton
        }
        .padding(20)
        .frame(maxHeight: .infinity, alignment: .bottom)
        .onAppear {
            
        }
        .onChange(of: selectedMethod) {
            if selectedMethod == .link && linkURL.isEmpty {
                checkClipboard()
            }
        }
        .qrScanner(isScanning: $showingQRScanner) { code in
            importFromString(code)
        }
        .alert("Import Failed", isPresented: $showingError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(errorMessage)
        }
    }

    private var isContinueDisabled: Bool {
        switch selectedMethod {
        case .link: linkURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isLoading
        case nil: true
        default: false
        }
    }
    
    @ViewBuilder
    var header: some View {
        HStack {
            Text("Add Proxy")
                .font(.title2)
                .fontWeight(.semibold)

            Spacer(minLength: 0)

            if #available(iOS 26.0, *) {
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark")
                        .frame(width: 15, height: 15)
                        .padding(10)
                        .glassEffect(.regular.interactive(), in: .circle)
                }
                .buttonStyle(.plain)
            }
            else {
                Button {
                    dismiss()
                } label: {
                    Image(systemName: "xmark")
                        .frame(width: 15, height: 15)
                        .padding(10)
                }
                .buttonStyle(.plain)
            }
        }
    }

    // MARK: - Method Picker
    
    @ViewBuilder
    var methodPicker: some View {
        ForEach(availableMethods) { method in
            let isSelected: Bool = selectedMethod == method
            
            HStack(spacing: 10) {
                let image = method.image
                if method.useCustomSymbol {
                    Image(image)
                        .font(.title)
                        .frame(width: 40)
                } else {
                    Image(systemName: image)
                        .font(.title)
                        .frame(width: 40)
                }
                
                Text(method.title)
                    .fontWeight(.semibold)
                
                Spacer(minLength: 0)
                
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle.fill")
                    .font(.title)
                    .contentTransition(.symbolEffect)
                    .foregroundStyle(isSelected ? Color.blue : Color.gray.opacity(0.2))
            }
            .padding(.vertical, 6)
            .contentShape(.rect)
            .onTapGesture {
                withAnimation(.snappy) {
                    selectedMethod = isSelected ? nil : method
                }
            }
        }
    }

    // MARK: - Link Input

    private var linkInputField: some View {
        VStack {
            if linkURL.hasPrefix("http://") || linkURL.hasPrefix("https://") {
                Picker("Link Type", selection: $linkType) {
                    Text("Subscription").tag(LinkType.subscription)
                    Text("HTTPS Proxy").tag(LinkType.http11Proxy)
                    Text("HTTP/2 Proxy").tag(LinkType.http2Proxy)
                }
                .pickerStyle(.segmented)
            }
            TextField(String("Link"), text: $linkURL)
                .textFieldStyle(LinkTextFieldStyle())
                .textInputAutocapitalization(.never)
                .keyboardType(.URL)
                .autocorrectionDisabled()
            Text("Supports proxy, subscription and Clash links")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.top, 12)
    }
    
    // MARK: - Continue Button
    @ViewBuilder
    private var continueButton: some View {
        if #available(iOS 26.0, *) {
            Button {
                handleContinue()
            } label: {
                if isLoading {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                } else {
                    Text("Continue")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
            }
            .disabled(isContinueDisabled)
            .buttonStyle(.glassProminent)
            .geometryGroup()
        } else {
            Button {
                handleContinue()
            } label: {
                if isLoading {
                    ProgressView()
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                } else {
                    Text("Continue")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                }
            }
            .disabled(isContinueDisabled)
            .buttonStyle(.borderedProminent)
            .geometryGroup()
        }
    }

    // MARK: - Actions

    private func checkClipboard() {
        if let clip = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines),
           clip.hasPrefix("vless://") || clip.hasPrefix("ss://") || clip.hasPrefix("http://") || clip.hasPrefix("https://") {
            linkURL = clip
        }
    }

    private func handleContinue() {
        switch selectedMethod {
        case .qrCode:
            showingQRScanner = true
        case .link:
            importFromString(linkURL)
        case .manual:
            showingManualAddSheet = true
            dismiss()
        case .anywherePremiumProxy:
            importAnywherePremiumProxy()
        case .none:
            break
        }
    }

    private func importAnywherePremiumProxy() {
        isLoading = true
        Task {
            do {
                struct CreateUserResponse: Decodable { let uuid: UUID }
                var request = URLRequest(url: URL(string: "https://anywhere-premium-proxy.argsment.com/users")!)
                request.httpMethod = "POST"
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                let (data, response) = try await URLSession.shared.data(for: request)
                if let httpResponse = response as? HTTPURLResponse,
                   !(200...299).contains(httpResponse.statusCode) {
                    throw NSError(
                        domain: "AnywherePremiumProxy",
                        code: httpResponse.statusCode,
                        userInfo: [NSLocalizedDescriptionKey: "HTTP \(httpResponse.statusCode)"]
                    )
                }
                let uuid = try JSONDecoder().decode(CreateUserResponse.self, from: data).uuid
                let configuration = ProxyConfiguration(
                    id: uuid,
                    name: String(localized: "Anywhere Premium Proxy"),
                    serverAddress: "anywhere.stdco.de",
                    serverPort: 443,
                    outbound: .vless(uuid: uuid, encryption: "none", flow: nil),
                    transportLayer: .xhttp(
                        XHTTPConfiguration(host: "anywhere.stdco.de", path: "/app")
                    ),
                    securityLayer: .tls(
                        TLSConfiguration(serverName: "anywhere.stdco.de", fingerprint: .chrome120)
                    ),
                    muxEnabled: true,
                    xudpEnabled: true
                )
                viewModel.addConfiguration(configuration)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
                showingError = true
            }
            isLoading = false
        }
    }

    private func importFromString(_ string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        let isHTTP = trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://")

        if trimmed.hasPrefix("vless://") || trimmed.hasPrefix("ss://") ||
            trimmed.hasPrefix("socks5://") || trimmed.hasPrefix("socks://") ||
            (isHTTP && linkType != .subscription) {
            // Single proxy link (VLESS, Shadowsocks, SOCKS5, or NaiveProxy)
            let naiveProtocol: OutboundProtocol? = switch linkType {
            case .http11Proxy: .http11
            case .http2Proxy: .http2
            case .subscription: nil
            }
            do {
                let configuration = try ProxyConfiguration.parse(url: trimmed, naiveProtocol: naiveProtocol)
                viewModel.addConfiguration(configuration)
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
                showingError = true
            }
        } else {
            // Treat as subscription URL
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
                    viewModel.addSubscription(configurations: result.configurations, subscription: subscription)
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

private struct LinkTextFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .padding(16)
            .background(.gray.opacity(0.1), in: .capsule)
    }
}
