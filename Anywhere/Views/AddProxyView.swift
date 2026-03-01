//
//  AddProxyView.swift
//  Anywhere
//
//  Created by Argsment Limited on 2/16/26.
//

import SwiftUI

fileprivate enum Method: String, CaseIterable, Identifiable {
    var id: String { self.rawValue }

    case qrCode = "qrCode"
    case link = "link"
    case manual = "manual"

    var systemImage: String {
        switch self {
        case .qrCode: "qrcode.viewfinder"
        case .link: "link"
        case .manual: "hand.point.up.left"
        }
    }

    var title: String {
        switch self {
        case .qrCode: String(localized: "QR Code")
        case .link: String(localized: "Link")
        case .manual: String(localized: "Manual")
        }
    }
}

struct AddProxyView: View {
    @Environment(\.dismiss) var dismiss
    @Binding var showingManualAddSheet: Bool
    var onImport: ((VLESSConfiguration) -> Void)?
    var onSubscriptionImport: (([VLESSConfiguration], Subscription) -> Void)?

    @State private var selectedMethod: Method?
    @State private var showingQRScanner = false
    @State private var linkURL = ""
    @State private var isLoading = false
    @State private var showingLinkError = false
    @State private var linkErrorMessage = ""

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
        .padding(20)
        .frame(maxHeight: .infinity, alignment: .bottom)
        .onChange(of: selectedMethod) {
            if selectedMethod == .link && linkURL.isEmpty {
                checkClipboard()
            }
        }
        .qrScanner(isScanning: $showingQRScanner) { code in
            importFromString(code)
        }
        .alert("Import Failed", isPresented: $showingLinkError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(linkErrorMessage)
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
        ForEach(Method.allCases) { method in
            let isSelected: Bool = selectedMethod == method
            
            HStack(spacing: 10) {
                Image(systemName: method.systemImage)
                    .font(.title)
                    .frame(width: 40)
                
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
        TextField(String("vless:// or https://"), text: $linkURL)
            .textFieldStyle(LinkTextFieldStyle())
            .textInputAutocapitalization(.never)
            .keyboardType(.URL)
            .autocorrectionDisabled()
            .padding(.top, 12)
    }

    // MARK: - Actions

    private func checkClipboard() {
        if let clip = UIPasteboard.general.string?.trimmingCharacters(in: .whitespacesAndNewlines),
           clip.hasPrefix("vless://") || clip.hasPrefix("http://") || clip.hasPrefix("https://") {
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
        case .none:
            break
        }
    }

    private func importFromString(_ string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)

        if trimmed.hasPrefix("vless://") {
            // Single VLESS link
            do {
                let configuration = try VLESSConfiguration.parse(url: trimmed)
                onImport?(configuration)
                dismiss()
            } catch {
                linkErrorMessage = error.localizedDescription
                showingLinkError = true
            }
        } else {
            // Treat as subscription URL
            isLoading = true
            Task {
                do {
                    let result = try await SubscriptionFetcher.fetch(url: trimmed)
                    let subscription = Subscription(
                        name: result.name ?? "Subscription",
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
                    linkErrorMessage = error.localizedDescription
                    showingLinkError = true
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
