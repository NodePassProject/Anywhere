//
//  TVRootView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/27/26.
//

import SwiftUI

struct TVRootView: View {
    let container: AppContainer

    var body: some View {
        TabView {
            Tab("Launchpad", image: "anywhere") {
                TVPageHost { TVLaunchpadViewController(container: container) }
                    .ignoresSafeArea()
            }
            Tab("Data", systemImage: "cylinder.split.1x2.fill") {
                TVPageHost { TVDataViewController(container: container) }
                    .ignoresSafeArea()
            }
            Tab("Tunnel", systemImage: "hammer.fill") {
                TVPageHost { TVTunnelViewController(container: container) }
                    .ignoresSafeArea()
            }
            Tab("Trusted Certificates", systemImage: "checkmark.seal.fill") {
                TVPageHost { TVTrustedCertificatesViewController(container: container) }
                    .ignoresSafeArea()
            }
        }
        .tabViewStyle(.sidebarAdaptable)
    }
}

private struct TVPageHost: UIViewControllerRepresentable {
    let makeController: () -> UIViewController

    func makeUIViewController(context: Context) -> UIViewController {
        makeController()
    }

    func updateUIViewController(_ uiViewController: UIViewController, context: Context) {}
}
