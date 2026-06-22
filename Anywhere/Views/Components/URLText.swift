//
//  URLText.swift
//  Anywhere
//
//  Created by NodePassProject on 6/22/26.
//

import SwiftUI

struct URLText: UIViewRepresentable {
    let urlString: String

    func makeUIView(context: Context) -> UILabel {
        let label = UILabel()
        label.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        label.textColor = .secondaryLabel
        label.numberOfLines = 3
        label.lineBreakMode = .byTruncatingMiddle
        label.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        label.isUserInteractionEnabled = true

        let interaction = UIEditMenuInteraction(delegate: context.coordinator)
        label.addInteraction(interaction)

        let tap = UITapGestureRecognizer(
            target: context.coordinator,
            action: #selector(Coordinator.tapped(_:))
        )
        label.addGestureRecognizer(tap)

        return label
    }

    func updateUIView(_ uiView: UILabel, context: Context) {
        uiView.text = urlString
        context.coordinator.text = urlString
    }

    func sizeThatFits(_ proposal: ProposedViewSize, uiView: UILabel, context: Context) -> CGSize? {
        let proposed = proposal.width ?? uiView.intrinsicContentSize.width
        let width = proposed.isFinite ? proposed : uiView.intrinsicContentSize.width
        let height = uiView.systemLayoutSizeFitting(
            CGSize(width: width, height: UIView.layoutFittingCompressedSize.height),
            withHorizontalFittingPriority: .required,
            verticalFittingPriority: .fittingSizeLevel
        ).height
        return CGSize(width: width, height: height)
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(text: urlString)
    }

    class Coordinator: NSObject, UIEditMenuInteractionDelegate {
        var text: String
        init(text: String) { self.text = text }

        @objc func tapped(_ sender: UITapGestureRecognizer) {
            guard let label = sender.view,
                  let interaction = label.interactions
                      .compactMap({ $0 as? UIEditMenuInteraction }).first
            else { return }

            let config = UIEditMenuConfiguration(
                identifier: nil,
                sourcePoint: sender.location(in: label)
            )
            interaction.presentEditMenu(with: config)
        }

        func editMenuInteraction(
            _ interaction: UIEditMenuInteraction,
            menuFor config: UIEditMenuConfiguration,
            suggestedActions: [UIMenuElement]
        ) -> UIMenu? {
            let copy = UIAction(title: String(localized: "Copy")) { _ in
                UIPasteboard.general.string = self.text
            }
            return UIMenu(children: [copy])
        }
    }
}
