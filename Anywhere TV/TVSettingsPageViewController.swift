//
//  TVSettingsPageViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 8/27/26.
//

import UIKit

class TVSettingsPageViewController: UIViewController {
    let container: AppContainer

    private let titleLabel = UILabel()
    private let contentStack = UIStackView()

    init(container: AppContainer, pageTitle: String) {
        self.container = container
        super.init(nibName: nil, bundle: nil)
        title = pageTitle
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        titleLabel.text = title
        titleLabel.font = .systemFont(ofSize: 48, weight: .bold)
        titleLabel.textColor = .label
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(titleLabel)

        contentStack.axis = .vertical
        contentStack.spacing = 24
        contentStack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(contentStack)

        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 40),
            titleLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 80),
            titleLabel.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -80),

            contentStack.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 60),
            contentStack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 80),
            contentStack.widthAnchor.constraint(equalToConstant: 800),
        ])
    }

    // MARK: - Content

    func addRow(_ row: UIView) {
        contentStack.addArrangedSubview(row)
    }

    func addFooter(_ text: String) {
        let label = UILabel()
        label.text = text
        label.font = .systemFont(ofSize: 26)
        label.textColor = .secondaryLabel
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false

        let wrapper = UIView()
        wrapper.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: wrapper.leadingAnchor, constant: 30),
            label.trailingAnchor.constraint(equalTo: wrapper.trailingAnchor, constant: -30),
            label.topAnchor.constraint(equalTo: wrapper.topAnchor),
            label.bottomAnchor.constraint(equalTo: wrapper.bottomAnchor),
        ])

        if let last = contentStack.arrangedSubviews.last {
            contentStack.setCustomSpacing(16, after: last)
        }
        contentStack.addArrangedSubview(wrapper)
    }
}
