//
//  ProxyModeOption.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation

nonisolated enum ProxyModeOption: String, AppEnum {
    case rule
    case global

    static let typeDisplayRepresentation = TypeDisplayRepresentation(name: "Mode")

    static let caseDisplayRepresentations: [ProxyModeOption: DisplayRepresentation] = [
        .rule: DisplayRepresentation(title: "Proxy Mode", image: .init(systemName: "arrow.triangle.branch")),
        .global: DisplayRepresentation(title: "Global Mode", image: .init(systemName: "arrow.triangle.merge")),
    ]

    var proxyMode: ProxyMode {
        switch self {
        case .rule: .rule
        case .global: .global
        }
    }
}
