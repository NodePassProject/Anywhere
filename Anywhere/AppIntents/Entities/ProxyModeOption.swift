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
        .rule: DisplayRepresentation(title: "Proxy Mode", image: .init(named: "anywhere.proxy")),
        .global: DisplayRepresentation(title: "Global Mode", image: .init(named: "anywhere.global")),
    ]

    var proxyMode: ProxyMode {
        switch self {
        case .rule: .rule
        case .global: .global
        }
    }
}
