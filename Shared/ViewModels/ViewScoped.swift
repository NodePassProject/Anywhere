//
//  ViewScoped.swift
//  Anywhere
//
//  Created by NodePassProject on 8/20/26.
//

import Foundation

@MainActor
final class ViewScoped<Value> {
    private var value: Value?

    func callAsFunction(_ make: () -> Value) -> Value {
        if let value { return value }
        let made = make()
        value = made
        return made
    }
}
