//
//  String+init.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation

nonisolated extension String {
    init(nulTerminated buffer: [CChar]) {
        let length = buffer.firstIndex(of: 0) ?? buffer.count
        self = String(decoding: buffer[..<length].lazy.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
