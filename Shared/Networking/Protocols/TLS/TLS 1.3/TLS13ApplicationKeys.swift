//
//  TLS13ApplicationKeys.swift
//  Anywhere
//
//  Created by NodePassProject on 6/19/26.
//

import Foundation

struct TLS13ApplicationKeys {
    let clientKey: Data
    let clientIV: Data
    let serverKey: Data
    let serverIV: Data
    let clientTrafficSecret: Data
    let serverTrafficSecret: Data
}
