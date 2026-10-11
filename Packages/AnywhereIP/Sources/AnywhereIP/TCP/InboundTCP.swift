//
//  InboundTCP.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

import Foundation

struct InboundTCP: @unchecked Sendable {
    let key: ConnectionKey
    let header: TCPHeader
    let options: UnsafeRawBufferPointer
    let payload: UnsafeRawBufferPointer
}
