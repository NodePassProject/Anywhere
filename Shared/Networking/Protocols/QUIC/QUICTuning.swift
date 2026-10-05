//
//  QUICTuning.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import AnywhereQUIC

nonisolated struct QUICTuning {

    // MARK: Congestion control

    enum CongestionControl {
        case reno
        case cubic
        case bbr
        case brutal(initialBps: UInt64)
    }

    var cc: CongestionControl

    func makeCongestionController() -> any QUICCongestionController {
        switch cc {
        case .reno: QUICNewRenoCongestionController()
        case .cubic: QUICCubicCongestionController()
        case .bbr: QUICBBRCongestionController()
        case .brutal(let initialBps): QUICBrutalCongestionController(bytesPerSecond: initialBps)
        }
    }

    // MARK: Flow-control windows
    
    var maxStreamWindow: UInt64
    var maxWindow: UInt64

    // MARK: Initial transport parameters

    var initialMaxData: UInt64
    var initialMaxStreamDataBidiLocal: UInt64
    var initialMaxStreamDataBidiRemote: UInt64
    var initialMaxStreamDataUni: UInt64
    var initialMaxStreamsBidi: UInt64
    var initialMaxStreamsUni: UInt64

    // MARK: Timeouts (nanoseconds)

    var maxIdleTimeout: UInt64
    var handshakeTimeout: UInt64
    var keepAliveTimeout: UInt64

    // MARK: Misc
    
    var disableActiveMigration: Bool
}

nonisolated extension QUICTuning {
    static let http3 = QUICTuning(
        cc: .cubic,
        maxStreamWindow: 64 * 1024 * 1024,
        maxWindow: 128 * 1024 * 1024,
        initialMaxData: 64 * 1024 * 1024,
        initialMaxStreamDataBidiLocal: 16 * 1024 * 1024,
        initialMaxStreamDataBidiRemote: 16 * 1024 * 1024,
        initialMaxStreamDataUni: 16 * 1024 * 1024,
        initialMaxStreamsBidi: 1024,
        initialMaxStreamsUni: 100,
        maxIdleTimeout: 30 * 1_000_000_000,
        handshakeTimeout: 10 * 1_000_000_000,
        keepAliveTimeout: 15 * 1_000_000_000,
        disableActiveMigration: false
    )
    
    static func hysteria(congestionControl: HysteriaCongestionControl, uploadMbps: Int) -> QUICTuning {
        switch congestionControl {
        case .brutal:
            let bps = UInt64(max(0, uploadMbps)) * 1_000_000 / 8
            return QUICTuning(
                cc: .brutal(initialBps: bps),
                maxStreamWindow: 2 * 1024 * 1024,
                maxWindow: 4 * 1024 * 1024,
                initialMaxData: 4 * 1024 * 1024,
                initialMaxStreamDataBidiLocal: 2 * 1024 * 1024,
                initialMaxStreamDataBidiRemote: 2 * 1024 * 1024,
                initialMaxStreamDataUni: 2 * 1024 * 1024,
                initialMaxStreamsBidi: 1024,
                initialMaxStreamsUni: 16,
                maxIdleTimeout: 30 * 1_000_000_000,
                handshakeTimeout: 10 * 1_000_000_000,
                keepAliveTimeout: 10 * 1_000_000_000,
                disableActiveMigration: false
            )
        case .bbr:
            return QUICTuning(
                cc: .bbr,
                maxStreamWindow: 16 * 1024 * 1024,
                maxWindow: 32 * 1024 * 1024,
                initialMaxData: 8 * 1024 * 1024,
                initialMaxStreamDataBidiLocal: 2 * 1024 * 1024,
                initialMaxStreamDataBidiRemote: 2 * 1024 * 1024,
                initialMaxStreamDataUni: 2 * 1024 * 1024,
                initialMaxStreamsBidi: 1024,
                initialMaxStreamsUni: 16,
                maxIdleTimeout: 30 * 1_000_000_000,
                handshakeTimeout: 10 * 1_000_000_000,
                keepAliveTimeout: 10 * 1_000_000_000,
                disableActiveMigration: false
            )
        }
    }
    
    static let nowhere = QUICTuning(
        cc: .bbr,
        maxStreamWindow: 16 * 1024 * 1024,
        maxWindow: 32 * 1024 * 1024,
        initialMaxData: 8 * 1024 * 1024,
        initialMaxStreamDataBidiLocal: 4 * 1024 * 1024,
        initialMaxStreamDataBidiRemote: 0,
        initialMaxStreamDataUni: 0,
        initialMaxStreamsBidi: 0,
        initialMaxStreamsUni: 0,
        maxIdleTimeout: 30 * 1_000_000_000,
        handshakeTimeout: 10 * 1_000_000_000,
        keepAliveTimeout: 10 * 1_000_000_000,
        disableActiveMigration: false
    )
}
