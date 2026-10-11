//
//  Constants+TCP.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/25/26.
//

extension Constants {
    static let maximumSegmentSize: UInt16 = 1460
    static let window: UInt32 = 64 * 1460
    static let sendBufferSize: UInt32 = 64 * 1460
    static let sendQueueLimit = 256
    static let receiveScale: UInt8 = 7
    static let initialMSS: UInt16 = 536
    static let initialRTO: Int16 = 5
    static let maximumRetransmissions: UInt8 = 8
    static let synReceivedTimeout: UInt32 = 100
    static let finWait2Timeout: UInt32 = 100
    static let lastAckTimeout: UInt32 = 10
    static let timeWaitTimeout: UInt32 = 10
    static let arenaReclaimDelay: UInt32 = 10
    static let receiveChunkSize = 16 * 1024
    static let receiveSealDelay: UInt32 = 1
    static let coarseTimerThreshold: UInt32 = 10
    static let coarseTimerGranularity: UInt32 = 5
    static let resetWindow: UInt16 = 730
    static let retransmissionBackoff: [Int16] = [1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7]
    static let persistBackoff: [UInt8] = [3, 6, 12, 24, 48, 96, 120]
}
