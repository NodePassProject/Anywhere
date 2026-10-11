//
//  ControlFrame.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

enum ControlFrame {
    case maxData(UInt64)
    case maxStreamData(id: UInt64, maximum: UInt64)
    case maxStreams(bidirectional: Bool, maximum: UInt64)
    case dataBlocked(UInt64)
    case streamDataBlocked(id: UInt64, limit: UInt64)
    case streamsBlocked(bidirectional: Bool, limit: UInt64)
    case newConnectionID(sequence: UInt64, retirePriorTo: UInt64, id: QUICConnectionID, token: QUICStatelessResetToken)
    case retireConnectionID(sequence: UInt64)
    case resetStream(id: UInt64, errorCode: UInt64, finalSize: UInt64)
    case stopSending(id: UInt64, errorCode: UInt64)

    var sentFrame: SentFrame {
        switch self {
        case .maxData(let value):
            return .maxData(value)
        case .maxStreamData(let id, let maximum):
            return .maxStreamData(id: id, maximum: maximum)
        case .maxStreams(let bidirectional, let maximum):
            return .maxStreams(bidirectional: bidirectional, maximum: maximum)
        case .dataBlocked(let limit):
            return .dataBlocked(limit)
        case .streamDataBlocked(let id, let limit):
            return .streamDataBlocked(id: id, limit: limit)
        case .streamsBlocked(let bidirectional, let limit):
            return .streamsBlocked(bidirectional: bidirectional, limit: limit)
        case .newConnectionID(let sequence, _, _, _):
            return .newConnectionID(sequence: sequence)
        case .retireConnectionID(let sequence):
            return .retireConnectionID(sequence: sequence)
        case .resetStream(let id, _, _):
            return .resetStream(id: id)
        case .stopSending(let id, _):
            return .stopSending(id: id)
        }
    }

    func write(to writer: inout OutputBuffer) -> Bool {
        switch self {
        case .maxData(let value):
            return writer.writeMaxData(value)
        case .maxStreamData(let id, let maximum):
            return writer.writeMaxStreamData(streamID: id, maximum: maximum)
        case .maxStreams(let bidirectional, let maximum):
            return writer.writeMaxStreams(bidirectional: bidirectional, maximum: maximum)
        case .dataBlocked(let limit):
            return writer.writeDataBlocked(limit)
        case .streamDataBlocked(let id, let limit):
            return writer.writeStreamDataBlocked(streamID: id, limit: limit)
        case .streamsBlocked(let bidirectional, let limit):
            return writer.writeStreamsBlocked(bidirectional: bidirectional, limit: limit)
        case .newConnectionID(let sequence, let retirePriorTo, let id, let token):
            return writer.writeNewConnectionID(sequence: sequence, retirePriorTo: retirePriorTo, id: id, token: token)
        case .retireConnectionID(let sequence):
            return writer.writeRetireConnectionID(sequence: sequence)
        case .resetStream(let id, let errorCode, let finalSize):
            return writer.writeResetStream(streamID: id, errorCode: errorCode, finalSize: finalSize)
        case .stopSending(let id, let errorCode):
            return writer.writeStopSending(streamID: id, errorCode: errorCode)
        }
    }
}
