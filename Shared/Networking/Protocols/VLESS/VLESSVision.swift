//
//  VLESSVision.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Security
import Synchronization

// MARK: - Constants

nonisolated enum VisionCommand: UInt8 {
    case paddingContinue = 0x00
    case paddingEnd = 0x01
    case paddingDirect = 0x02
}

private nonisolated let tlsClientHandshakeStart: [UInt8] = [0x16, 0x03]
private nonisolated let tlsServerHandshakeStart: [UInt8] = [0x16, 0x03, 0x03]
private nonisolated let tlsApplicationDataStart: [UInt8] = [0x17, 0x03, 0x03]
private nonisolated let tls13SupportedVersions: [UInt8] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
private nonisolated let tlsHandshakeTypeClientHello: UInt8 = 0x01
private nonisolated let tlsHandshakeTypeServerHello: UInt8 = 0x02

private nonisolated let tls13CipherSuites: Set<UInt16> = [
    0x1301,  // TLS_AES_128_GCM_SHA256
    0x1302,  // TLS_AES_256_GCM_SHA384
    0x1303,  // TLS_CHACHA20_POLY1305_SHA256
    0x1304,  // TLS_AES_128_CCM_SHA256
    // 0x1305 (TLS_AES_128_CCM_8_SHA256) is excluded
]

// MARK: - Traffic State

nonisolated struct VisionTrafficState {
    enum WriterPhase: PhaseTransitionable {
        case padding
        case ended
        case direct

        static func canTransition(from old: WriterPhase, to new: WriterPhase) -> Bool {
            switch (old, new) {
            case (.padding, .ended),
                 (.padding, .direct):
                return true
            default:
                return false
            }
        }
    }

    enum ReaderPhase: PhaseTransitionable {
        case withinPadding
        case ended
        case direct
        case failed

        static func canTransition(from old: ReaderPhase, to new: ReaderPhase) -> Bool {
            switch (old, new) {
            case (.withinPadding, .ended),
                 (.withinPadding, .direct),
                 (.ended, .withinPadding),
                 (.ended, .direct):
                return true
            case (_, .failed):
                return old != .failed
            default:
                return false
            }
        }
    }

    let userUUID: Data

    var numberOfPacketsToFilter: Int = 8
    var enableXtls: Bool = false
    var isTLS12orAbove: Bool = false
    var isTLS: Bool = false
    var cipher: UInt16 = 0
    var remainingServerHello: Int32 = -1

    var writerPhase: WriterPhase = .padding
    var readerPhase: ReaderPhase = .withinPadding

    var remainingCommand: Int32 = -1
    var remainingContent: Int32 = -1
    var remainingPadding: Int32 = -1
    var currentCommand: Int = 0


    var writeOnceUserUUID: Data?

    init(userUUID: Data) {
        self.userUUID = userUUID
        self.writeOnceUserUUID = userUUID
    }
}

private nonisolated let visionPaddingSeed: [UInt32] = [900, 500, 900, 256]

// MARK: - Buffer Reshaping

private nonisolated let visionBufSize: Int32 = 8192

private nonisolated let reshapeThreshold: Int = 8192 - 21

private nonisolated func reshapeData(_ data: Data) -> [Data] {
    guard data.count >= reshapeThreshold else {
        return [data]
    }

    var splitIndex = data.count / 2
    data.withUnsafeBytes { pointer in
        let bytes = pointer.bindMemory(to: UInt8.self)
        for i in stride(from: bytes.count - 3, through: 0, by: -1) {
            if bytes[i] == 0x17 && bytes[i + 1] == 0x03 && bytes[i + 2] == 0x03 {
                if i >= 21 && i <= reshapeThreshold {
                    splitIndex = i
                    break
                }
            }
        }
    }

    let first = data.prefix(splitIndex)
    let second = data.suffix(from: data.index(data.startIndex, offsetBy: splitIndex))
    return reshapeData(first) + reshapeData(second)
}

// MARK: - Padding Functions

private nonisolated func visionPadding(data: Data?, command: VisionCommand, state: inout VisionTrafficState, longPadding: Bool) -> Data {
    let contentLen = Int32(data?.count ?? 0)
    var paddingLen: Int32 = 0

    if contentLen < Int32(visionPaddingSeed[0]) && longPadding {
        paddingLen = Int32.random(in: 0..<Int32(visionPaddingSeed[1])) + Int32(visionPaddingSeed[2]) - contentLen
    } else {
        paddingLen = Int32.random(in: 0..<Int32(visionPaddingSeed[3]))
    }

    let maxPadding = 8192 - 21 - contentLen
    if paddingLen > maxPadding {
        paddingLen = maxPadding
    }
    if paddingLen < 0 {
        paddingLen = 0
    }

    let uuidLen = state.writeOnceUserUUID != nil ? 16 : 0
    let totalLen = uuidLen + 5 + Int(contentLen) + Int(paddingLen)
    var result = Data(count: totalLen)
    result.withUnsafeMutableBytes { pointer in
        let p = pointer.bindMemory(to: UInt8.self)
        var offset = 0

        if let uuid = state.writeOnceUserUUID {
            uuid.copyBytes(to: p.baseAddress! + offset, count: 16)
            offset += 16
        }

        p[offset] = command.rawValue; offset += 1
        p[offset] = UInt8(contentLen >> 8); offset += 1
        p[offset] = UInt8(contentLen & 0xFF); offset += 1
        p[offset] = UInt8(paddingLen >> 8); offset += 1
        p[offset] = UInt8(paddingLen & 0xFF); offset += 1

        if let data = data {
            data.copyBytes(to: p.baseAddress! + offset, count: data.count)
            offset += data.count
        }

        if paddingLen > 0 {
            _ = SecRandomCopyBytes(kSecRandomDefault, Int(paddingLen), p.baseAddress! + offset)
        }
    }
    state.writeOnceUserUUID = nil

    return result
}

private nonisolated func visionUnpadding(data: inout Data, state: inout VisionTrafficState) -> Data {
    var readOffset = 0
    let dataCount = data.count
    let startIdx = data.startIndex

    if state.remainingCommand == -1 && state.remainingContent == -1 && state.remainingPadding == -1 {
        if dataCount >= 21 && data.prefix(16) == state.userUUID {
            readOffset = 16
            state.remainingCommand = 5
        } else {
            return data
        }
    }

    var result = Data()

    while readOffset < dataCount {
        if state.remainingCommand > 0 {
            let byte = data[startIdx + readOffset]
            readOffset += 1
            switch state.remainingCommand {
            case 5:
                state.currentCommand = Int(byte)
            case 4:
                state.remainingContent = Int32(byte) << 8
            case 3:
                state.remainingContent |= Int32(byte)
            case 2:
                state.remainingPadding = Int32(byte) << 8
            case 1:
                state.remainingPadding |= Int32(byte)
            default:
                break
            }
            state.remainingCommand -= 1
        } else if state.remainingContent > 0 {
            let remaining = dataCount - readOffset
            let toRead = min(Int(state.remainingContent), remaining)
            result.append(data[(startIdx + readOffset)..<(startIdx + readOffset + toRead)])
            readOffset += toRead
            state.remainingContent -= Int32(toRead)
        } else if state.remainingPadding > 0 {
            let remaining = dataCount - readOffset
            let toSkip = min(Int(state.remainingPadding), remaining)
            readOffset += toSkip
            state.remainingPadding -= Int32(toSkip)
        }

        if state.remainingCommand <= 0 && state.remainingContent <= 0 && state.remainingPadding <= 0 {
            switch state.currentCommand {
            case 0:
                state.remainingCommand = 5
            case 1, 2:
                state.remainingCommand = -1
                state.remainingContent = -1
                state.remainingPadding = -1
                if readOffset < dataCount {
                    result.append(data[(startIdx + readOffset)..<(startIdx + dataCount)])
                    readOffset = dataCount
                }
            default:
                VisionTrafficState.ReaderPhase.transition(&state.readerPhase, to: .failed)
                data = Data()
                return result
            }
            if state.currentCommand != 0 { break }
        }
    }

    if readOffset >= dataCount {
        data = Data()
    } else {
        data = Data(data[(startIdx + readOffset)...])
    }

    return result
}

// MARK: - TLS Filtering

private nonisolated func visionFilterTLS(data: Data, state: inout VisionTrafficState) {
    guard state.numberOfPacketsToFilter > 0 else { return }

    state.numberOfPacketsToFilter -= 1

    guard data.count >= 6 else { return }

    let startIdx = data.startIndex
    let byte0 = data[startIdx]
    let byte1 = data[data.index(startIdx, offsetBy: 1)]
    let byte2 = data[data.index(startIdx, offsetBy: 2)]
    let byte5 = data[data.index(startIdx, offsetBy: 5)]

    if byte0 == 0x16 && byte1 == 0x03 && byte2 == 0x03 && byte5 == tlsHandshakeTypeServerHello {
        let byte3 = data[data.index(startIdx, offsetBy: 3)]
        let byte4 = data[data.index(startIdx, offsetBy: 4)]
        state.remainingServerHello = (Int32(byte3) << 8 | Int32(byte4)) + 5
        state.isTLS12orAbove = true
        state.isTLS = true

        if data.count >= 79 && state.remainingServerHello >= 79 {
            let byte43 = data[data.index(startIdx, offsetBy: 43)]
            let sessionIdLen = Int(byte43)
            let cipherOffset = 43 + sessionIdLen + 1
            if data.count > cipherOffset + 2 {
                let cipherIdx = data.index(startIdx, offsetBy: cipherOffset)
                let cipherIdx1 = data.index(startIdx, offsetBy: cipherOffset + 1)
                state.cipher = UInt16(data[cipherIdx]) << 8 | UInt16(data[cipherIdx1])
            }
        }
    } else if byte0 == 0x16 && byte1 == 0x03 && byte5 == tlsHandshakeTypeClientHello {
        state.isTLS = true
    }

    if state.remainingServerHello > 0 {
        let end = min(Int(state.remainingServerHello), data.count)
        state.remainingServerHello -= Int32(data.count)

        if let _ = data.prefix(end).range(of: Data(tls13SupportedVersions)) {
            if tls13CipherSuites.contains(state.cipher) {
                state.enableXtls = true
            }
            state.numberOfPacketsToFilter = 0
            return
        } else if state.remainingServerHello <= 0 {
            state.numberOfPacketsToFilter = 0
            return
        }
    }
}

private nonisolated func visionDetectClientHello(data: Data, state: inout VisionTrafficState) {
    guard data.count >= 6 else { return }

    let startIdx = data.startIndex
    let byte0 = data[startIdx]
    let byte1 = data[data.index(startIdx, offsetBy: 1)]
    let byte5 = data[data.index(startIdx, offsetBy: 5)]

    if byte0 == 0x16 && byte1 == 0x03 && byte5 == tlsHandshakeTypeClientHello {
        state.isTLS = true
    }
}

private nonisolated func isCompleteTLSRecord(data: Data) -> Bool {
    let totalLen = data.count

    guard totalLen >= 5 else { return false }

    let startIdx = data.startIndex
    guard data[startIdx] == 0x17 &&
          data[data.index(startIdx, offsetBy: 1)] == 0x03 &&
          data[data.index(startIdx, offsetBy: 2)] == 0x03 else { return false }

    var offset = 0

    while offset < totalLen {
        guard offset + 5 <= totalLen else { return false }

        let idx0 = data.index(startIdx, offsetBy: offset)
        let idx1 = data.index(startIdx, offsetBy: offset + 1)
        let idx2 = data.index(startIdx, offsetBy: offset + 2)
        let idx3 = data.index(startIdx, offsetBy: offset + 3)
        let idx4 = data.index(startIdx, offsetBy: offset + 4)

        guard data[idx0] == 0x17,
              data[idx1] == 0x03,
              data[idx2] == 0x03 else { return false }

        let recordLen = Int(data[idx3]) << 8 | Int(data[idx4])
        offset += 5

        guard offset + recordLen <= totalLen else { return false }
        offset += recordLen
    }

    return offset == totalLen
}

// MARK: - Vision Connection Wrapper

nonisolated final class VLESSVisionConnection: ProxyConnection {
    private let innerConnection: ProxyConnection
    private let trafficState: Mutex<VisionTrafficState>

    private let sendChain = SerialSender()

    init(connection: ProxyConnection, userUUID: Data) {
        self.innerConnection = connection
        self.trafficState = Mutex(VisionTrafficState(userUUID: userUUID))
    }

    func sendEmptyPadding() async throws {
        let pending: SerialSender.Pending = trafficState.withLock { state in
            let padded = visionPadding(data: nil, command: .paddingContinue, state: &state, longPadding: true)
            let inner = self.innerConnection
            return sendChain.submit { try await inner.send(padded) }
        }
        try await pending.value()
    }

    var isConnected: Bool {
        return innerConnection.isConnected
    }

    // MARK: - Async Surface

    func sendRaw(_ data: Data) async throws {
        let pending: SerialSender.Pending = trafficState.withLock { state in
            let isDirectCopy = state.writerPhase == .direct
            let paddedData = processSendData(data, state: &state)
            let inner = self.innerConnection
            return sendChain.submit {
                if isDirectCopy {
                    try await inner.sendDirectRaw(paddedData)
                } else {
                    try await inner.send(paddedData)
                }
            }
        }
        try await pending.value()
    }

    func receive() async throws -> Data? {
        try await receiveRaw()
    }

    private func processSendData(_ data: Data, state: inout VisionTrafficState) -> Data {
        if !state.isTLS {
            visionDetectClientHello(data: data, state: &state)
        }

        guard state.writerPhase == .padding else {
            return data
        }

        let longPadding = state.isTLS
        let isComplete = isCompleteTLSRecord(data: data)

        let chunks = reshapeData(data)

        let startIdx = data.startIndex
        if state.isTLS && data.count >= 6 &&
           data[startIdx] == tlsApplicationDataStart[0] &&
           data[data.index(startIdx, offsetBy: 1)] == tlsApplicationDataStart[1] &&
           data[data.index(startIdx, offsetBy: 2)] == tlsApplicationDataStart[2] &&
           isComplete {

            var result = Data()
            for (i, chunk) in chunks.enumerated() {
                if i == chunks.count - 1 {
                    var command: VisionCommand = .paddingEnd
                    if state.enableXtls {
                        command = .paddingDirect
                        VisionTrafficState.WriterPhase.transition(&state.writerPhase, to: .direct)
                    } else {
                        VisionTrafficState.WriterPhase.transition(&state.writerPhase, to: .ended)
                    }
                    result.append(visionPadding(data: chunk, command: command, state: &state, longPadding: false))
                } else {
                    result.append(visionPadding(data: chunk, command: .paddingContinue, state: &state, longPadding: true))
                }
            }
            return result
        }

        if !state.isTLS12orAbove && state.numberOfPacketsToFilter <= 1 {
            VisionTrafficState.WriterPhase.transition(&state.writerPhase, to: .ended)
            var result = Data()
            for (i, chunk) in chunks.enumerated() {
                let cmd: VisionCommand = (i == chunks.count - 1) ? .paddingEnd : .paddingContinue
                result.append(visionPadding(data: chunk, command: cmd, state: &state, longPadding: longPadding))
            }
            return result
        }

        var result = Data()
        for chunk in chunks {
            result.append(visionPadding(data: chunk, command: .paddingContinue, state: &state, longPadding: longPadding))
        }
        return result
    }

    func receiveRaw() async throws -> Data? {
        while true {
            let readerPhase = trafficState.withLock { $0.readerPhase }
            if readerPhase == .failed {
                throw AnywhereError.proxy(.vless, .protocolViolation(detail: "Vision: invalid padding command"))
            }

            if readerPhase == .direct {
                let data = try await innerConnection.receiveDirectRaw()
                guard let data, !data.isEmpty else { return nil }
                return data
            }

            let received = try await innerConnection.receive()
            guard var data = received, !data.isEmpty else { return nil }

            let (processedData, failed) = trafficState.withLock { state in
                (processReceiveData(&data, state: &state), state.readerPhase == .failed)
            }
            if failed {
                throw AnywhereError.proxy(.vless, .protocolViolation(detail: "Vision: invalid padding command"))
            }

            if processedData.isEmpty {
                continue
            }
            return processedData
        }
    }

    private func processReceiveData(_ data: inout Data, state: inout VisionTrafficState) -> Data {
        if state.numberOfPacketsToFilter > 0 {
            visionFilterTLS(data: data, state: &state)
        }

        if state.readerPhase == .direct {
            return data
        }

        if state.readerPhase == .withinPadding || state.numberOfPacketsToFilter > 0 {
            let unpadded = visionUnpadding(data: &data, state: &state)

            if state.remainingContent > 0 || state.remainingPadding > 0 || state.currentCommand == 0 {
                VisionTrafficState.ReaderPhase.transition(&state.readerPhase, to: .withinPadding)
            } else if state.currentCommand == 1 {
                VisionTrafficState.ReaderPhase.transition(&state.readerPhase, to: .ended)
            } else if state.currentCommand == 2 {
                VisionTrafficState.ReaderPhase.transition(&state.readerPhase, to: .direct)
            }

            return unpadded
        }

        return data
    }

    func cancel() {
        sendChain.cancel()
        innerConnection.cancel()
    }
}
