//
//  VLESSVision.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Security

// MARK: - Constants

enum VisionCommand: UInt8 {
    case paddingContinue = 0x00
    case paddingEnd = 0x01
    case paddingDirect = 0x02
}

private let tlsClientHandshakeStart: [UInt8] = [0x16, 0x03]
private let tlsServerHandshakeStart: [UInt8] = [0x16, 0x03, 0x03]
private let tlsApplicationDataStart: [UInt8] = [0x17, 0x03, 0x03]
private let tls13SupportedVersions: [UInt8] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
private let tlsHandshakeTypeClientHello: UInt8 = 0x01
private let tlsHandshakeTypeServerHello: UInt8 = 0x02

/// TLS 1.3 cipher suites that support XTLS direct copy
private let tls13CipherSuites: Set<UInt16> = [
    0x1301,  // TLS_AES_128_GCM_SHA256
    0x1302,  // TLS_AES_256_GCM_SHA384
    0x1303,  // TLS_CHACHA20_POLY1305_SHA256
    0x1304,  // TLS_AES_128_CCM_SHA256
    // 0x1305 (TLS_AES_128_CCM_8_SHA256) is excluded
]

// MARK: - Traffic State

/// Tracks TLS detection and padding state for Vision.
nonisolated class VisionTrafficState {
    let userUUID: Data

    var numberOfPacketsToFilter: Int = 8
    var enableXtls: Bool = false
    var isTLS12orAbove: Bool = false
    var isTLS: Bool = false
    var cipher: UInt16 = 0
    var remainingServerHello: Int32 = -1

    var writerIsPadding: Bool = true
    var writerDirectCopy: Bool = false

    var readerWithinPaddingBuffers: Bool = true
    var readerDirectCopy: Bool = false
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

/// Vision padding seed: `[contentThreshold, longPaddingMax, longPaddingBase, shortPaddingMax]`.
private let visionPaddingSeed: [UInt32] = [900, 500, 900, 256]

// MARK: - Buffer Reshaping

/// Must equal the protocol buffer size.
private let visionBufSize: Int32 = 8192

/// Buffers >= this are split to leave room for the 21-byte padding header.
private let reshapeThreshold: Int = 8192 - 21  // 8171

/// Splits data too large for one Vision-padded frame at the last TLS application-data
/// boundary (midpoint fallback), recursing until every chunk is below reshapeThreshold.
private func reshapeData(_ data: Data) -> [Data] {
    guard data.count >= reshapeThreshold else {
        return [data]
    }

    var splitIndex = data.count / 2
    data.withUnsafeBytes { ptr in
        let bytes = ptr.bindMemory(to: UInt8.self)
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
    // Either chunk may still exceed reshapeThreshold (peer buffers are capped at 8192).
    return reshapeData(first) + reshapeData(second)
}

// MARK: - Padding Functions

/// Frame layout: `[UUID (16 bytes, first packet only)] [command (1)] [contentLen (2)] [paddingLen (2)] [content] [padding]`.
/// `longPadding` pads short content with a large random block to obscure the VLESS header.
private func visionPadding(data: Data?, command: VisionCommand, state: VisionTrafficState, longPadding: Bool) -> Data {
    let contentLen = Int32(data?.count ?? 0)
    var paddingLen: Int32 = 0

    if contentLen < Int32(visionPaddingSeed[0]) && longPadding {
        paddingLen = Int32.random(in: 0..<Int32(visionPaddingSeed[1])) + Int32(visionPaddingSeed[2]) - contentLen
    } else {
        paddingLen = Int32.random(in: 0..<Int32(visionPaddingSeed[3]))
    }

    // Frame must fit the peer's 8192-byte buffer or its reshaper
    // fragments it and breaks padding detection.
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
    result.withUnsafeMutableBytes { ptr in
        let p = ptr.bindMemory(to: UInt8.self)
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

private func visionUnpadding(data: inout Data, state: VisionTrafficState) -> Data {
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
            if state.currentCommand == 0 {
                state.remainingCommand = 5
            } else {
                state.remainingCommand = -1
                state.remainingContent = -1
                state.remainingPadding = -1
                if readOffset < dataCount {
                    result.append(data[(startIdx + readOffset)..<(startIdx + dataCount)])
                    readOffset = dataCount
                }
                break
            }
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

/// Detects TLS 1.3 in incoming server responses.
private func visionFilterTLS(data: Data, state: VisionTrafficState) {
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
            // Server Hello complete with no TLS 1.3 marker — it's TLS 1.2.
            state.numberOfPacketsToFilter = 0
            return
        }
    }
}

/// Detects a TLS Client Hello in outgoing data without decrementing the filter counter.
private func visionDetectClientHello(data: Data, state: VisionTrafficState) {
    guard data.count >= 6 else { return }

    let startIdx = data.startIndex
    let byte0 = data[startIdx]
    let byte1 = data[data.index(startIdx, offsetBy: 1)]
    let byte5 = data[data.index(startIdx, offsetBy: 5)]

    if byte0 == 0x16 && byte1 == 0x03 && byte5 == tlsHandshakeTypeClientHello {
        state.isTLS = true
    }
}

private func isCompleteTLSRecord(data: Data) -> Bool {
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

/// VLESS connection with Vision flow control.
nonisolated class VLESSVisionConnection: ProxyConnection {
    private let innerConnection: ProxyConnection
    private let trafficState: VisionTrafficState

    init(connection: ProxyConnection, userUUID: Data) {
        self.innerConnection = connection
        self.trafficState = VisionTrafficState(userUUID: userUUID)
        super.init()
    }

    /// Sends an empty padding frame to camouflage the VLESS header when no initial
    /// data is available. Callers must wait on `completion` before subsequent sends.
    func sendEmptyPadding(completion: @escaping (Error?) -> Void) {
        lock.lock()
        let padded = visionPadding(data: nil, command: .paddingContinue, state: trafficState, longPadding: true)
        lock.unlock()
        innerConnection.send(data: padded, completion: completion)
    }
    
    override var isConnected: Bool {
        return innerConnection.isConnected
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        let isDirectCopy = trafficState.writerDirectCopy
        let paddedData = processSendData(data)
        lock.unlock()

        if isDirectCopy {
            innerConnection.sendDirectRaw(data: paddedData, completion: completion)
        } else {
            innerConnection.send(data: paddedData, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        lock.lock()
        let isDirectCopy = trafficState.writerDirectCopy
        let paddedData = processSendData(data)
        lock.unlock()

        if isDirectCopy {
            innerConnection.sendDirectRaw(data: paddedData)
        } else {
            innerConnection.send(data: paddedData)
        }
    }

    private func processSendData(_ data: Data) -> Data {
        if !trafficState.isTLS {
            visionDetectClientHello(data: data, state: trafficState)
        }

        if trafficState.writerDirectCopy {
            return data
        }

        guard trafficState.writerIsPadding else {
            return data
        }

        let longPadding = trafficState.isTLS
        let isComplete = isCompleteTLSRecord(data: data)

        let chunks = reshapeData(data)

        // A complete TLS application-data record ends padding mode.
        let startIdx = data.startIndex
        if trafficState.isTLS && data.count >= 6 &&
           data[startIdx] == tlsApplicationDataStart[0] &&
           data[data.index(startIdx, offsetBy: 1)] == tlsApplicationDataStart[1] &&
           data[data.index(startIdx, offsetBy: 2)] == tlsApplicationDataStart[2] &&
           isComplete {

            var result = Data()
            for (i, chunk) in chunks.enumerated() {
                if i == chunks.count - 1 {
                    var command: VisionCommand = .paddingEnd
                    if trafficState.enableXtls {
                        command = .paddingDirect
                        trafficState.writerDirectCopy = true
                    }
                    trafficState.writerIsPadding = false
                    result.append(visionPadding(data: chunk, command: command, state: trafficState, longPadding: false))
                } else {
                    result.append(visionPadding(data: chunk, command: .paddingContinue, state: trafficState, longPadding: true))
                }
            }
            return result
        }

        // Finish padding one packet early for older Vision receivers (the `<= 1` boundary).
        if !trafficState.isTLS12orAbove && trafficState.numberOfPacketsToFilter <= 1 {
            trafficState.writerIsPadding = false
            var result = Data()
            for (i, chunk) in chunks.enumerated() {
                let cmd: VisionCommand = (i == chunks.count - 1) ? .paddingEnd : .paddingContinue
                result.append(visionPadding(data: chunk, command: cmd, state: trafficState, longPadding: longPadding))
            }
            return result
        }

        var result = Data()
        for chunk in chunks {
            result.append(visionPadding(data: chunk, command: .paddingContinue, state: trafficState, longPadding: longPadding))
        }
        return result
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        receiveRawInternal(completion: completion)
    }

    private func receiveRawInternal(completion: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        let isDirectCopy = trafficState.readerDirectCopy
        lock.unlock()

        if isDirectCopy {
            // Direct copy bypasses Reality decryption.
            innerConnection.receiveDirectRaw { data, error in
                if let error {
                    completion(nil, error)
                    return
                }

                guard let data = data, !data.isEmpty else {
                    completion(nil, nil)
                    return
                }

                completion(data, nil)
            }
        } else {
            innerConnection.receive { [weak self] data, error in
                guard let self else {
                    completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                    return
                }

                if let error {
                    completion(nil, error)
                    return
                }

                guard var data = data, !data.isEmpty else {
                    completion(nil, nil)
                    return
                }

                self.lock.lock()
                let processedData = self.processReceiveData(&data)
                self.lock.unlock()

                // Empty result means only padding was received; continue rather than signalling EOF.
                if processedData.isEmpty {
                    self.receiveRawInternal(completion: completion)
                } else {
                    completion(processedData, nil)
                }
            }
        }
    }

    // The inner connection already handles response-header processing.
    override func receive(completion: @escaping (Data?, Error?) -> Void) {
        receiveRaw(completion: completion)
    }

    private func processReceiveData(_ data: inout Data) -> Data {
        if trafficState.numberOfPacketsToFilter > 0 {
            visionFilterTLS(data: data, state: trafficState)
        }

        if trafficState.readerDirectCopy {
            return data
        }

        if trafficState.readerWithinPaddingBuffers || trafficState.numberOfPacketsToFilter > 0 {
            let unpadded = visionUnpadding(data: &data, state: trafficState)

            if trafficState.remainingContent > 0 || trafficState.remainingPadding > 0 || trafficState.currentCommand == 0 {
                trafficState.readerWithinPaddingBuffers = true
            } else if trafficState.currentCommand == 1 {
                trafficState.readerWithinPaddingBuffers = false
            } else if trafficState.currentCommand == 2 {
                trafficState.readerWithinPaddingBuffers = false
                trafficState.readerDirectCopy = true
            }

            return unpadded
        }

        return data
    }

    override func cancel() {
        innerConnection.cancel()
    }
}
