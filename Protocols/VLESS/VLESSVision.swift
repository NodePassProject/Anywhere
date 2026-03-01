//
//  VLESSVision.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Security

// MARK: - Constants

/// Vision padding commands
enum VisionCommand: UInt8 {
    case paddingContinue = 0x00  // Continue with padding
    case paddingEnd = 0x01       // End padding mode
    case paddingDirect = 0x02    // Switch to direct copy
}

/// TLS detection constants
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

/// Tracks TLS detection and padding state for Vision
class VisionTrafficState {
    let userUUID: Data

    // TLS detection state
    var numberOfPacketsToFilter: Int = 8
    var enableXtls: Bool = false
    var isTLS12orAbove: Bool = false
    var isTLS: Bool = false
    var cipher: UInt16 = 0
    var remainingServerHello: Int32 = -1

    // Writer state (for outgoing data)
    var writerIsPadding: Bool = true
    var writerDirectCopy: Bool = false

    // Reader state (for incoming data)
    var readerWithinPaddingBuffers: Bool = true
    var readerDirectCopy: Bool = false
    var remainingCommand: Int32 = -1
    var remainingContent: Int32 = -1
    var remainingPadding: Int32 = -1
    var currentCommand: Int = 0

    // First packet flag for UUID
    var writeOnceUserUUID: Data?

    // Vision padding seed: [contentThreshold, longPaddingMax, longPaddingBase, shortPaddingMax]
    let testseed: [UInt32]

    init(userUUID: Data, testseed: [UInt32] = [900, 500, 900, 256]) {
        self.userUUID = userUUID
        self.writeOnceUserUUID = userUUID
        self.testseed = testseed.count >= 4 ? testseed : [900, 500, 900, 256]
    }
}

// MARK: - Buffer Reshaping

/// Maximum buffer size matching Xray-core's buf.Size
private let visionBufSize: Int32 = 8192

/// Reshape threshold: buffers >= this need splitting to leave room for the 21-byte padding header
private let reshapeThreshold: Int = 8192 - 21  // 8171

/// Split data that is too large for a single Vision-padded frame.
/// Tries to split at the last TLS application data boundary; falls back to midpoint.
/// Matches Xray-core's `ReshapeMultiBuffer`.
private func reshapeData(_ data: Data) -> [Data] {
    guard data.count >= reshapeThreshold else {
        return [data]
    }

    // Find last occurrence of TLS application data header (0x17 0x03 0x03)
    var splitIndex = data.count / 2
    let bytes = data.withUnsafeBytes { Array(UnsafeBufferPointer(start: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: data.count)) }
    for i in stride(from: bytes.count - 3, through: 0, by: -1) {
        if bytes[i] == 0x17 && bytes[i + 1] == 0x03 && bytes[i + 2] == 0x03 {
            if i >= 21 && i <= reshapeThreshold {
                splitIndex = i
                break
            }
        }
    }

    let first = data.prefix(splitIndex)
    let second = data.suffix(from: data.index(data.startIndex, offsetBy: splitIndex))
    return [Data(first), Data(second)]
}

// MARK: - Padding Functions

/// Add Vision padding to data
/// Format: [UUID (16 bytes, first packet only)] [command (1)] [contentLen (2)] [paddingLen (2)] [content] [padding]
func visionPadding(data: Data?, command: VisionCommand, state: VisionTrafficState, longPadding: Bool) -> Data {
    let contentLen = Int32(data?.count ?? 0)
    var paddingLen: Int32 = 0

    // Calculate padding length using testseed: [contentThreshold, longPaddingMax, longPaddingBase, shortPaddingMax]
    let seed = state.testseed
    if contentLen < Int32(seed[0]) && longPadding {
        paddingLen = Int32.random(in: 0..<Int32(seed[1])) + Int32(seed[2]) - contentLen
    } else {
        paddingLen = Int32.random(in: 0..<Int32(seed[3]))
    }

    // Ensure padding doesn't exceed buffer limits (matches Xray-core buf.Size = 8192)
    let maxPadding = 8192 - 21 - contentLen
    if paddingLen > maxPadding {
        paddingLen = maxPadding
    }
    if paddingLen < 0 {
        paddingLen = 0
    }

    var result = Data()

    // Add UUID on first packet
    if let uuid = state.writeOnceUserUUID {
        result.append(uuid)
        state.writeOnceUserUUID = nil
    }

    // Add command header: [command (1)] [contentLen (2)] [paddingLen (2)]
    result.append(command.rawValue)
    result.append(UInt8(contentLen >> 8))
    result.append(UInt8(contentLen & 0xFF))
    result.append(UInt8(paddingLen >> 8))
    result.append(UInt8(paddingLen & 0xFF))

    // Add content
    if let data = data {
        result.append(data)
    }

    // Add random padding
    if paddingLen > 0 {
        var padding = Data(count: Int(paddingLen))
        padding.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, Int(paddingLen), ptr.baseAddress!)
        }
        result.append(padding)
    }

    return result
}

/// Remove Vision padding from data and extract content
/// Returns the extracted content data
func visionUnpadding(data: inout Data, state: VisionTrafficState) -> Data {
    // Initial state check - look for UUID prefix
    if state.remainingCommand == -1 && state.remainingContent == -1 && state.remainingPadding == -1 {
        if data.count >= 21 && data.prefix(16) == state.userUUID {
            data = Data(data.dropFirst(16))
            state.remainingCommand = 5
        } else {
            // No Vision header, return data as-is
            return data
        }
    }

    var result = Data()

    while !data.isEmpty {
        if state.remainingCommand > 0 {
            // Reading command header
            let byte = data.removeFirst()
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
            // Reading content
            let toRead = min(Int(state.remainingContent), data.count)
            result.append(data.prefix(toRead))
            data = Data(data.dropFirst(toRead))
            state.remainingContent -= Int32(toRead)
        } else if state.remainingPadding > 0 {
            // Skipping padding
            let toSkip = min(Int(state.remainingPadding), data.count)
            data = Data(data.dropFirst(toSkip))
            state.remainingPadding -= Int32(toSkip)
        }

        // Check if current block is done
        if state.remainingCommand <= 0 && state.remainingContent <= 0 && state.remainingPadding <= 0 {
            if state.currentCommand == 0 {
                // Continue - expect another block
                state.remainingCommand = 5
            } else {
                // End or Direct - reset to initial state
                state.remainingCommand = -1
                state.remainingContent = -1
                state.remainingPadding = -1
                if !data.isEmpty {
                    // Remaining data after padding ends
                    result.append(data)
                    data = Data()
                }
                break
            }
        }
    }

    return result
}

// MARK: - TLS Filtering

/// Filter and detect TLS 1.3 in traffic (for incoming server responses)
func visionFilterTLS(data: Data, state: VisionTrafficState) {
    guard state.numberOfPacketsToFilter > 0 else { return }

    state.numberOfPacketsToFilter -= 1

    guard data.count >= 6 else { return }

    let startIdx = data.startIndex
    let byte0 = data[startIdx]
    let byte1 = data[data.index(startIdx, offsetBy: 1)]
    let byte2 = data[data.index(startIdx, offsetBy: 2)]
    let byte5 = data[data.index(startIdx, offsetBy: 5)]

    // Check for Server Hello: 0x16 0x03 0x03 ... 0x02
    if byte0 == 0x16 && byte1 == 0x03 && byte2 == 0x03 && byte5 == tlsHandshakeTypeServerHello {
        let byte3 = data[data.index(startIdx, offsetBy: 3)]
        let byte4 = data[data.index(startIdx, offsetBy: 4)]
        state.remainingServerHello = (Int32(byte3) << 8 | Int32(byte4)) + 5
        state.isTLS12orAbove = true
        state.isTLS = true

        // Try to extract cipher suite
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
        // Client Hello: 0x16 0x03 ... 0x01
        state.isTLS = true
    }

    // Check for TLS 1.3 supported versions extension
    if state.remainingServerHello > 0 {
        let end = min(Int(state.remainingServerHello), data.count)
        state.remainingServerHello -= Int32(data.count)

        // Search for TLS 1.3 supported versions extension
        if let _ = data.prefix(end).range(of: Data(tls13SupportedVersions)) {
            // Found TLS 1.3
            if tls13CipherSuites.contains(state.cipher) {
                state.enableXtls = true
            }
            state.numberOfPacketsToFilter = 0
            return
        } else if state.remainingServerHello <= 0 {
            // Server Hello complete but no TLS 1.3 - it's TLS 1.2
            state.numberOfPacketsToFilter = 0
            return
        }
    }
}

/// Detect TLS Client Hello in outgoing data (doesn't decrement counter)
func visionDetectClientHello(data: Data, state: VisionTrafficState) {
    guard data.count >= 6 else { return }

    let startIdx = data.startIndex
    let byte0 = data[startIdx]
    let byte1 = data[data.index(startIdx, offsetBy: 1)]
    let byte5 = data[data.index(startIdx, offsetBy: 5)]

    // Check for Client Hello: 0x16 0x03 ... 0x01
    if byte0 == 0x16 && byte1 == 0x03 && byte5 == tlsHandshakeTypeClientHello {
        state.isTLS = true
    }
}

/// Check if data is a complete TLS application data record
func isCompleteTLSRecord(data: Data) -> Bool {
    let totalLen = data.count

    // Quick check - if data doesn't start with TLS app data header, return false
    guard totalLen >= 5 else { return false }

    let startIdx = data.startIndex
    guard data[startIdx] == 0x17 &&
          data[data.index(startIdx, offsetBy: 1)] == 0x03 &&
          data[data.index(startIdx, offsetBy: 2)] == 0x03 else { return false }

    var offset = 0

    while offset < totalLen {
        // Need at least 5 bytes for TLS record header
        guard offset + 5 <= totalLen else { return false }

        let idx0 = data.index(startIdx, offsetBy: offset)
        let idx1 = data.index(startIdx, offsetBy: offset + 1)
        let idx2 = data.index(startIdx, offsetBy: offset + 2)
        let idx3 = data.index(startIdx, offsetBy: offset + 3)
        let idx4 = data.index(startIdx, offsetBy: offset + 4)

        // Check for application data header: 0x17 0x03 0x03
        guard data[idx0] == 0x17,
              data[idx1] == 0x03,
              data[idx2] == 0x03 else { return false }

        // Get record length
        let recordLen = Int(data[idx3]) << 8 | Int(data[idx4])
        offset += 5

        // Check if we have the full record
        guard offset + recordLen <= totalLen else { return false }
        offset += recordLen
    }

    return offset == totalLen
}

// MARK: - Vision Connection Wrapper

/// VLESS connection with Vision flow control
class VLESSVisionConnection: VLESSConnection {
    private let innerConnection: VLESSConnection
    private let trafficState: VisionTrafficState

    init(connection: VLESSConnection, userUUID: Data, testseed: [UInt32] = [900, 500, 900, 256]) {
        self.innerConnection = connection
        self.trafficState = VisionTrafficState(userUUID: userUUID, testseed: testseed)
        super.init()
    }

    /// Send an empty padding frame to camouflage the VLESS header.
    /// Called when no initial data is available, so the header isn't sent alone.
    /// Matches Xray-core `outbound.go` lines 331-337.
    func sendEmptyPadding() {
        lock.lock()
        let padded = visionPadding(data: nil, command: .paddingContinue, state: trafficState, longPadding: true)
        lock.unlock()
        innerConnection.send(data: padded)
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
            // Direct copy mode: send raw without Reality encryption
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
            // Direct copy mode: send raw without Reality encryption
            innerConnection.sendDirectRaw(data: paddedData)
        } else {
            innerConnection.send(data: paddedData)
        }
    }

    private func processSendData(_ data: Data) -> Data {
        // Detect Client Hello to enable long padding (don't decrement counter)
        if !trafficState.isTLS {
            visionDetectClientHello(data: data, state: trafficState)
        }

        // If direct copy mode, send without padding
        if trafficState.writerDirectCopy {
            return data
        }

        // If not in padding mode, send directly
        guard trafficState.writerIsPadding else {
            return data
        }

        let longPadding = trafficState.isTLS
        let isComplete = isCompleteTLSRecord(data: data)

        // Reshape oversized buffers to ensure room for the 21-byte Vision padding header
        let chunks = reshapeData(data)

        // Check if this is TLS application data and we should end padding
        let startIdx = data.startIndex
        if trafficState.isTLS && data.count >= 6 &&
           data[startIdx] == tlsApplicationDataStart[0] &&
           data[data.index(startIdx, offsetBy: 1)] == tlsApplicationDataStart[1] &&
           data[data.index(startIdx, offsetBy: 2)] == tlsApplicationDataStart[2] &&
           isComplete {

            // End padding mode — pad each chunk, last one gets the terminal command
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

        // For compatibility with earlier vision receiver, finish padding 1 packet early (matches Xray-core <= 1)
        if !trafficState.isTLS12orAbove && trafficState.numberOfPacketsToFilter <= 1 {
            trafficState.writerIsPadding = false
            var result = Data()
            for (i, chunk) in chunks.enumerated() {
                let cmd: VisionCommand = (i == chunks.count - 1) ? .paddingEnd : .paddingContinue
                result.append(visionPadding(data: chunk, command: cmd, state: trafficState, longPadding: longPadding))
            }
            return result
        }

        // Continue with padding
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
        // Check if we're in direct copy mode BEFORE receiving
        // In direct copy mode, bypass Reality decryption and read raw data
        lock.lock()
        let isDirectCopy = trafficState.readerDirectCopy
        lock.unlock()

        if isDirectCopy {
            // Direct copy mode: read raw data without Reality decryption
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
            // Normal mode: receive through Reality decryption
            innerConnection.receive { [weak self] data, error in
                guard let self else {
                    completion(nil, VLESSError.connectionFailed("Connection deallocated"))
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

                // If processed data is empty (e.g., only padding was received),
                // continue receiving instead of returning nil (which would close the connection)
                if processedData.isEmpty {
                    self.receiveRawInternal(completion: completion)
                } else {
                    completion(processedData, nil)
                }
            }
        }
    }

    // Override receive to skip response header processing (inner connection handles it)
    override func receive(completion: @escaping (Data?, Error?) -> Void) {
        receiveRaw(completion: completion)
    }

    private func processReceiveData(_ data: inout Data) -> Data {
        // Filter TLS from server responses
        if trafficState.numberOfPacketsToFilter > 0 {
            visionFilterTLS(data: data, state: trafficState)
        }

        // If direct copy mode, return without unpadding
        if trafficState.readerDirectCopy {
            return data
        }

        // If within padding buffers or still filtering, unpad
        if trafficState.readerWithinPaddingBuffers || trafficState.numberOfPacketsToFilter > 0 {
            let unpadded = visionUnpadding(data: &data, state: trafficState)

            // Update state based on current command
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
