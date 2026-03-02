//
//  LWIPUDPFlow.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "LWIP-UDP")

class LWIPUDPFlow {
    let flowKey: String
    let srcHost: String
    let srcPort: UInt16
    let dstHost: String
    let dstPort: UInt16
    let isIPv6: Bool
    let configuration: VLESSConfiguration
    let lwipQueue: DispatchQueue

    // Raw IP bytes for lwip_bridge_udp_sendto (swapped src/dst for responses)
    let srcIPBytes: Data  // original source (becomes dst in response)
    let dstIPBytes: Data  // original destination (becomes src in response)

    var lastActivity: CFAbsoluteTime = CFAbsoluteTimeGetCurrent()

    // Direct bypass path
    private var directRelay: DirectUDPRelay?

    // Non-mux path
    private var vlessClient: VLESSClient?
    private var vlessConnection: VLESSConnection?

    // Mux path
    private var muxSession: MuxSession?

    private var vlessConnecting = false
    private var forceBypass = false
    private var pendingData: [Data] = []  // always raw payloads (framing deferred to send time)
    private var pendingBufferSize = 0      // current total size of pendingData
    private var closed = false

    /// Maximum buffer size for queued UDP datagrams (matches Xray-core's DiscardOverflow 16KB limit).
    /// Datagrams that would exceed this limit are silently dropped (standard UDP behavior).
    private static let maxUDPBufferSize = 16 * 1024  // 16 KB

    init(flowKey: String,
         srcHost: String, srcPort: UInt16,
         dstHost: String, dstPort: UInt16,
         srcIPData: Data, dstIPData: Data,
         isIPv6: Bool,
         configuration: VLESSConfiguration,
         forceBypass: Bool = false,
         lwipQueue: DispatchQueue) {
        self.flowKey = flowKey
        self.srcHost = srcHost
        self.srcPort = srcPort
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.srcIPBytes = srcIPData
        self.dstIPBytes = dstIPData
        self.isIPv6 = isIPv6
        self.configuration = configuration
        self.forceBypass = forceBypass
        self.lwipQueue = lwipQueue
    }

    // MARK: - Data Handling (called on lwipQueue)

    func handleReceivedData(_ data: Data, payloadLength: Int) {
        guard !closed else { return }
        lastActivity = CFAbsoluteTimeGetCurrent()

        let payload = data.prefix(payloadLength)

        // Direct bypass path
        if let relay = directRelay {
            relay.send(data: Data(payload))
            return
        }

        // Mux path: send raw payload (mux framing handled by MuxSession)
        if let session = muxSession {
            session.send(data: Data(payload)) { [weak self] error in
                if let error {
                    logger.error("[UDP] Mux send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
                }
            }
            return
        }

        // Non-mux path: send length-framed payload through VLESS connection
        if let connection = vlessConnection {
            sendUDPThroughVLESS(connection: connection, payload: data, payloadLength: payloadLength)
            return
        }

        // Buffer and connect
        if vlessConnecting {
            bufferPayload(data: data, payloadLength: payloadLength)
        } else {
            bufferPayload(data: data, payloadLength: payloadLength)
            connectVLESS()
        }
    }

    private func bufferPayload(data: Data, payloadLength: Int) {
        // Drop datagram if buffer limit would be exceeded (DiscardOverflow)
        if pendingBufferSize + payloadLength > Self.maxUDPBufferSize {
            return
        }

        // Always buffer raw payloads. Framing for VLESS non-mux is deferred
        // to send time so that bypass and mux paths receive unframed data.
        let payload = Data(data.prefix(payloadLength))
        pendingData.append(payload)
        pendingBufferSize += payload.count
    }

    private func sendUDPThroughVLESS(connection: VLESSConnection, payload: Data, payloadLength: Int) {
        let framedLen = 2 + payloadLength
        var framedPayload = Data(count: framedLen)
        framedPayload.withUnsafeMutableBytes { outPtr in
            payload.withUnsafeBytes { srcPtr in
                frame_udp_payload(
                    outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    srcPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    UInt16(payloadLength)
                )
            }
        }

        connection.sendRaw(data: framedPayload) { [weak self] error in
            if let error {
                logger.error("[UDP] VLESS send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    // MARK: - VLESS Connection

    private func connectVLESS() {
        guard !vlessConnecting && vlessConnection == nil && muxSession == nil && directRelay == nil && !closed else { return }

        if forceBypass || LWIPStack.shared?.shouldBypass(host: dstHost) == true {
            connectDirectUDP()
            return
        }

        vlessConnecting = true

        // Only use mux for the default configuration (mux is tied to the default proxy's connection)
        let isDefaultConfiguration = (LWIPStack.shared?.configuration?.id == configuration.id)
        if isDefaultConfiguration, let muxManager = LWIPStack.shared?.muxManager {
            // Mux path
            // Cone NAT: GlobalID = blake3("udp:srcHost:srcPort") matching Xray-core's
            // net.Destination.String() format. Non-zero GlobalID enables server-side
            // session persistence (Full Cone NAT). Nil = no GlobalID (Symmetric NAT).
            let globalID = configuration.xudpEnabled ? XUDP.generateGlobalID(sourceAddress: "udp:\(srcHost):\(srcPort)") : nil
            muxManager.dispatch(network: .udp, host: dstHost, port: dstPort, globalID: globalID) { [weak self] result in
                guard let self else { return }

                self.lwipQueue.async {
                    self.vlessConnecting = false
                    guard !self.closed else { return }

                    switch result {
                    case .success(let session):
                        self.muxSession = session

                        // Set up receive handler
                        session.dataHandler = { [weak self] data in
                            self?.handleVLESSData(data)
                        }
                        session.closeHandler = { [weak self] in
                            guard let self else { return }
                            self.lwipQueue.async {
                                self.close()
                                LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                            }
                        }

                        // Send buffered raw payloads
                        let buffered = self.pendingData
                        self.pendingData.removeAll()
                        self.pendingBufferSize = 0
                        for payload in buffered {
                            session.send(data: payload) { [weak self] error in
                                if let error {
                                    logger.error("[UDP] Mux initial send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
                                }
                            }
                        }

                    case .failure(let error):
                        if case .dropped = error as? VLESSError {} else {
                            logger.error("[UDP] Mux dispatch failed: \(self.flowKey, privacy: .public): \(error.localizedDescription, privacy: .public)")
                        }
                        self.releaseVLESS()
                        LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                    }
                }
            }
        } else {
            // Non-mux path (existing behavior)
            let client = VLESSClient(configuration: configuration)
            self.vlessClient = client

            client.connectUDP(to: dstHost, port: dstPort) { [weak self] result in
                guard let self else { return }

                self.lwipQueue.async {
                    self.vlessConnecting = false
                    guard !self.closed else { return }

                    switch result {
                    case .success(let vlessConnection):
                        self.vlessConnection = vlessConnection

                        // Send buffered raw payloads (frame each for VLESS non-mux)
                        if !self.pendingData.isEmpty {
                            var dataToSend = Data()
                            for payload in self.pendingData {
                                var framedPayload = Data(count: 2 + payload.count)
                                framedPayload.withUnsafeMutableBytes { outPtr in
                                    payload.withUnsafeBytes { srcPtr in
                                        frame_udp_payload(
                                            outPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                            srcPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                            UInt16(payload.count)
                                        )
                                    }
                                }
                                dataToSend.append(framedPayload)
                            }
                            self.pendingData.removeAll()
                            self.pendingBufferSize = 0
                            vlessConnection.sendRaw(data: dataToSend) { [weak self] error in
                                if let error {
                                    logger.error("[UDP] VLESS initial send error for \(self?.flowKey ?? "?", privacy: .public): \(error.localizedDescription, privacy: .public)")
                                }
                            }
                        }

                        // Start receiving VLESS responses
                        self.startVLESSReceiving(vlessConnection: vlessConnection)

                    case .failure(let error):
                        if case .dropped = error as? VLESSError {} else {
                            logger.error("[UDP] connect failed: \(self.flowKey, privacy: .public): \(error.localizedDescription, privacy: .public)")
                        }
                        self.releaseVLESS()
                        LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                    }
                }
            }
        }
    }

    private func connectDirectUDP() {
        guard directRelay == nil && !closed else { return }
        vlessConnecting = true  // reuse flag to prevent re-entry

        let relay = DirectUDPRelay()
        self.directRelay = relay
        relay.connect(dstHost: dstHost, dstPort: dstPort, lwipQueue: lwipQueue) { [weak self] error in
            guard let self else { return }

            self.lwipQueue.async {
                self.vlessConnecting = false
                guard !self.closed else { return }

                if let error {
                    logger.error("[UDP] Direct connect failed: \(self.flowKey, privacy: .public): \(error.localizedDescription, privacy: .public)")
                    self.close()
                    LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
                    return
                }

                // Send buffered payloads
                for payload in self.pendingData {
                    relay.send(data: payload)
                }
                self.pendingData.removeAll()
                self.pendingBufferSize = 0

                // Start receiving responses
                relay.startReceiving { [weak self] data in
                    self?.handleVLESSData(data)
                }
            }
        }
    }

    private func startVLESSReceiving(vlessConnection: VLESSConnection) {
        vlessConnection.startReceiving { [weak self] data in
            guard let self else { return }
            self.handleVLESSData(data)
        } errorHandler: { [weak self] error in
            guard let self else { return }
            if let error {
                logger.error("[UDP] VLESS recv error: \(self.flowKey, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
            self.lwipQueue.async {
                self.close()
                LWIPStack.shared?.udpFlows.removeValue(forKey: self.flowKey)
            }
        }
    }

    private func handleVLESSData(_ data: Data) {
        lwipQueue.async { [weak self] in
            guard let self, !self.closed else { return }
            self.lastActivity = CFAbsoluteTimeGetCurrent()

            // Send UDP response via lwIP (swap src/dst for the response packet)
            self.dstIPBytes.withUnsafeBytes { dstPtr in  // original dst = response src
                self.srcIPBytes.withUnsafeBytes { srcPtr in  // original src = response dst
                    data.withUnsafeBytes { dataPtr in
                        guard let dstBase = dstPtr.baseAddress,
                              let srcBase = srcPtr.baseAddress,
                              let dataBase = dataPtr.baseAddress else {
                            logger.error("[UDP] NULL base address in data pointers")
                            return
                        }
                        lwip_bridge_udp_sendto(
                            dstBase, self.dstPort,   // response source = original destination
                            srcBase, self.srcPort,   // response destination = original source
                            self.isIPv6 ? 1 : 0,
                            dataBase, Int32(data.count)
                        )
                    }
                }
            }
        }
    }

    // MARK: - Close

    func close() {
        guard !closed else { return }
        closed = true
        releaseVLESS()
    }

    private func releaseVLESS() {
        let relay = directRelay
        let connection = vlessConnection
        let client = vlessClient
        let session = muxSession
        directRelay = nil
        vlessConnection = nil
        vlessClient = nil
        muxSession = nil
        vlessConnecting = false
        pendingData.removeAll()
        pendingBufferSize = 0
        relay?.cancel()
        connection?.cancel()
        client?.cancel()
        session?.close()
    }

    deinit {
        directRelay?.cancel()
        vlessConnection?.cancel()
        vlessClient?.cancel()
        muxSession?.close()
    }
}
