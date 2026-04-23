//
//  SudokuProxyConnection.swift
//  Anywhere
//
//  Copyright (C) 2026 by saba <contact me via issue>. GPLv3.
//  Created by saba on 4/23/26.
//

#if NETWORK_EXTENSION

import Foundation
import Darwin

private let sudokuLogger = AnywhereLogger(category: "Sudoku")

@_cdecl("sudoku_swift_socket_factory_open")
private func sudoku_swift_socket_factory_open(
    _ context: UnsafeMutableRawPointer?,
    _ host: UnsafePointer<CChar>?,
    _ port: UInt16
) -> Int32 {
    guard let context, let host else { return -1 }
    let connector = Unmanaged<SudokuChainConnector>.fromOpaque(context).takeUnretainedValue()
    return connector.openSocket(host: String(cString: host), port: port)
}

private enum SudokuBridgeConstants {
    static let serverHostCapacity = 256
    static let keyHexCapacity = 129
    static let aeadCapacity = 32
    static let asciiModeCapacity = 64
    static let httpMaskModeCapacity = 16
    static let httpMaskHostCapacity = 256
    static let httpMaskPathRootCapacity = 64
    static let httpMaskMultiplexCapacity = 8
    static let customTableCapacity = 16
    static let customTableSlots = 16
    static let tcpReadBufferSize = 16 * 1024
    static let udpReadBufferSize = 64 * 1024
    static let udpHostBufferSize = 256
}

private final class SudokuSocketBridge {
    private let ioQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.bridge.io", qos: .userInitiated)
    private let bridgeWriteQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.bridge.write", qos: .userInitiated)
    private let tunnel: ProxyConnection
    private let retainedClients: [ProxyClient]
    private let onClose: ((SudokuSocketBridge) -> Void)?

    private var cRuntimeFD: Int32
    private var bridgeFD: Int32
    private var readSource: DispatchSourceRead?
    private var closed = false
    private var pendingSends: [Data] = []
    private var isSendingToTunnel = false

    init?(
        tunnel: ProxyConnection,
        retainedClients: [ProxyClient] = [],
        onClose: ((SudokuSocketBridge) -> Void)? = nil
    ) {
        var fds: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else {
            return nil
        }

        self.tunnel = tunnel
        self.retainedClients = retainedClients
        self.onClose = onClose
        self.cRuntimeFD = fds[0]
        self.bridgeFD = fds[1]

        let flags = fcntl(bridgeFD, F_GETFL, 0)
        if flags >= 0 {
            _ = fcntl(bridgeFD, F_SETFL, flags | O_NONBLOCK)
        }
        var noSigPipe: Int32 = 1
        _ = setsockopt(cRuntimeFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        _ = setsockopt(bridgeFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        armReadSource()
        pumpTunnelReceive()
    }

    deinit {
        close()
    }

    func takeCRuntimeFD() -> Int32 {
        let fd = cRuntimeFD
        cRuntimeFD = -1
        return fd
    }

    func close() {
        ioQueue.async { [weak self] in
            guard let self, !self.closed else { return }
            self.closed = true
            self.readSource?.cancel()
            self.readSource = nil
            if self.cRuntimeFD >= 0 {
                Darwin.shutdown(self.cRuntimeFD, SHUT_RDWR)
                Darwin.close(self.cRuntimeFD)
                self.cRuntimeFD = -1
            }
            if self.bridgeFD >= 0 {
                Darwin.shutdown(self.bridgeFD, SHUT_RDWR)
                Darwin.close(self.bridgeFD)
                self.bridgeFD = -1
            }
            self.tunnel.cancel()
            for client in self.retainedClients {
                client.cancel()
            }
            self.pendingSends.removeAll()
            self.onClose?(self)
        }
    }

    private func armReadSource() {
        let source = DispatchSource.makeReadSource(fileDescriptor: bridgeFD, queue: ioQueue)
        source.setEventHandler { [weak self] in
            self?.drainBridgeReads()
        }
        source.setCancelHandler { }
        readSource = source
        source.resume()
    }

    private func drainBridgeReads() {
        guard !closed else { return }
        var buffer = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let count = Darwin.read(bridgeFD, &buffer, buffer.count)
            if count > 0 {
                enqueueTunnelSend(Data(buffer.prefix(Int(count))))
                continue
            }
            if count == 0 {
                close()
                return
            }
            let code = errno
            if code == EAGAIN || code == EWOULDBLOCK || code == EINTR {
                return
            }
            close()
            return
        }
    }

    private func enqueueTunnelSend(_ data: Data) {
        guard !closed else { return }
        pendingSends.append(data)
        drainTunnelSendQueue()
    }

    private func drainTunnelSendQueue() {
        guard !closed, !isSendingToTunnel, !pendingSends.isEmpty else { return }
        let next = pendingSends.removeFirst()
        isSendingToTunnel = true
        tunnel.sendRaw(data: next) { [weak self] error in
            guard let self else { return }
            self.ioQueue.async {
                self.isSendingToTunnel = false
                if error != nil || self.closed {
                    self.close()
                } else {
                    self.drainTunnelSendQueue()
                }
            }
        }
    }

    private func pumpTunnelReceive() {
        guard !closed else { return }
        tunnel.receiveRaw { [weak self] data, error in
            guard let self else { return }
            if let error {
                sudokuLogger.error("[Sudoku-Bridge] Tunnel receive error: \(error.localizedDescription)")
                self.close()
                return
            }
            guard let data, !data.isEmpty else {
                self.close()
                return
            }
            self.bridgeWriteQueue.async { [weak self] in
                guard let self else { return }
                if self.writeAllToBridge(data) {
                    self.pumpTunnelReceive()
                } else {
                    self.close()
                }
            }
        }
    }

    private func writeAllToBridge(_ data: Data) -> Bool {
        if closed { return false }
        return data.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return true }
            var written = 0
            let deadline = Date().addingTimeInterval(5)
            while written < bytes.count {
                let result = Darwin.write(bridgeFD, baseAddress.advanced(by: written), bytes.count - written)
                if result > 0 {
                    written += result
                    continue
                }
                if result == 0 {
                    return false
                }
                let code = errno
                if code == EINTR {
                    continue
                }
                if code == EAGAIN || code == EWOULDBLOCK {
                    if Date() >= deadline {
                        return false
                    }
                    usleep(1000)
                    continue
                }
                return false
            }
            return true
        }
    }
}

final class SudokuChainConnector {
    private let configuration: ProxyConfiguration
    private let stateLock = UnfairLock()
    private var initialTunnel: ProxyConnection?
    private var bridges: [SudokuSocketBridge] = []
    private var closed = false

    init(configuration: ProxyConfiguration, initialTunnel: ProxyConnection?) {
        self.configuration = configuration
        self.initialTunnel = initialTunnel
    }

    func contextPointer() -> UnsafeMutableRawPointer {
        UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
    }

    func openSocket(host: String, port: UInt16) -> Int32 {
        if stateLock.withLock({ closed }) {
            return -1
        }

        let semaphore = DispatchSemaphore(value: 0)
        var resultFD: Int32 = -1

        openTunnel(to: host, port: port) { [weak self] result in
            defer { semaphore.signal() }
            guard let self else { return }
            switch result {
            case .success(let payload):
                let bridge = SudokuSocketBridge(
                    tunnel: payload.connection,
                    retainedClients: payload.retainedClients,
                    onClose: { [weak self] bridge in self?.removeBridge(bridge) }
                )
                guard let bridge else {
                    payload.connection.cancel()
                    for client in payload.retainedClients { client.cancel() }
                    return
                }
                self.stateLock.withLock {
                    if self.closed {
                        bridge.close()
                        return
                    }
                    self.bridges.append(bridge)
                    resultFD = bridge.takeCRuntimeFD()
                }
            case .failure:
                break
            }
        }

        if semaphore.wait(timeout: .now() + 30) == .timedOut {
            return -1
        }
        return resultFD
    }

    func closeAll() {
        let bridgesToClose: [SudokuSocketBridge]
        let tunnelToClose: ProxyConnection?
        stateLock.lock()
        if closed {
            stateLock.unlock()
            return
        }
        closed = true
        bridgesToClose = bridges
        bridges.removeAll()
        tunnelToClose = initialTunnel
        initialTunnel = nil
        stateLock.unlock()

        tunnelToClose?.cancel()
        for bridge in bridgesToClose {
            bridge.close()
        }
    }

    private func removeBridge(_ bridge: SudokuSocketBridge?) {
        guard let bridge else { return }
        stateLock.withLock {
            bridges.removeAll { $0 === bridge }
        }
    }

    private func openTunnel(
        to host: String,
        port: UInt16,
        completion: @escaping (Result<(connection: ProxyConnection, retainedClients: [ProxyClient]), Error>) -> Void
    ) {
        if let tunnel = stateLock.withLock({ () -> ProxyConnection? in
            let current = initialTunnel
            initialTunnel = nil
            return current
        }) {
            completion(.success((tunnel, [])))
            return
        }

        guard let chain = configuration.chain, !chain.isEmpty else {
            completion(.failure(ProxyError.protocolError("Sudoku chain connector has no tunnel or chain")))
            return
        }

        buildChainTunnel(
            chain: chain,
            index: 0,
            currentTunnel: nil,
            targetHost: host,
            targetPort: port,
            retainedClients: [],
            completion: completion
        )
    }

    private func buildChainTunnel(
        chain: [ProxyConfiguration],
        index: Int,
        currentTunnel: ProxyConnection?,
        targetHost: String,
        targetPort: UInt16,
        retainedClients: [ProxyClient],
        completion: @escaping (Result<(connection: ProxyConnection, retainedClients: [ProxyClient]), Error>) -> Void
    ) {
        let chainConfig = chain[index]
        let nextHost: String
        let nextPort: UInt16
        if index + 1 < chain.count {
            nextHost = chain[index + 1].serverAddress
            nextPort = chain[index + 1].serverPort
        } else {
            nextHost = targetHost
            nextPort = targetPort
        }

        let chainClient = ProxyClient(configuration: chainConfig, tunnel: currentTunnel)
        var updatedClients = retainedClients
        updatedClients.append(chainClient)

        chainClient.connect(to: nextHost, port: nextPort) { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let connection):
                if index + 1 < chain.count {
                    self.buildChainTunnel(
                        chain: chain,
                        index: index + 1,
                        currentTunnel: connection,
                        targetHost: targetHost,
                        targetPort: targetPort,
                        retainedClients: updatedClients,
                        completion: completion
                    )
                } else {
                    completion(.success((connection, updatedClients)))
                }
            case .failure(let error):
                for client in updatedClients {
                    client.cancel()
                }
                completion(.failure(error))
            }
        }
    }
}

struct SudokuOutboundConfigBridge {
    let raw: sudoku_outbound_config_t

    init(configuration: ProxyConfiguration, serverHost: String, socketFactoryContext: UnsafeMutableRawPointer? = nil) throws {
        guard let sudoku = configuration.sudoku else {
            throw ProxyError.protocolError("Sudoku configuration is missing")
        }

        var cfg = sudoku_outbound_config_t()
        sudoku_outbound_config_init(&cfg)

        Self.copy(serverHost, into: &cfg.server_host, capacity: SudokuBridgeConstants.serverHostCapacity)
        cfg.server_port = configuration.serverPort

        Self.copy(sudoku.key, into: &cfg.key_hex, capacity: SudokuBridgeConstants.keyHexCapacity)
        Self.copy(sudoku.aeadMethod.rawValue, into: &cfg.aead_method, capacity: SudokuBridgeConstants.aeadCapacity)
        Self.copy(sudoku.asciiMode.rawValue, into: &cfg.ascii_mode, capacity: SudokuBridgeConstants.asciiModeCapacity)

        cfg.padding_min = numericCast(sudoku.paddingMin)
        cfg.padding_max = numericCast(sudoku.paddingMax)
        cfg.enable_pure_downlink = sudoku.enablePureDownlink ? 1 : 0

        cfg.httpmask_disable = sudoku.httpMask.disable ? 1 : 0
        Self.copy(sudoku.httpMask.mode.rawValue, into: &cfg.httpmask_mode, capacity: SudokuBridgeConstants.httpMaskModeCapacity)
        cfg.httpmask_tls = sudoku.httpMask.tls ? 1 : 0
        Self.copy(sudoku.httpMask.host, into: &cfg.httpmask_host, capacity: SudokuBridgeConstants.httpMaskHostCapacity)
        Self.copy(
            sudoku.httpMask.pathRoot,
            into: &cfg.httpmask_path_root,
            capacity: SudokuBridgeConstants.httpMaskPathRootCapacity
        )
        Self.copy(
            sudoku.httpMask.multiplex.rawValue,
            into: &cfg.httpmask_multiplex,
            capacity: SudokuBridgeConstants.httpMaskMultiplexCapacity
        )
        cfg.swift_socket_factory_ctx = socketFactoryContext

        let customTables = Array(sudoku.customTables.prefix(SudokuBridgeConstants.customTableSlots))
        cfg.custom_tables_count = numericCast(customTables.count)
        withUnsafeMutablePointer(to: &cfg.custom_tables) { pointer in
            let base = UnsafeMutableRawPointer(pointer).assumingMemoryBound(to: CChar.self)
            memset(
                base,
                0,
                SudokuBridgeConstants.customTableSlots * SudokuBridgeConstants.customTableCapacity
            )
            for (index, table) in customTables.enumerated() {
                Self.copy(
                    table,
                    into: base.advanced(by: index * SudokuBridgeConstants.customTableCapacity),
                    capacity: SudokuBridgeConstants.customTableCapacity
                )
            }
        }

        guard sudoku_outbound_config_finalize(&cfg) == 0 else {
            throw ProxyError.protocolError("Invalid Sudoku outbound configuration")
        }

        self.raw = cfg
    }

    private static func copy<T>(_ string: String, into field: inout T, capacity: Int) {
        withUnsafeMutablePointer(to: &field) { pointer in
            let chars = UnsafeMutableRawPointer(pointer).assumingMemoryBound(to: CChar.self)
            copy(string, into: chars, capacity: capacity)
        }
    }

    private static func copy(_ string: String, into buffer: UnsafeMutablePointer<CChar>, capacity: Int) {
        memset(buffer, 0, capacity)
        let utf8 = Array(string.utf8)
        let copyCount = min(utf8.count, max(0, capacity - 1))
        if copyCount > 0 {
            utf8.withUnsafeBytes { bytes in
                if let baseAddress = bytes.baseAddress {
                    memcpy(buffer, baseAddress, copyCount)
                }
            }
        }
        buffer[copyCount] = 0
    }
}

final class SudokuTCPProxyConnection: ProxyConnection {
    private let readQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.tcp.read", qos: .userInitiated)
    private let writeQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.tcp.write", qos: .userInitiated)
    private var handle: sudoku_tcp_handle_t?
    private let chainConnector: SudokuChainConnector?

    init(handle: sudoku_tcp_handle_t, chainConnector: SudokuChainConnector? = nil) {
        self.handle = handle
        self.chainConnector = chainConnector
        super.init()
    }

    deinit {
        closeHandle()
    }

    var isClosed: Bool {
        lock.withLock { handle == nil }
    }

    override var isConnected: Bool {
        !isClosed
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        guard !data.isEmpty else {
            completion(nil)
            return
        }
        writeQueue.async { [weak self] in
            guard let self else {
                completion(ProxyError.connectionFailed("Sudoku TCP connection deallocated"))
                return
            }
            guard let handle = self.lock.withLock({ self.handle }) else {
                completion(ProxyError.connectionFailed("Sudoku TCP connection is closed"))
                return
            }
            let result = data.withUnsafeBytes { bytes -> ssize_t in
                sudoku_swift_client_send(handle, bytes.baseAddress, bytes.count)
            }
            if result == data.count {
                completion(nil)
            } else if self.isClosed {
                completion(nil)
            } else {
                completion(Self.lastError("Sudoku TCP send failed"))
            }
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            if let error {
                sudokuLogger.error("[Sudoku-TCP] Send error: \(error.localizedDescription)")
            }
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        readQueue.async { [weak self] in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Sudoku TCP connection deallocated"))
                return
            }
            guard let handle = self.lock.withLock({ self.handle }) else {
                completion(nil, nil)
                return
            }
            var buffer = [UInt8](repeating: 0, count: SudokuBridgeConstants.tcpReadBufferSize)
            let count = buffer.withUnsafeMutableBytes { bytes -> ssize_t in
                sudoku_swift_client_recv(handle, bytes.baseAddress, bytes.count)
            }
            if count > 0 {
                completion(Data(buffer.prefix(Int(count))), nil)
            } else if count == 0 || self.isClosed {
                completion(nil, nil)
            } else {
                completion(nil, Self.lastError("Sudoku TCP receive failed"))
            }
        }
    }

    override func cancel() {
        closeHandle()
        chainConnector?.closeAll()
    }

    func closeHandle() {
        let handle = lock.withLock { () -> sudoku_tcp_handle_t? in
            let current = self.handle
            self.handle = nil
            return current
        }
        if let handle {
            sudoku_swift_client_close(handle)
        }
    }

    private static func lastError(_ fallback: String) -> ProxyError {
        let code = errno
        if code != 0 {
            return .connectionFailed("\(fallback): \(String(cString: strerror(code)))")
        }
        return .connectionFailed(fallback)
    }
}

final class SudokuUDPProxyConnection: ProxyConnection {
    private let readQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.udp.read", qos: .userInitiated)
    private let writeQueue = DispatchQueue(label: "com.argsment.Anywhere.sudoku.udp.write", qos: .userInitiated)
    private let destinationHost: String
    private let destinationPort: UInt16
    private var handle: sudoku_uot_handle_t?
    private let chainConnector: SudokuChainConnector?

    init(
        handle: sudoku_uot_handle_t,
        destinationHost: String,
        destinationPort: UInt16,
        chainConnector: SudokuChainConnector? = nil
    ) {
        self.handle = handle
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        self.chainConnector = chainConnector
        super.init()
    }

    deinit {
        closeHandle()
    }

    var isClosed: Bool {
        lock.withLock { handle == nil }
    }

    override var isConnected: Bool {
        !isClosed
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        writeQueue.async { [weak self] in
            guard let self else {
                completion(ProxyError.connectionFailed("Sudoku UDP connection deallocated"))
                return
            }
            guard let handle = self.lock.withLock({ self.handle }) else {
                completion(ProxyError.connectionFailed("Sudoku UDP connection is closed"))
                return
            }
            let result = self.destinationHost.withCString { host in
                data.withUnsafeBytes { bytes -> Int32 in
                    sudoku_swift_uot_sendto(handle, host, self.destinationPort, bytes.baseAddress, bytes.count)
                }
            }
            if result == 0 {
                completion(nil)
            } else if self.isClosed {
                completion(nil)
            } else {
                completion(Self.lastError("Sudoku UDP send failed"))
            }
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            if let error {
                sudokuLogger.error("[Sudoku-UDP] Send error: \(error.localizedDescription)")
            }
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        readQueue.async { [weak self] in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Sudoku UDP connection deallocated"))
                return
            }
            guard let handle = self.lock.withLock({ self.handle }) else {
                completion(nil, nil)
                return
            }

            var hostBuffer = [CChar](repeating: 0, count: SudokuBridgeConstants.udpHostBufferSize)
            var returnedPort: UInt16 = 0
            var payload = [UInt8](repeating: 0, count: SudokuBridgeConstants.udpReadBufferSize)
            let count = hostBuffer.withUnsafeMutableBufferPointer { hostChars -> ssize_t in
                payload.withUnsafeMutableBytes { bytes -> ssize_t in
                    sudoku_swift_uot_recvfrom(
                        handle,
                        hostChars.baseAddress,
                        hostBuffer.count,
                        &returnedPort,
                        bytes.baseAddress,
                        bytes.count
                    )
                }
            }

            if count > 0 {
                completion(Data(payload.prefix(Int(count))), nil)
            } else if count == 0 || self.isClosed {
                completion(nil, nil)
            } else {
                completion(nil, Self.lastError("Sudoku UDP receive failed"))
            }
        }
    }

    override func cancel() {
        closeHandle()
        chainConnector?.closeAll()
    }

    func closeHandle() {
        let handle = lock.withLock { () -> sudoku_uot_handle_t? in
            let current = self.handle
            self.handle = nil
            return current
        }
        if let handle {
            sudoku_swift_uot_close(handle)
        }
    }

    private static func lastError(_ fallback: String) -> ProxyError {
        let code = errno
        if code != 0 {
            return .connectionFailed("\(fallback): \(String(cString: strerror(code)))")
        }
        return .connectionFailed(fallback)
    }
}

#endif
