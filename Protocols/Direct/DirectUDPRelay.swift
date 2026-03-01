//
//  DirectUDPRelay.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "DirectUDP")

class DirectUDPRelay {
    private var fd: Int32 = -1
    private let socketQueue = DispatchQueue(label: "com.argsment.Anywhere.direct-udp")
    private var readSource: DispatchSourceRead?
    private var readSourceResumed = false
    private var cancelled = false

    init() {}

    /// Creates a UDP socket and connects it to the destination.
    ///
    /// DNS resolution runs on a global concurrent queue. The completion
    /// is called on `lwipQueue` with nil on success or an error on failure.
    func connect(dstHost: String, dstPort: UInt16, lwipQueue: DispatchQueue,
                 completion: @escaping (Error?) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            var hints = addrinfo()
            hints.ai_family = AF_UNSPEC
            hints.ai_socktype = SOCK_DGRAM
            hints.ai_protocol = IPPROTO_UDP

            var result: UnsafeMutablePointer<addrinfo>?
            let status = getaddrinfo(dstHost, String(dstPort), &hints, &result)
            guard status == 0, let info = result else {
                let msg = status != 0 ? String(cString: gai_strerror(status)) : "No addresses"
                lwipQueue.async { completion(BSDSocketError.resolutionFailed(msg)) }
                return
            }
            defer { freeaddrinfo(result) }

            let sockFd = Darwin.socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
            guard sockFd >= 0 else {
                lwipQueue.async { completion(BSDSocketError.socketCreationFailed(String(cString: strerror(errno)))) }
                return
            }

            // Non-blocking + SO_NOSIGPIPE
            let flags = fcntl(sockFd, F_GETFL)
            _ = fcntl(sockFd, F_SETFL, flags | O_NONBLOCK)
            var yes: Int32 = 1
            setsockopt(sockFd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))

            // connect() on a UDP socket sets the default destination
            let connectResult = Darwin.connect(sockFd, info.pointee.ai_addr, info.pointee.ai_addrlen)
            if connectResult != 0 {
                Darwin.close(sockFd)
                lwipQueue.async { completion(BSDSocketError.connectionFailed(String(cString: strerror(errno)))) }
                return
            }

            self.socketQueue.async {
                guard !self.cancelled else {
                    Darwin.close(sockFd)
                    lwipQueue.async { completion(BSDSocketError.notConnected) }
                    return
                }
                self.fd = sockFd
                lwipQueue.async { completion(nil) }
            }
        }
    }

    /// Sends a UDP datagram to the connected destination.
    func send(data: Data) {
        socketQueue.async { [self] in
            guard fd >= 0, !cancelled else { return }
            data.withUnsafeBytes { buf in
                guard let base = buf.baseAddress else { return }
                _ = Darwin.send(fd, base, data.count, 0)
            }
        }
    }

    /// Starts receiving datagrams asynchronously via a DispatchSource.
    /// The handler is called on `socketQueue`; callers should dispatch to lwipQueue.
    func startReceiving(handler: @escaping (Data) -> Void) {
        socketQueue.async { [self] in
            guard fd >= 0, !cancelled else { return }

            let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: socketQueue)
            source.setEventHandler { [weak self] in
                guard let self, self.fd >= 0 else { return }
                let buffer = UnsafeMutableRawPointer.allocate(byteCount: 65536, alignment: 1)
                let n = Darwin.recv(self.fd, buffer, 65536, 0)
                if n > 0 {
                    let data = Data(bytes: buffer, count: n)
                    buffer.deallocate()
                    handler(data)
                } else {
                    buffer.deallocate()
                    // UDP doesn't have EOF, ignore errors and zero-length reads
                }
            }
            source.setCancelHandler { [weak self] in
                self?.readSource = nil
                self?.readSourceResumed = false
            }
            readSource = source
            readSourceResumed = true
            source.resume()
        }
    }

    func cancel() {
        socketQueue.async { [self] in
            guard !cancelled else { return }
            cancelled = true

            let currentFd = fd
            fd = -1

            if let rs = readSource {
                if !readSourceResumed { rs.resume() }
                rs.cancel()
                readSource = nil
                readSourceResumed = false
            }

            if currentFd >= 0 {
                Darwin.close(currentFd)
            }
        }
    }

    deinit {
        if fd >= 0 {
            Darwin.close(fd)
        }
        if let rs = readSource, !readSourceResumed { rs.resume() }
    }
}
