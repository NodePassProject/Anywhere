//
//  DNSSyscallConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import dnssd

nonisolated final class DNSSyscallConcurrencyBridge: Sendable {
    private let queue: DispatchQueue = DispatchQueue(
        label: "com.argsment.Anywhere.DNSSyscallConcurrencyBridge",
        qos: .userInitiated,
        attributes: .concurrent
    )

    func run<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: body()) }
        }
    }

    // MARK: - Record query

    /// One-shot `DNSServiceQueryRecord` for `host`/`rrtype`, blocking on this bridge's pool (a
    /// private fd + `poll` loop, never a cooperative thread). Resumes with the first record
    /// `accept` extracts a payload from — plus its TTL — or `nil` on a negative answer or after
    /// `timeout`. The C-callback trampoline and its context passing stay inside this bridge;
    /// callers supply only the record-payload parser.
    func queryFirstRecord(
        host: String,
        rrtype: UInt16,
        timeout: TimeInterval,
        accept: @escaping @Sendable (Data) -> Data?
    ) async -> (payload: Data, ttl: UInt32)? {
        await run { Self.queryFirstRecordBlocking(host: host, rrtype: rrtype, timeout: timeout, accept: accept) }
    }

    /// Carried across the C callback as its context pointer (unretained; the blocking frame
    /// below owns it for the query's whole span).
    private final class QueryResult {
        let rrtype: UInt16
        let accept: (Data) -> Data?
        var payload: Data?
        var ttl: UInt32 = 0
        var answered = false
        init(rrtype: UInt16, accept: @escaping (Data) -> Data?) {
            self.rrtype = rrtype
            self.accept = accept
        }
    }

    private static func queryFirstRecordBlocking(
        host: String,
        rrtype: UInt16,
        timeout: TimeInterval,
        accept: @escaping @Sendable (Data) -> Data?
    ) -> (payload: Data, ttl: UInt32)? {
        let result = QueryResult(rrtype: rrtype, accept: accept)

        // Non-capturing so it bridges to the C callback; state flows via context.
        let callback: DNSServiceQueryRecordReply = { _, flags, _, errorCode, _, rrtype, _, rdlen, rdata, ttl, context in
            guard let context else { return }
            let result = BridgeContext.unretained(context, as: QueryResult.self)
            // MoreComing clear marks the batch complete; note it so the poll loop
            // stops instead of waiting out the timeout when the host publishes no
            // usable record (the common negative case resolves promptly).
            if (flags & kDNSServiceFlagsMoreComing) == 0 { result.answered = true }
            guard errorCode == kDNSServiceErr_NoError,
                  rrtype == result.rrtype, let rdata, rdlen > 0
            else { return }
            guard result.payload == nil else { return }   // keep the first usable record
            if let payload = result.accept(Data(bytes: rdata, count: Int(rdlen))) {
                result.payload = payload
                result.ttl = ttl
            }
        }

        var serviceRef: DNSServiceRef?
        let context = BridgeContext.passUnretained(result)
        let queryError = host.withCString { cHost in
            DNSServiceQueryRecord(&serviceRef, 0, 0, cHost,
                                  rrtype, UInt16(kDNSServiceClass_IN), callback, context)
        }
        guard queryError == kDNSServiceErr_NoError, let serviceRef else { return nil }
        defer { DNSServiceRefDeallocate(serviceRef) }

        let fd = DNSServiceRefSockFD(serviceRef)
        guard fd >= 0 else { return nil }

        let deadline = CFAbsoluteTimeGetCurrent() + timeout
        while result.payload == nil, !result.answered {
            let remaining = deadline - CFAbsoluteTimeGetCurrent()
            if remaining <= 0 { break }
            var pollDescriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&pollDescriptor, 1, Int32(remaining * 1000))
            guard ready > 0, (pollDescriptor.revents & Int16(POLLIN)) != 0 else { break }
            if DNSServiceProcessResult(serviceRef) != kDNSServiceErr_NoError { break }
        }
        guard let payload = result.payload else { return nil }
        return (payload, result.ttl)
    }
}
