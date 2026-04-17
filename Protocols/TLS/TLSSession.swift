//
//  TLSSession.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/17/26.
//

import Foundation

/// The two async BIO callbacks installed on a wolfSSL SSL object read and
/// write through `TLSSession`'s buffers. `wolfSSL_Set{IORead,IOWrite}Ctx`
/// stores a raw pointer; we hand it `Unmanaged.passUnretained(session)`
/// which stays valid as long as any Swift owner holds the session.
final class TLSSession {

    /// wolfSSL context — kept alive for as long as this session exists.
    let ctx: OpaquePointer

    /// wolfSSL SSL object — kept alive for as long as this session exists.
    let ssl: OpaquePointer

    /// Serialises every wolfSSL call and every BIO buffer mutation.
    /// wolfSSL's SSL object is NOT thread-safe.
    let queue: DispatchQueue

    /// Underlying TCP / tunneled transport. wolfSSL writes go into `txBuffer`
    /// and get drained here; reads land here and are staged into `rxBuffer`.
    var connection: (any RawTransport)?

    /// Encrypted bytes pulled off the network, waiting for wolfSSL to
    /// consume them via the IORecv callback.
    var rxBuffer = Data()

    /// Encrypted bytes wolfSSL wants on the wire, waiting for us to flush
    /// them via `connection.send`.
    var txBuffer = Data()

    /// Decrypted application bytes already wolfSSL_read'd but not yet
    /// delivered to a `TLSRecordConnection.receive` call.
    var appBuffer = Data()

    /// Bytes "pushed back" by `TLSRecordConnection.prependToReceiveBuffer`.
    /// Consumed ahead of the encrypted/decrypted pipeline by the plain /
    /// raw receive paths, mirroring the pre-wolfSSL implementation's
    /// semantics.
    var prependedRaw = Data()

    /// `true` once someone has called `cancel()`. The handshake pump and
    /// the post-handshake I/O loop both check this before scheduling
    /// further work.
    var cancelled = false

    /// `true` while a `connection.receive(…)` is in flight. Prevents us
    /// from stacking overlapping receives when multiple send/receive
    /// callers all see an empty buffer.
    var receiveInFlight = false

    /// Completions waiting for the next chunk of bytes to arrive on the
    /// wire. Multiple callers (concurrent send + receive, each hitting
    /// `WOLFSSL_ERROR_WANT_READ`) all wait on the single in-flight receive;
    /// every waiter fires when that receive's callback lands.
    var receiveWaiters: [(Error?) -> Void] = []

    /// Retained copy of the ClientHello body produced by
    /// `TLSClientHelloBuilder`. Must outlive `wolfSSL_connect` so the
    /// custom-CH callback's `const unsigned char*` stays valid.
    var clientHelloBody: [UInt8] = []

    /// Set from `certVerifyCallback` when SecTrust rejects the leaf chain
    /// (and no pinned fingerprint matches). Read from the handshake pump
    /// right after `wolfSSL_connect` returns so the caller can distinguish
    /// "bad certificate" from a generic handshake failure, and fail fast
    /// instead of waiting for wolfSSL to wind down through alert/close.
    var certificateRejected = false

    init(ctx: OpaquePointer, ssl: OpaquePointer, queue: DispatchQueue) {
        self.ctx = ctx
        self.ssl = ssl
        self.queue = queue
    }

    deinit {
        // wolfSSL objects are freed in reverse creation order. After this
        // the IO callbacks installed on `ssl` will never be invoked again,
        // so the `Unmanaged.passUnretained(self)` pointer we gave wolfSSL
        // via wolfSSL_SetIOReadCtx / wolfSSL_SetIOWriteCtx becomes moot.
        wolfSSL_free(ssl)
        wolfSSL_CTX_free(ctx)
    }
}

/// wolfSSL NamedGroup values (mirrors the WOLFSSL_ECC_* constants in ssl.h).
enum TLSNamedGroup {
    static let secp256r1: UInt16 = 23
    static let secp384r1: UInt16 = 24
    static let x25519:    UInt16 = 29
}

/// Return codes that our BIO callbacks signal to wolfSSL when the Swift
/// side has no data yet or can't proceed. wolfSSL defines these in
/// `wolfssl/internal.h` but they're not re-exported to Swift — redeclare
/// the two we need.
enum TLSBIOStatus {
    static let wantRead:  Int32 = -2   // WOLFSSL_CBIO_ERR_WANT_READ
    static let wantWrite: Int32 = -2   // WOLFSSL_CBIO_ERR_WANT_WRITE (same value)
    static let generalError: Int32 = -1
    static let connectionClose: Int32 = -6  // WOLFSSL_CBIO_ERR_CONN_CLOSE
}
