# NaiveProxy Swift Reimplementation Plan

> **Reference source**: The original NaiveProxy C++ implementation is located at `/Volumes/Work/naiveproxy`. Key source files are under `src/net/tools/naive/`. After completing each implementation phase, cross-check against the NaiveProxy reference source to verify correctness of wire formats, header values, padding logic, and protocol state machines.

## Architecture Overview

NaiveProxy supports two proxy schemes: `https://` (HTTP/2 over TLS) and `quic://` (HTTP/3 over QUIC). The implementation is split into three protocol layers: HTTPS (TLS), HTTP/2, and HTTP/3.

```
┌──────────────────────────────────────────────────┐
│  NaiveProxyConnection (ProxyConnection subclass) │
│  ┌───────────────┐  ┌─────────────────────────┐  │
│  │ PaddingFramer │  │ PaddingHeaderNegotiator │  │
│  └───────┬───────┘  └────────────┬────────────┘  │
│          │                       │               │
│  ┌───────▼───────────────────────▼────────────┐  │
│  │          NaiveTransport (protocol)         │  │
│  │  ┌────────────────┐    ┌────────────────┐  │  │
│  │  │ HTTP2Transport │    │ HTTP3Transport │  │  │
│  │  │ (TLS + h2)     │    │ (QUIC + h3)    │  │  │
│  │  └────────────────┘    └────────────────┘  │  │
│  └────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────┘
```

---

## Protocol 1: HTTPS (TLS Layer)

**Purpose**: Establish a TLS 1.3 connection to the naive server with ALPN `h2`.

**What's different from Anywhere's existing `TLSClient`**: The current `TLSClient` does a full custom TLS 1.3 handshake with X25519 only. For naive, we need standard TLS with proper ALPN negotiation. The simplest approach is to use Apple's `Network.framework` (`NWConnection` with TLS) or `Security.framework` (`SSLCreateContext`), since the whole point is to look like legitimate iOS traffic.

**Recommended approach**: Use `NWConnection` with TLS — it produces Apple's native TLS fingerprint (which is the iOS equivalent of naive's Chromium fingerprint strategy).

### Files to Create

**`Protocols/Naive/NaiveTLSTransport.swift`** (~100 lines)

```
Responsibilities:
- Establish TCP connection to proxy server
- TLS handshake with ALPN ["h2"] (for HTTP/2) or ["h3"] (for HTTP/3, handled separately)
- Certificate validation (standard, with optional insecure mode)
- Provide raw read/write over TLS for the HTTP/2 layer above

Interface:
  class NaiveTLSTransport {
    init(host: String, port: UInt16, sni: String?, alpn: [String])
    func connect(completion: (Error?) -> Void)
    func send(data: Data, completion: (Error?) -> Void)
    func receive(completion: (Data?, Error?) -> Void)
    func cancel()
  }

Implementation options:
  Option A (Recommended): Use BSDSocket + sec_protocol_options for TLS
    - Reuses Anywhere's existing BSDSocket infrastructure
    - Add TLS via Security.framework's SSLCreateContext or sec_protocol_options
    - Pro: Consistent with existing codebase
    - Con: More manual work

  Option B: Use NWConnection with .tls
    - Apple's high-level API, handles TLS automatically
    - Pro: Simplest, best TLS fingerprint
    - Con: Different pattern from existing BSDSocket-based code

  Decision: Option A - wrap BSDSocket with Security.framework TLS,
  keeping consistency with existing code. Add ALPN configuration
  to the handshake.
```

### Key Parameters

```
ALPN: ["h2"] for HTTP/2, no ALPN needed for QUIC (handled at QUIC layer)
SNI: proxy server hostname (configurable)
Min TLS version: TLS 1.2 (for h2 requirement)
Certificate validation: Standard iOS trust evaluation
```

---

## Protocol 2: HTTP/2 CONNECT Tunnel

**Purpose**: Establish an HTTP/2 CONNECT tunnel through the naive proxy server, with padding negotiation.

This is the core protocol and the most code. We need a **minimal HTTP/2 client** — not a general-purpose implementation, just enough for a single CONNECT stream.

### Files to Create

#### `Protocols/Naive/HTTP2/HTTP2Connection.swift` (~400 lines)

```
The main HTTP/2 session manager.

Responsibilities:
- Send connection preface
- Exchange SETTINGS frames
- Open a single CONNECT stream
- Handle HEADERS, DATA, WINDOW_UPDATE, PING, GOAWAY, RST_STREAM
- Bidirectional data relay through the tunnel

State Machine:
  .idle
    → send connection preface ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    → send SETTINGS frame (INITIAL_WINDOW_SIZE=67108864, MAX_CONCURRENT_STREAMS=100)
  .settingsExchanged
    → receive SETTINGS from server
    → send SETTINGS ACK
    → receive SETTINGS ACK from server
  .ready
    → send HEADERS frame (CONNECT request on stream 1)
  .tunnelPending
    → receive HEADERS frame (200 response on stream 1)
    → parse padding-type-reply header
  .tunnelOpen
    → bidirectional DATA frames on stream 1
    → send/receive WINDOW_UPDATE as needed
  .closed

Connection preface (fixed 24 bytes):
  "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

SETTINGS to send:
  SETTINGS_INITIAL_WINDOW_SIZE (0x3) = 67,108,864  (64 MB - matches naive)
  SETTINGS_MAX_CONCURRENT_STREAMS (0x3) = 100

After SETTINGS exchange, send WINDOW_UPDATE on stream 0:
  Window increment = 67,108,864 * 2 - 65,535  (expand session window to 128 MB)

CONNECT request pseudo-headers (stream 1):
  :method = CONNECT
  :authority = <destination_host>:<destination_port>

CONNECT request regular headers:
  proxy-authorization: Basic <base64(user:pass)>  (if credentials set)
  padding: <16-32 random non-indexed chars>
  padding-type-request: 1, 0
  [fastopen: 1]  (if server padding type already known)

Data relay:
  - Upstream: write user data as DATA frames on stream 1
  - Downstream: receive DATA frames on stream 1, deliver to user
  - Flow control: send WINDOW_UPDATE when half the window is consumed
  - Max DATA frame payload: 16,384 bytes (HTTP/2 default)
```

#### `Protocols/Naive/HTTP2/HTTP2Framer.swift` (~200 lines)

```
HTTP/2 binary frame serializer/deserializer.

Frame header format (9 bytes):
  [3 bytes] Length (payload length, max 16384 for DATA)
  [1 byte]  Type
  [1 byte]  Flags
  [4 bytes] Stream ID (bit 0 reserved)

Frame types to implement:
  0x0 DATA       - tunnel payload
  0x1 HEADERS    - CONNECT request/response
  0x3 RST_STREAM - stream error
  0x4 SETTINGS   - connection parameters
  0x6 PING       - keepalive (echo ACK)
  0x7 GOAWAY     - graceful shutdown
  0x8 WINDOW_UPDATE - flow control

Struct definitions:
  struct HTTP2Frame {
    let length: UInt32      // 24-bit
    let type: UInt8
    let flags: UInt8
    let streamID: UInt32    // 31-bit
    let payload: Data
  }

  enum HTTP2FrameType: UInt8 {
    case data = 0x0
    case headers = 0x1
    case rstStream = 0x3
    case settings = 0x4
    case ping = 0x6
    case goaway = 0x7
    case windowUpdate = 0x8
  }

  Flags:
    DATA:     END_STREAM = 0x1, PADDED = 0x8
    HEADERS:  END_STREAM = 0x1, END_HEADERS = 0x4, PADDED = 0x8
    SETTINGS: ACK = 0x1
    PING:     ACK = 0x1

Functions:
  func serialize(frame: HTTP2Frame) -> Data
  func deserialize(from buffer: inout Data) -> HTTP2Frame?  // returns nil if incomplete

Frame reading strategy:
  - Read 9-byte header first
  - Extract length from header
  - Read exactly `length` more bytes for payload
  - Return complete frame
```

#### `Protocols/Naive/HTTP2/HPACKEncoder.swift` (~200 lines)

```
Minimal HPACK encoder/decoder for the CONNECT tunnel.

We do NOT need:
  - Dynamic table (we can use literal-without-indexing for everything)
  - Huffman decoding of arbitrary headers
  - Full static table lookup

We DO need:
  - Integer encoding (prefix-coded, RFC 7541 §5.1)
  - String encoding (raw, no Huffman - simpler and matches naive's intent)
  - Literal header without indexing (0000xxxx prefix, RFC 7541 §6.2.2)
  - Indexed header field (1xxxxxxx prefix) for decoding responses
  - Static table entries for common pseudo-headers

Encoding the CONNECT request:
  :method = CONNECT     → Indexed (static table index 15)
  :authority = host:port → Literal without indexing, name index 1
  proxy-authorization    → Literal without indexing, name literal
  padding                → Literal without indexing, name literal
  padding-type-request   → Literal without indexing, name literal
  fastopen               → Literal without indexing, name literal

Decoding the response:
  :status = 200          → Indexed (static table index 8)
  padding                → Literal (check for presence)
  padding-type-reply     → Literal (extract value "0" or "1")

Static table entries needed (RFC 7541 Appendix A):
  Index 1:  :authority  (empty value)
  Index 8:  :status 200
  Index 15: :method CONNECT

Integer encoding (RFC 7541 §5.1):
  func encodeInteger(_ value: Int, prefixBits: Int) -> Data
  func decodeInteger(from data: Data, at offset: inout Int, prefixBits: Int) -> Int

String encoding (RFC 7541 §5.2):
  func encodeString(_ string: String, huffman: Bool = false) -> Data
  func decodeString(from data: Data, at offset: inout Int) -> String
```

#### `Protocols/Naive/HTTP2/HTTP2FlowControl.swift` (~80 lines)

```
Tracks send/receive windows for stream and connection level.

class HTTP2FlowControl {
  private var connectionSendWindow: Int    // how much WE can send
  private var connectionRecvWindow: Int    // how much we've received (track for WINDOW_UPDATE)
  private var streamSendWindow: Int
  private var streamRecvWindow: Int

  let initialWindowSize: Int = 67_108_864  // 64 MB (naive's setting)
  let windowUpdateThreshold: Int           // send WINDOW_UPDATE at 50% consumed

  func consumeSendWindow(bytes: Int) -> Bool    // returns false if would exceed
  func consumeRecvWindow(bytes: Int) -> Int?    // returns WINDOW_UPDATE increment if needed
  func applySettings(initialWindowSize: Int)
  func applyWindowUpdate(streamID: UInt32, increment: Int)
}

Window size calculations (from naive):
  kMaxBandwidthMBps = 125
  kTypicalRttSecond = 0.256
  kMaxBdpMB = 125 * 0.256 = 32
  kTypicalWindow = 32 * 2 * 1024 * 1024 = 67,108,864 (64 MB)

  Stream initial window: 67,108,864 bytes (64 MB)
  Session max recv window: 134,217,728 bytes (128 MB)
  WINDOW_UPDATE sent after consuming ~50% of the window
```

---

## Protocol 3: HTTP/3 CONNECT Tunnel (over QUIC)

**Purpose**: Establish an HTTP/3 CONNECT tunnel over QUIC (UDP-based).

This is significantly more complex than HTTP/2 because QUIC itself is a full transport protocol. Implementing QUIC from scratch (packet encryption, loss recovery, congestion control, connection migration) would be thousands of lines. Use Apple's `Network.framework` QUIC support instead (iOS 15+).

### Files to Create

#### `Protocols/Naive/HTTP3/NaiveQUICTransport.swift` (~150 lines)

```
Uses NWConnection with QUIC parameters.

class NaiveQUICTransport {
  private var connection: NWConnection

  init(host: String, port: UInt16, sni: String?) {
    let quicOptions = NWProtocolQUIC.Options()
    quicOptions.alpn = ["h3"]
    // TLS 1.3 is mandatory for QUIC

    let params = NWParameters(quic: quicOptions)
    connection = NWConnection(host: ..., port: ..., using: params)
  }
}

Apple's NWConnection QUIC support:
  - Handles QUIC handshake (TLS 1.3 inside QUIC)
  - Manages QUIC streams (bidirectional, unidirectional)
  - Handles flow control at QUIC level
  - Does NOT implement HTTP/3 framing

QUIC version: RFC 9000 (QUIC v1, version 0x00000001)
  - Only version supported by naive
  - TLS 1.3 inside QUIC (PROTOCOL_TLS1_3)

Key constraint from naive:
  - QUIC proxies cannot follow TCP-based proxies in a chain
  - QUIC proxies must be the first in any proxy chain
```

#### `Protocols/Naive/HTTP3/HTTP3Connection.swift` (~350 lines)

```
HTTP/3 session over QUIC streams.

HTTP/3 uses multiple QUIC streams:
  - Control stream (unidirectional, client→server): sends SETTINGS
  - Control stream (unidirectional, server→client): receives SETTINGS
  - Request stream (bidirectional): CONNECT tunnel

State Machine:
  .idle
    → open QUIC connection (handled by NWConnection)
  .connected
    → open unidirectional stream, send HTTP/3 SETTINGS
    → open bidirectional stream for CONNECT request
  .tunnelPending
    → send HEADERS frame (CONNECT) on request stream
    → receive HEADERS frame (200 response)
  .tunnelOpen
    → bidirectional DATA frames on request stream
  .closed

HTTP/3 Frame format (variable-length):
  [variable-int] Type
  [variable-int] Length
  [Length bytes]  Payload

Frame types:
  0x0 DATA     - tunnel payload
  0x1 HEADERS  - QPACK-encoded headers
  0x4 SETTINGS - connection settings

Key differences from HTTP/2:
  - Frames are on QUIC streams, not multiplexed on one TCP connection
  - No WINDOW_UPDATE frames (QUIC handles flow control natively)
  - No PING/GOAWAY at HTTP/3 level (QUIC handles keepalive)
  - HEADERS use QPACK instead of HPACK

Stream termination:
  - Stream remains open and bidirectional after tunnel established
  - Tunnel closes when either side sends FIN in final STREAM frame
  - Or resets stream with QUIC_STREAM_CANCELLED
  - No special frame exchange needed for tunnel closure
```

#### `Protocols/Naive/HTTP3/QPACKEncoder.swift` (~180 lines)

```
Minimal QPACK encoder for CONNECT tunnel.

QPACK (RFC 9204) differs from HPACK:
  - Separate encoder/decoder streams (unidirectional QUIC streams)
  - Different static table (98 entries vs HPACK's 61)
  - No dynamic table needed for our use case

For minimal CONNECT, we can use:
  - Static table references only
  - Literal with name reference
  - No dynamic table (Required Insert Count = 0)

QPACK static table entries we need:
  Index 15: :method = CONNECT
  Index 1:  :authority (empty value)
  Index 24: :status = 200

Encoded header block prefix (RFC 9204 §4.5):
  Required Insert Count = 0 (encoded as 0)
  Delta Base = 0
  → prefix bytes: 0x00 0x00

Then field lines:
  - Indexed: 1Txxxxxx (T=1 for static)
  - Literal with name ref: 01N1xxxx (N=0 no forward ref, 1=static table)
  - Literal: 001Nxxxx

For CONNECT request:
  0x00 0x00                              // prefix (RIC=0, DB=0)
  0xC0 | 15                             // :method=CONNECT (static index 15)
  0x51 | 0, encode_string(host:port)    // :authority=host:port (static ref 1)
  0x27 | 0, encode_name, encode_value   // literal headers (padding, etc.)
```

#### `Protocols/Naive/HTTP3/QUICVarInt.swift` (~40 lines)

```
QUIC variable-length integer encoding/decoding (RFC 9000 §16).

  1 byte:  0xxxxxxx                     (0-63)
  2 bytes: 01xxxxxx xxxxxxxx            (0-16383)
  4 bytes: 10xxxxxx xxxxxxxx * 3        (0-1073741823)
  8 bytes: 11xxxxxx xxxxxxxx * 7        (0-4611686018427387903)

func encodeVarInt(_ value: UInt64) -> Data
func decodeVarInt(from data: Data, at offset: inout Int) -> UInt64?
```

---

## Shared Components (Used by Both HTTP/2 and HTTP/3)

#### `Protocols/Naive/NaivePaddingFramer.swift` (~60 lines)

```
Encodes/decodes naive's padding frames for the first 8 read/write operations.

struct NaivePaddingFramer {
  private let maxReadFrames: Int = 8
  private var numReadFrames: Int = 0
  private var numWrittenFrames: Int = 0

  // Read state machine
  private enum ReadState {
    case payloadLength1, payloadLength2, paddingLength1, payload, padding
  }
  private var state: ReadState = .payloadLength1
  private var readPayloadLength: Int = 0
  private var readPaddingLength: Int = 0

  // Returns unpadded payload bytes extracted from padded input.
  // Returns 0 bytes for pure-padding frames (not EOF).
  mutating func read(padded: Data, into output: inout Data) -> Int

  // Returns padded frame containing the payload.
  // paddingSize: random [0, 255], biased larger for small payloads to server.
  mutating func write(payload: Data, paddingSize: Int) -> Data

  var isPaddingActive: Bool { true if under 8 frames }
}

Wire format (per frame):
  Byte 0: payload_size >> 8
  Byte 1: payload_size & 0xFF
  Byte 2: padding_size
  Bytes 3..<3+payload_size: payload
  Bytes 3+payload_size..<3+payload_size+padding_size: zeros

After 8 frames: raw passthrough (no framing).
```

#### `Protocols/Naive/NaivePaddingNegotiator.swift` (~80 lines)

```
Handles padding header generation and response parsing.

struct NaivePaddingNegotiator {
  // The 17 non-indexed HPACK characters (≥8-bit Huffman codes in [0x20..0x7f])
  // Selected from RFC 7541 Huffman table in iteration order:
  //   Characters with Huffman encoding length >= 8 bits
  //   in the printable ASCII range 0x20-0x7f
  private static let nonIndexCodes: [UInt8] = [...]

  // Generate padding header value (16-32 random chars from nonIndexCodes)
  static func generatePaddingValue() -> String

  // Generate request headers dict
  static func requestHeaders(fastOpen: Bool) -> [(name: String, value: String)]
  // Returns:
  //   ("padding", "<random 16-32 chars>")
  //   ("padding-type-request", "1, 0")
  //   ("fastopen", "1")  // only if fastOpen == true

  // Parse response headers to determine negotiated padding type
  enum PaddingType { case none, variant1 }
  static func parseResponse(headers: [(name: String, value: String)]) -> PaddingType
  // Logic:
  //   if "padding-type-reply" header exists → parse "0" or "1"
  //   else if "padding" header exists → .variant1 (backward compat)
  //   else → .none
}
```

#### `Protocols/Naive/NaiveProxyConnection.swift` (~200 lines)

```
The ProxyConnection subclass that ties everything together.

class NaiveProxyConnection: ProxyConnection {
  private let transport: NaiveTransport  // HTTP2Transport or HTTP3Transport
  private var readFramer: NaivePaddingFramer
  private var writeFramer: NaivePaddingFramer
  private let paddingType: NaivePaddingNegotiator.PaddingType

  override var isConnected: Bool { transport.isConnected }

  override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
    let toSend: Data
    if writeFramer.isPaddingActive && paddingType == .variant1 {
      let paddingSize = generatePaddingSize(payloadSize: data.count, direction: .server)
      toSend = writeFramer.write(payload: data, paddingSize: paddingSize)
    } else {
      toSend = data
    }
    transport.sendData(toSend, completion: completion)
  }

  override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
    transport.receiveData { [weak self] data, error in
      guard let self, let data else { completion(nil, error); return }
      if self.readFramer.isPaddingActive && self.paddingType == .variant1 {
        var output = Data()
        let payloadBytes = self.readFramer.read(padded: data, into: &output)
        if payloadBytes > 0 {
          completion(output, nil)
        } else {
          // Pure padding frame, read more
          self.receiveRaw(completion: completion)
        }
      } else {
        completion(data, nil)
      }
    }
  }

  // Padding size generation (matches naive_padding_socket.cc)
  private func generatePaddingSize(payloadSize: Int, direction: Direction) -> Int {
    if direction == .server && payloadSize < 100 {
      return Int.random(in: (255 - payloadSize)...255)
    } else {
      return Int.random(in: 0...255)
    }
  }
}
```

#### `Protocols/Naive/NaiveConfiguration.swift` (~40 lines)

```
struct NaiveConfiguration {
  let proxyHost: String
  let proxyPort: UInt16
  let username: String?
  let password: String?
  let sni: String?           // TLS SNI, defaults to proxyHost
  let scheme: NaiveScheme     // .https or .quic
  let insecureTLS: Bool       // skip certificate validation

  enum NaiveScheme: String {
    case https   // HTTP/2 over TLS
    case quic    // HTTP/3 over QUIC
  }
}
```

---

## Integration with Anywhere

### Changes to existing files

| File | Change |
|---|---|
| `ProxyConfiguration.swift` | Add `case naive` to `OutboundProtocol`. Add `naiveUsername: String?`, `naivePassword: String?`, `naiveScheme: String?` fields |
| `ProxyClient.swift` | Add naive case in connection factory — when `outboundProtocol == .naive`, create `NaiveProxyConnection` via HTTP2 or HTTP3 transport |
| `ProxyConfiguration+URLParsing.swift` | Parse `naive+https://user:pass@host:port` and `naive+quic://user:pass@host:port` URLs |

---

## File Summary

```
Protocols/Naive/
├── NaiveConfiguration.swift          (~40 lines)   - Config struct
├── NaivePaddingFramer.swift          (~60 lines)   - Padding frame encode/decode
├── NaivePaddingNegotiator.swift      (~80 lines)   - Padding header negotiation
├── NaiveProxyConnection.swift        (~200 lines)  - ProxyConnection subclass
├── NaiveTLSTransport.swift           (~100 lines)  - TLS transport for HTTP/2
├── HTTP2/
│   ├── HTTP2Connection.swift         (~400 lines)  - HTTP/2 session + CONNECT tunnel
│   ├── HTTP2Framer.swift             (~200 lines)  - HTTP/2 frame serialize/deserialize
│   ├── HPACKEncoder.swift            (~200 lines)  - Minimal HPACK encode/decode
│   └── HTTP2FlowControl.swift        (~80 lines)   - Flow control window tracking
└── HTTP3/
    ├── HTTP3Connection.swift         (~350 lines)  - HTTP/3 session + CONNECT tunnel
    ├── NaiveQUICTransport.swift      (~150 lines)  - QUIC transport via Network.framework
    ├── QPACKEncoder.swift            (~180 lines)  - Minimal QPACK encode/decode
    └── QUICVarInt.swift              (~40 lines)   - QUIC variable-length integers
```

---

## Implementation Order

| Phase | Files | ~Lines | Depends On |
|---|---|---|---|
| **Phase 1: Shared** | `NaivePaddingFramer.swift`, `NaivePaddingNegotiator.swift`, `NaiveConfiguration.swift` | 180 | Nothing |
| **Phase 2: HTTP/2 Framing** | `HTTP2Framer.swift`, `HPACKEncoder.swift`, `HTTP2FlowControl.swift` | 480 | Nothing |
| **Phase 3: HTTP/2 Transport** | `HTTP2Connection.swift`, `NaiveTLSTransport.swift` | 500 | Phase 1, 2 |
| **Phase 4: Integration** | `NaiveProxyConnection.swift` + Anywhere integration | 250 | Phase 3 |
| **Phase 5: HTTP/3 (Deferred)** | `QUICVarInt.swift`, `QPACKEncoder.swift`, `HTTP3Connection.swift`, `NaiveQUICTransport.swift` | 720 | Phase 1 |

**Phase 1-4** gives a working naive client over HTTPS/HTTP2 (~1,400 lines of Swift).
**Phase 5** adds HTTP/3 over QUIC (~720 additional lines, can be deferred).

**Total: ~2,100 lines of Swift across 12 files.**

---

## Implementation Checklist

### Phase 1: Shared Components
- [x] `NaiveConfiguration.swift` — config struct with host, port, username, password, scheme, SNI
- [x] `NaivePaddingFramer.swift` — padding frame encode/decode
  - [x] Write: 3-byte header (uint16 payload_size BE + uint8 padding_size) + payload + zeros
  - [x] Read: state machine (payloadLength1 → payloadLength2 → paddingLength → payload → padding)
  - [x] Frame counter — disable padding after 8 frames (read and write tracked independently)
  - [x] Handle partial reads (framer must be resumable across multiple data chunks)
- [x] `NaivePaddingNegotiator.swift` — padding header generation and response parsing
  - [x] Build the 17-char non-indexed HPACK character table (printable ASCII 0x20-0x7f with Huffman length ≥ 8 bits)
  - [x] `generatePaddingValue()` — random 16-32 chars from the table, seeded by random 64-bit value
  - [x] `requestHeaders(fastOpen:)` — return `padding`, `padding-type-request: 1, 0`, optional `fastopen: 1`
  - [x] `parseResponse(headers:)` — check `padding-type-reply` header, fall back to `padding` header presence

### Phase 2: HTTP/2 Framing
- [x] `HTTP2Framer.swift` — frame serialization/deserialization
  - [x] `HTTP2Frame` struct (length, type, flags, streamID, payload)
  - [x] `HTTP2FrameType` enum (data=0x0, headers=0x1, rstStream=0x3, settings=0x4, ping=0x6, goaway=0x7, windowUpdate=0x8)
  - [x] Frame flag constants (END_STREAM=0x1, END_HEADERS=0x4, ACK=0x1, PADDED=0x8)
  - [x] `serialize(frame:) -> Data` — 9-byte header + payload
  - [x] `deserialize(from buffer:) -> HTTP2Frame?` — returns nil if buffer has incomplete frame
  - [x] Buffer accumulation for partial frame reads
  - [x] Convenience builders: settingsFrame, settingsAckFrame, windowUpdateFrame, headersFrame, dataFrame, pingAckFrame
  - [x] Payload parsers: parseSettings, parseWindowUpdate, parseGoaway, parseRstStream
- [x] `HPACKEncoder.swift` — minimal HPACK encode/decode
  - [x] Integer encoding with prefix bits (RFC 7541 §5.1)
  - [x] Integer decoding with prefix bits
  - [x] String encoding (raw, no Huffman)
  - [x] String decoding (handle both raw and Huffman-encoded from server)
  - [x] Indexed header field decoding (1xxxxxxx prefix) — for `:status 200` (index 8)
  - [x] Literal without indexing encoding (0000xxxx prefix) — for `:method CONNECT`, `:authority`, `padding`, etc.
  - [x] Literal with incremental indexing decoding (01xxxxxx prefix) — for server response headers
  - [x] Full static table (61 entries, RFC 7541 Appendix A)
  - [x] Dynamic table support for response decoding
  - [x] Full Huffman decode tree (257 entries, RFC 7541 Appendix B) — verified against reference
  - [x] `encodeConnectRequest(authority:, extraHeaders:) -> Data`
  - [x] `decodeHeaders(from data:) -> [(name, value)]`
  - [x] NOTE: Plan incorrectly stated `:method CONNECT` is static index 15; actual index 2 (`:method`) with literal value "CONNECT"
- [x] `HTTP2FlowControl.swift` — flow control window tracking
  - [x] Connection-level send/receive windows
  - [x] Stream-level send/receive windows
  - [x] Initial window size: 67,108,864 (64 MB, matching naive)
  - [x] Session window expansion to 134,217,728 (128 MB)
  - [x] `consumeSendWindow(bytes:)` — check if send is allowed
  - [x] `consumeRecvWindow(bytes:)` — return WINDOW_UPDATE increment when ≥50% consumed
  - [x] `applyWindowUpdate(streamID:, increment:)` — update send window
  - [x] `applySettings(initialWindowSize:)` — adjust windows from server SETTINGS
  - [x] NOTE: Plan incorrectly labeled SETTINGS_INITIAL_WINDOW_SIZE as 0x3; correct identifier is 0x4

### Phase 3: HTTP/2 Transport
- [x] `NaiveTLSTransport.swift` — TLS connection to proxy server
  - [x] TCP connection via BSDSocket (reuses existing infrastructure)
  - [x] TLS handshake with ALPN `["h2"]` via existing TLSClient + TLSRecordConnection
  - [x] SNI configuration (defaults to proxy hostname)
  - [x] Standard certificate validation via SecTrust (existing TLSClient)
  - [x] Optional insecure mode (allowInsecure via TLSConfiguration)
  - [x] Raw send/receive over TLS for HTTP/2 layer via TLSRecordConnection
- [x] `HTTP2Connection.swift` — HTTP/2 session and CONNECT tunnel
  - [x] State machine: idle → connecting → prefaceSent → ready → tunnelPending → tunnelOpen → closed
  - [x] Send connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`)
  - [x] Send initial SETTINGS (INITIAL_WINDOW_SIZE=67108864)
  - [x] Receive and process server SETTINGS
  - [x] Send SETTINGS ACK
  - [x] Send connection-level WINDOW_UPDATE to expand to 128 MB
  - [x] Send CONNECT HEADERS frame on stream 1 (HPACK-encoded)
  - [x] Include proxy-authorization header (Basic auth, base64-encoded)
  - [x] Include padding negotiation headers
  - [x] Receive and parse CONNECT response HEADERS
  - [x] Handle 200 OK — tunnel established
  - [x] Handle 407 — proxy authentication required
  - [x] Handle other status codes — tunnel failed
  - [x] Bidirectional DATA frame relay on stream 1
  - [x] Receive loop: read frames, dispatch by type (DATA, PING, WINDOW_UPDATE, GOAWAY, RST_STREAM)
  - [x] PING handling: echo back with ACK flag
  - [x] GOAWAY handling: graceful shutdown
  - [x] RST_STREAM handling: report stream error
  - [x] Send WINDOW_UPDATE when receive window is ≥50% consumed
  - [x] DATA frame size limit: max 16,384 bytes payload
  - [x] END_STREAM flag handling (tunnel close)
  - [x] Error propagation to NaiveProxyConnection

### Phase 4: Integration
- [x] `NaiveProxyConnection.swift` — ProxyConnection subclass
  - [x] Wrap HTTP2Connection as transport
  - [x] Apply padding framer on send (first 8 writes) when variant1 negotiated
  - [x] Apply padding framer on receive (first 8 reads) when variant1 negotiated
  - [x] Padding size generation: server direction with payloads <100 bytes biased to [255-len, 255]
  - [x] Padding size generation: all other payloads uniform random [0, 255]
  - [x] Handle pure-padding reads (0 payload bytes) — re-read automatically
  - [x] Write fragmentation for server-direction medium payloads (400-1024 bytes, split to 200-300 byte chunks)
  - [x] `isConnected` delegation to HTTP2Connection
  - [x] `cancel()` delegation via HTTP2Connection.close()
  - [x] `responseHeaderReceived = true` (no VLESS response header)
  - [x] TCP-only validation (rejects UDP/mux commands)
- [x] `ProxyConfiguration.swift` changes
  - [x] Add `case naive` to `OutboundProtocol` enum
  - [x] Add `naiveUsername: String?` field
  - [x] Add `naivePassword: String?` field
  - [x] Add `naiveScheme: String?` field (defaults to `"https"`)
  - [x] Update `contentEquals()` to include naive fields
  - [x] Update `init(from decoder:)` for backward compatibility
  - [x] Update both init overloads with naive parameters
- [x] `ProxyClient.swift` changes
  - [x] Add naive case in `connectWithCommand` (before transport routing)
  - [x] `connectWithNaive()` creates NaiveTLSTransport → HTTP2Connection → NaiveProxyConnection
  - [x] Pass destination host:port to CONNECT request
  - [x] Pass credentials from NaiveConfiguration
- [x] `ProxyConfiguration+URLParsing.swift` changes
  - [x] Parse `https://user:pass@host:port` URLs
  - [x] Parse `quic://user:pass@host:port` URLs (scheme stored, QUIC deferred to Phase 5)
- [x] `ProxyConfiguration+URLExport.swift` changes
  - [x] Add `.naive` case to `toURL()` switch
  - [x] `toNaiveURL()` exports `{scheme}://user:pass@host:port#name`
- [x] `ProxyConfiguration+DictParsing.swift` changes
  - [x] Parse `naiveUsername`, `naivePassword`, `naiveScheme` from dictionary
- [ ] End-to-end testing with a naive server (Caddy + forwardproxy)

### Phase 5: HTTP/3 over QUIC (Deferred)
- [ ] `QUICVarInt.swift` — QUIC variable-length integer encoding/decoding
  - [ ] `encodeVarInt(_ value: UInt64) -> Data` (1/2/4/8 byte encoding)
  - [ ] `decodeVarInt(from data:, at offset:) -> UInt64?`
- [ ] `QPACKEncoder.swift` — minimal QPACK encode/decode
  - [ ] Header block prefix encoding (Required Insert Count=0, Delta Base=0)
  - [ ] Indexed field line (static table reference)
  - [ ] Literal with name reference (static table)
  - [ ] Literal field line (name + value)
  - [ ] Static table entries: index 15 (`:method CONNECT`), index 1 (`:authority`), index 24 (`:status 200`)
  - [ ] `encodeConnectRequest(authority:, extraHeaders:) -> Data`
  - [ ] `decodeResponseHeaders(from data:) -> [(name, value)]`
- [ ] `NaiveQUICTransport.swift` — QUIC connection via Network.framework
  - [ ] NWConnection with `NWProtocolQUIC.Options` (ALPN `["h3"]`)
  - [ ] QUIC stream management (open bidirectional + unidirectional)
  - [ ] Connection lifecycle (connect, cancel)
  - [ ] Send/receive on QUIC streams
- [ ] `HTTP3Connection.swift` — HTTP/3 session and CONNECT tunnel
  - [ ] State machine: idle → connected → tunnelPending → tunnelOpen → closed
  - [ ] Open unidirectional control stream, send HTTP/3 SETTINGS frame
  - [ ] Open bidirectional request stream for CONNECT
  - [ ] Send HEADERS frame (QPACK-encoded CONNECT request)
  - [ ] Include proxy-authorization, padding negotiation headers
  - [ ] Receive and parse HEADERS response (200 OK)
  - [ ] Bidirectional DATA frame relay on request stream
  - [ ] HTTP/3 frame serialization (variable-length type + length + payload)
  - [ ] No WINDOW_UPDATE needed (QUIC handles flow control)
  - [ ] No PING needed (QUIC handles keepalive)
  - [ ] Stream termination (FIN flag)
  - [ ] Error propagation
- [ ] Update `NaiveProxyConnection` to support HTTP3 transport
- [ ] Update `ProxyClient` to create HTTP3 transport when `naiveScheme == "quic"`
- [ ] End-to-end testing with naive QUIC server
