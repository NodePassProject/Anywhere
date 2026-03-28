# Anywhere Network Extension — Complete Codebase Analysis

> **Purpose**: Internal reference for Claude when making code changes. Not user-facing documentation.
> **Last updated**: 2026-03-28

---

## TABLE OF CONTENTS

1. [Project Overview](#1-project-overview)
2. [Build Targets & Configuration](#2-build-targets--configuration)
3. [Directory Map](#3-directory-map)
4. [App ↔ Extension IPC](#4-app--extension-ipc)
5. [Network Extension Architecture](#5-network-extension-architecture)
6. [Packet Flow Diagrams](#6-packet-flow-diagrams)
7. [Protocol Stack](#7-protocol-stack)
8. [ProxyClient — The Central Factory](#8-proxyclient--the-central-factory)
9. [VLESS & Vision Flow](#9-vless--vision-flow)
10. [Shadowsocks Protocol](#10-shadowsocks-protocol)
11. [SOCKS5 Protocol](#11-socks5-protocol)
12. [TLS Layer](#12-tls-layer)
13. [Reality Layer](#13-reality-layer)
14. [Transport Layers](#14-transport-layers)
15. [Multiplexing (Mux/XUDP)](#15-multiplexing-muxxudp)
16. [Naive Proxy (HTTP CONNECT)](#16-naive-proxy-http-connect)
17. [Direct Connection](#17-direct-connection)
18. [Shared Infrastructure](#18-shared-infrastructure)
19. [Main App Layer](#19-main-app-layer)
20. [Data Models & Persistence](#20-data-models--persistence)
21. [Threading Model](#21-threading-model)
22. [Error Handling Patterns](#22-error-handling-patterns)
23. [Constants & Magic Values](#23-constants--magic-values)
24. [File Index](#24-file-index)

---

## 1. PROJECT OVERVIEW

**Anywhere** is a native iOS/tvOS VLESS proxy client. One SPM dependency (BLAKE3). C libraries lwIP and libyaml are vendored. Built entirely with Xcode (objectVersion 77).

**Supported outbound protocols**: VLESS, Shadowsocks (legacy + 2022), SOCKS5, HTTP/1.1, HTTP/2, HTTP/3 (Naive)
**Supported transports**: TCP, WebSocket, HTTP Upgrade, XHTTP
**Supported security**: None, TLS (1.0–1.3), Reality (TLS 1.3 fingerprint spoofing)
**Advanced features**: Proxy chaining, Mux with XUDP, Vision direct-copy flow, Fake-IP DNS, GeoIP routing, domain rule routing (trie + Aho-Corasick)

**App Group**: `group.com.argsment.Anywhere`
**Bundle**: `com.argsment.Anywhere`

---

## 2. BUILD TARGETS & CONFIGURATION

| Target | Type | Entitlements |
|--------|------|-------------|
| Anywhere | iOS app | ATS arbitrary loads |
| Anywhere Network Extension | packet-tunnel-provider | NetworkExtension + App Groups |
| Anywhere TV | tvOS app | NetworkExtension + App Groups |

**Bridging Headers**:
- Main app: imports `libyaml/yaml.h`
- Network Extension: imports `lwip/lwip_bridge.h`
- TV app: imports `libyaml/yaml.h`

**Info.plist (Extension)**:
- `NSExtensionPrincipalClass`: `PacketTunnelProvider`
- `NSExtensionPointIdentifier`: `com.apple.networkextension.packet-tunnel`

---

## 3. DIRECTORY MAP

```
/Volumes/Work/Anywhere/
├── Anywhere/                          # iOS app target
│   ├── AnywhereApp.swift              # @main entry point
│   ├── ContentView.swift              # TabView root (Home, Proxies, Chains, Settings)
│   ├── Views/
│   │   ├── HomeView.swift             # VPN toggle, traffic stats, config card
│   │   ├── OnboardingView.swift       # First-run: country bypass + ad block
│   │   ├── DemoViews.swift            # Preview/demo views
│   │   ├── ProxyList/
│   │   │   ├── ProxyListView.swift    # Proxy list with subscriptions
│   │   │   ├── ProxyEditorView.swift  # Create/edit proxy config form
│   │   │   └── AddProxyView.swift     # QR/Link/Manual import
│   │   ├── ChainList/
│   │   │   ├── ChainListView.swift    # Chain list with validation
│   │   │   └── ChainEditorView.swift  # Reorderable chain editor
│   │   ├── Settings/
│   │   │   ├── SettingsView.swift         # Main settings
│   │   │   ├── RuleSetListView.swift      # Routing rule assignments
│   │   │   ├── AdvancedSettingsView.swift # Links to IPv6/DNS
│   │   │   ├── IPv6SettingsView.swift
│   │   │   ├── EncryptedDNSSettingsView.swift
│   │   │   ├── TrustedCertificatesView.swift
│   │   │   └── AcknowledgementsView.swift
│   │   └── Components/
│   │       ├── 3DPicker.swift         # Custom 3D picker modifier
│   │       ├── AppIconView.swift
│   │       ├── DIQRScanner.swift      # QR code scanner
│   │       ├── DynamicSheet.swift
│   │       └── TextWithColorfulIcon.swift
│   ├── Resources/                     # Bundled JSON rule sets
│   │   ├── Direct.json, CN.json, RU.json, IR.json, ...
│   │   ├── Telegram.json, Netflix.json, YouTube.json, ...
│   │   ├── ChatGPT.json, Claude.json, Gemini.json
│   │   └── ADBlock.json
│   └── Assets.xcassets/
│
├── Anywhere Network Extension/        # Network Extension target
│   ├── PacketTunnelProvider.swift      # NEPacketTunnelProvider subclass
│   ├── LWIPStack.swift                # lwIP coordinator (serial queue)
│   ├── LWIPTCPConnection.swift        # TCP connection handler
│   ├── LWIPUDPFlow.swift              # UDP flow handler
│   ├── DNSPacket.swift                # DNS query/response utilities
│   ├── FakeIPPool.swift               # Fake-IP allocator (LRU, 198.18.0.0/15)
│   ├── DomainRouter.swift             # Domain routing (trie + Aho-Corasick)
│   ├── GeoIP/
│   │   ├── GeoIPDatabase.swift        # Binary GeoIP lookup
│   │   └── geoip.dat                  # Binary database
│   └── lwip/                          # Vendored lwIP stack
│       ├── lwip_bridge.h              # C bridge interface
│       ├── lwip_bridge.c              # Bridge implementation
│       ├── port/                      # Platform adaptation
│       └── src/                       # lwIP source (~24K LOC C)
│
├── Anywhere TV/                       # tvOS target
│
├── General/                           # Shared utilities (all targets)
│   ├── NWTransport.swift              # Network.framework TCP transport
│   ├── ProxyDNSCache.swift            # DNS cache (bypasses VPN tunnel)
│   ├── ActivityTimer.swift            # Inactivity timeout detector
│   ├── DomainRule.swift               # Rule type enum + struct
│   ├── Data+init.swift                # Hex/Base64URL extensions
│   ├── UnfairLock.swift               # os_unfair_lock + pthread_rwlock wrappers
│   └── DeviceCensorship.swift         # China device detection
│
├── Shared/                            # Shared code (app + extension)
│   ├── AWCore.swift                   # App Group suite, ProxyMode enum, migration
│   ├── Blake3/
│   │   └── Blake3Hasher.swift         # Swift wrapper over SPM BLAKE3 package
│   ├── libyaml/                       # Vendored YAML parser (~13K LOC C)
│   ├── Configuration/
│   │   ├── ConfigurationStore.swift   # ProxyConfiguration CRUD → configurations.json
│   │   ├── ChainStore.swift           # ProxyChain CRUD → chains.json
│   │   ├── SubscriptionStore.swift    # Subscription CRUD → subscriptions.json
│   │   ├── RuleSetStore.swift         # Rule assignments → UserDefaults routingData
│   │   ├── CertificateStore.swift     # Trusted cert SHA256s → UserDefaults
│   │   ├── LatencyTester.swift        # Proxy latency via captive.apple.com:80
│   │   ├── SubscriptionFetcher.swift  # Fetch & parse subscriptions
│   │   ├── ClashProxyParser.swift     # Clash YAML → ProxyConfiguration
│   │   └── ConfigurationProvider.swift # Protocol: loadConfigurations()
│   ├── Models/
│   │   ├── ProxyChain.swift           # Named ordered proxy chain
│   │   ├── Subscription.swift         # Subscription profile
│   │   └── PickerItem.swift           # ID+Name for picker UI
│   ├── ViewModels/
│   │   └── VPNViewModel.swift         # @MainActor singleton, VPN state management
│   └── Localizable.xcstrings
│
├── Protocols/                         # All proxy protocol implementations
│   ├── Core/
│   │   ├── ProxyClient.swift          # Central connection factory (~1500 LOC)
│   │   ├── ProxyConnection.swift      # Base class + UDPProxyConnection
│   │   ├── ProxyConfiguration.swift   # Config struct (Outbound/Transport/Security enums)
│   │   ├── ProxyConfiguration+DictParsing.swift
│   │   ├── ProxyConfiguration+URLParsing.swift
│   │   ├── ProxyConfiguration+URLExport.swift
│   │   ├── TunneledTransport.swift    # ProxyConnection→RawTransport adapter (chaining)
│   │   └── UDPFraming.swift           # 2-byte length prefix framing
│   ├── VLESS/
│   │   ├── VLESSProtocol.swift        # Request/response header construction
│   │   └── VLESSVision.swift          # XTLS Vision padding + direct-copy
│   ├── Shadowsocks/
│   │   ├── ShadowsocksProtocol.swift  # Address header format
│   │   ├── ShadowsocksConnection.swift # Stream connection wrapper
│   │   ├── ShadowsocksAEAD.swift      # AEAD encryption (legacy ciphers)
│   │   ├── Shadowsocks2022.swift      # SS2022 with BLAKE3 identity
│   │   └── ShadowsocksUDPRelay.swift  # Per-packet UDP encryption
│   ├── SOCKS5/
│   │   └── SOCKS5Connection.swift     # Full SOCKS5 + UDP ASSOCIATE
│   ├── TLS/
│   │   ├── TLSClient.swift            # TLS 1.2/1.3 handshake (~2020 LOC)
│   │   ├── TLSConfiguration.swift     # SNI, ALPN, fingerprint, version
│   │   ├── TLSProxyConnection.swift   # ProxyConnection wrapper
│   │   └── TLS12KeyDerivation.swift   # PRF-SHA256/384
│   ├── Reality/
│   │   ├── RealityClient.swift        # X25519 ECDH + session auth (~843 LOC)
│   │   ├── RealityConfiguration.swift # Public key, short ID, fingerprint
│   │   ├── RealityProxyConnection.swift
│   │   ├── TLS13KeyDerivation.swift   # HKDF-SHA256/384
│   │   ├── TLSClientHelloBuilder.swift # Browser fingerprint spoofing
│   │   ├── TLSRecordConnection.swift  # TLS record encrypt/decrypt (~960 LOC)
│   │   └── TLSRecordCrypto.swift      # AES-GCM, ChaCha20, AES-CBC
│   ├── WebSocket/
│   │   ├── WebSocketConfiguration.swift
│   │   ├── WebSocketConnection.swift  # RFC 6455 with masking (~503 LOC)
│   │   └── WebSocketProxyConnection.swift
│   ├── HTTPUpgrade/
│   │   ├── HTTPUpgradeConfiguration.swift
│   │   ├── HTTPUpgradeConnection.swift # HTTP 101 upgrade tunnel
│   │   └── HTTPUpgradeProxyConnection.swift
│   ├── XHTTP/
│   │   ├── XHTTPConfiguration.swift   # Modes: stream-one, stream-up, packet-up
│   │   └── XHTTPConnection.swift      # HTTP/1.1 + HTTP/2 split HTTP (~1918 LOC)
│   ├── Mux/
│   │   ├── MuxClient.swift            # Session multiplexer (~335 LOC)
│   │   ├── MuxManager.swift           # Client pool manager
│   │   ├── MuxSession.swift           # Per-session state
│   │   ├── MuxFrame.swift             # Frame format (port-first)
│   │   └── XUDP.swift                 # 8-byte GlobalID for Full Cone NAT
│   ├── Naive/
│   │   ├── NaiveProxyConnection.swift # Padding negotiation
│   │   ├── HTTP11/
│   │   │   └── HTTP11Connection.swift # HTTP/1.1 CONNECT
│   │   └── HTTP2/
│   │       ├── HTTP2Session.swift
│   │       ├── HTTP2Connection.swift
│   │       ├── HTTP2Framer.swift
│   │       ├── HTTP2FlowControl.swift
│   │       ├── HPACKEncoder.swift
│   │       └── NaivePaddingNegotiator.swift / NaivePaddingFramer.swift
│   └── Direct/
│       ├── DirectProxyConnection.swift
│       ├── DirectTCPRelay.swift
│       └── DirectUDPRelay.swift
│
├── build_geoip.py
├── README.md
└── LICENSE (GPLv3)
```

---

## 4. APP ↔ EXTENSION IPC

### Shared Data (App Group UserDefaults)

| Key | Type | Writer | Reader | Purpose |
|-----|------|--------|--------|---------|
| `lastConfigurationData` | Data (JSON) | App | Extension | Fallback config on on-demand restart |
| `proxyServerAddresses` | Data (JSON) | App | Extension | Proxy IPs to bypass at lwIP level |
| `routingData` | Data (JSON) | App | Extension | Domain rules + config UUID mappings |
| `bypassCountryDomainRules` | Data (JSON) | App | Extension | Country-specific bypass domains |
| `selectedConfigurationId` | String (UUID) | App | App | Currently selected proxy |
| `selectedChainId` | String (UUID) | App | App | Currently selected chain |
| `proxyMode` | String | App | Extension | "rule" or "global" |
| `bypassCountryCode` | String | App | Extension | 2-letter country code or "" |
| `alwaysOnEnabled` | Bool | App | App | Always-on VPN flag |
| `allowInsecure` | Bool | App | Extension | Skip TLS validation |
| `ipv6DNSEnabled` | Bool | App | Extension | Add AAAA fake IPs |
| `encryptedDNSEnabled` | Bool | App | Extension | DoH/DoT toggle |
| `encryptedDNSProtocol` | String | App | Extension | "doh" or "dot" |
| `encryptedDNSServer` | String | App | Extension | Custom DNS server URL |
| `trustedCertificateSHA256s` | [String] | App | Extension | Trusted cert fingerprints |
| `ruleSetAssignments` | [String:String] | App | App | Rule→config mappings for UI |
| `onboardingCompleted` | Bool | App | App | First-run flag |

### File Storage (App Group Container)

| File | Writer | Reader | Purpose |
|------|--------|--------|---------|
| `configurations.json` | App | Extension | All ProxyConfiguration objects |
| `chains.json` | App | App | All ProxyChain objects |
| `subscriptions.json` | App | App | All Subscription profiles |

### NETunnelProviderSession IPC Messages

**App → Extension:**
1. **Start tunnel**: `options["config"]` = configuration dictionary
2. **Stats request**: `{"type": "stats"}` → Response: `{"bytesIn": Int64, "bytesOut": Int64}`
3. **Proxy addresses**: `{"type": "proxyAddresses", "addresses": [String]}`
4. **Config switch**: Full configuration dictionary (triggers `switchConfiguration()`)

### Darwin Notifications

| Notification | Sender | Receiver | Action |
|-------------|--------|----------|--------|
| `com.argsment.Anywhere.settingsChanged` | App | Extension | Full LWIPStack restart (reloads IPv6, DNS, bypass, proxy mode) |
| `com.argsment.Anywhere.routingChanged` | App | Extension | Reloads routing rules only (DomainRouter) |

---

## 5. NETWORK EXTENSION ARCHITECTURE

### PacketTunnelProvider.swift
- Subclass of `NEPacketTunnelProvider`
- **Tunnel settings**: Virtual IP 10.8.0.2, gateway 10.8.0.1, MTU 1400
- **DNS**: 1.1.1.1, 1.0.0.1 (+ IPv6 variants if enabled)
- **Bypass routes**: Private ranges (10/8, 172.16/12, 192.168/16), link-local, multicast, CDN IPs
- **Encrypted DNS**: Resolves DoH/DoT server hostnames via `getaddrinfo` before tunnel setup
- **Config loading**: From `options["config"]`, fallback to `lastConfigurationData` in UserDefaults
- **handleAppMessage**: Dispatches stats/proxyAddresses/config-switch messages

### LWIPStack.swift — The Core Coordinator
- **Serial queue**: `lwipQueue` — ALL lwIP operations serialized here
- **Packet I/O**: `startReadingPackets()` → `lwip_bridge_input()` → callbacks → `flushOutputPackets()`
- **Output batching**: Collects output packets, flushes in single `packetFlow.writePackets()` call
- **Timer**: 250ms periodic `lwip_bridge_check_timeouts()`
- **UDP cleanup**: 1s timer, 60s idle timeout, max 200 concurrent flows

**Key state**:
- `fakeIPPool: FakeIPPool` — Domain→synthetic IP mapping (198.18.0.0/15, fc00::/18)
- `domainRouter: DomainRouter` — Compiled routing rules
- `geoIPDatabase: GeoIPDatabase` — Country lookup (persists across config switches)
- `muxManager: MuxManager` — UDP multiplexing manager
- `udpFlows: [UDPFlowKey: LWIPUDPFlow]` — Active UDP flows

**DNS Interception** (port 53 UDP):
1. Parse query via `DNSPacket.parseQuery()`
2. Block DDR (`_dns.resolver.arpa`) when encrypted DNS disabled
3. Block SVCB/HTTPS (qtype=65) queries
4. Allocate fake IP via `fakeIPPool.allocate(domain:)`
5. Generate response with TTL=1 via `DNSPacket.generateResponse()`
6. Send directly via `lwip_bridge_udp_sendto()` (no flow created)

**Fake-IP Resolution** (`resolveFakeIP`):
1. Check if IP is fake via `FakeIPPool.isFakeIP()`
2. If not fake → `.passthrough` (direct routing for real IPs)
3. Lookup domain from pool → if stale entry → `.unreachable` (sends ICMP)
4. Apply routing: `domainRouter.matchDomain()` → direct/reject/proxy(UUID)
5. In global mode: always proxy (skip domain matching)
6. Check `shouldBypass(host:)` for GeoIP country bypass and proxy server bypass

### LWIPTCPConnection.swift
- One instance per TCP connection from local app
- **Upload coalescing**: Batches segments into `uploadCoalesceBuffer` (max 64KB) before encryption
- **Overflow buffering**: When lwIP send buffer full, stores in `overflowBuffer` (max 512KB)
- **Backpressure**: Per-segment for direct, coalesced for proxy
- **Timeouts** (matching Xray-core defaults):
  - `connectionIdleTimeout` = 300s
  - `downlinkOnlyTimeout` = 1s
  - `uplinkOnlyTimeout` = 1s
  - `handshakeTimeout` = 60s

**Connection lifecycle**:
1. `tcp_accept_fn` → create LWIPTCPConnection
2. Resolve fake IP → determine bypass/proxy/reject
3. `connectDirect()` or `connectProxy()` (via ProxyClient)
4. Bidirectional relay: `handleReceivedData` ↔ `requestNextReceive`
5. Graceful close or abort on timeout/error

### LWIPUDPFlow.swift
- One instance per UDP 5-tuple (srcHost:srcPort → dstHost:dstPort)
- **Connection strategies** (prioritized):
  1. **Mux** (VLESS only, no chain) → through MuxManager with XUDP GlobalID
  2. **Shadowsocks Direct UDP** → per-packet encryption via ShadowsocksUDPRelay
  3. **ProxyClient** (general) → chain-aware, length-prefixed for VLESS
  4. **Direct** → via DirectUDPRelay
- **Buffer limit**: 16KB (`maxUDPBufferSize`, matches Xray-core DiscardOverflow)
- **Framing**: Deferred to send time — VLESS gets 2-byte length prefix, SS sends raw

### DNSPacket.swift
- Static utility enum
- `parseQuery(_:)` → extracts domain + qtype from DNS wire format
- `generateResponse(query:fakeIP:qtype:)` → builds minimal A/AAAA response (TTL=1)
- Handles label decompression pointers

### FakeIPPool.swift
- **IPv4 range**: 198.18.0.0/15 (base 0xC6120000, offsets 1–131071)
- **IPv6 range**: fc00::/18 (fc00::1 to fc00::1:ffff)
- **LRU eviction**: Doubly-linked list, O(1) insert/touch/evict
- `domainToOffset: [String: Int]`, `offsetToEntry: [Int: Entry]`
- `isFakeIP()` — fast prefix check without pool lookup

### DomainRouter.swift
- **Exact match**: O(1) hash lookup
- **Suffix match**: Reverse-label trie (O(k) where k = label count)
- **Keyword match**: Aho-Corasick automaton (O(m) where m = domain length)
- **IP CIDR**: Compiled network/mask pairs (O(n) linear scan)
- **Rule actions**: `.direct`, `.reject`, `.proxy(UUID)`
- User rules take precedence over country bypass rules
- `resolveConfiguration(action:)` maps UUID to ProxyConfiguration

### GeoIPDatabase.swift
- Binary format: "GEO1" magic + entries (startIP 4B, endIP 4B, country 2B)
- O(log n) binary search for IPv4 lookup
- `packCountryCode("CN")` → 0x434E

---

## 6. PACKET FLOW DIAGRAMS

### TCP Connection (App → Proxy Server)
```
Local App
  → IP packet → TUN interface
  → packetFlow.readPackets()
  → lwipQueue: lwip_bridge_input(packet)
  → lwIP TCP reassembly
  → tcp_accept_fn callback (new connection)
     → LWIPTCPConnection created
     → resolveFakeIP(dstIP) → domain + routing decision
     → connectProxy() / connectDirect()
  → tcp_recv_fn callback (data from app)
     → handleReceivedData()
     → uploadCoalesceBuffer accumulate
     → flushUploadBuffer()
     → proxyConnection.send() → encrypted to server
  ← proxyConnection.receive() → data from server
     → writeToLWIP() → feedLWIP()
     → lwip_bridge_tcp_write() → lwIP sends
     → lwip_bridge_tcp_output()
     → output_fn callback → flushOutputPackets()
     → packetFlow.writePackets() → TUN → Local App
```

### UDP Flow (App → Proxy Server)
```
Local App
  → UDP packet → TUN interface
  → lwip_bridge_input(packet)
  → udp_recv_fn callback
  → [Port 53?] → handleDNSQuery() → fake-IP response → lwip_bridge_udp_sendto()
  → [Not port 53] → resolveFakeIP(dstIP)
     → LWIPUDPFlow created (or existing flow)
     → handleReceivedData()
     → [Mux path] → muxSession.write() → multiplexed
     → [Proxy path] → proxyConnection.send() → 2-byte length prefix + payload
     → [SS UDP path] → ssUDPRelay.send() → per-packet encrypted
     → [Direct path] → directRelay.send()
  ← Response data
     → handleProxyData()
     → lwip_bridge_udp_sendto() (swap src/dst IPs)
     → output_fn → packetFlow.writePackets()
     → TUN → Local App
```

### DNS Interception (Never Creates Flow)
```
App DNS query → TUN → lwip_bridge_input()
  → udp_recv_fn (port 53)
  → handleDNSQuery()
  → DNSPacket.parseQuery() → domain + qtype
  → [DDR/SVCB?] → sendNODATA()
  → fakeIPPool.allocate(domain) → offset
  → DNSPacket.generateResponse(fakeIP: offset, qtype)
  → lwip_bridge_udp_sendto() → output_fn → TUN → App
  (No LWIPUDPFlow created, no proxy connection)
```

---

## 7. PROTOCOL STACK

ProxyClient composes layers bottom-up:

```
┌─────────────────────────────────────────┐
│  Application Protocol (VLESS/SS/SOCKS5) │  ← ProxyConnection subclass
├─────────────────────────────────────────┤
│  Transport (WS/HTTPUpgrade/XHTTP/TCP)   │  ← Optional transport wrapper
├─────────────────────────────────────────┤
│  Security (TLS/Reality/None)             │  ← TLSRecordConnection
├─────────────────────────────────────────┤
│  Raw Transport (NWTransport/Tunnel)      │  ← RawTransport protocol
├─────────────────────────────────────────┤
│  [Chain Link N-1 (ProxyConnection)]      │  ← TunneledTransport adapter
│  [Chain Link N-2 ...]                    │
│  [Chain Link 0 (NWTransport)]            │
└─────────────────────────────────────────┘
```

**Composition rules** (enforced in ProxyClient):
- Shadowsocks: No Mux, no Reality, no Vision
- Naive (HTTP/1.1, HTTP/2, HTTP/3): TCP only
- SOCKS5: No Mux
- Vision flow: TLS 1.3 only, TCP/Mux only (no WS/HTTPUpgrade/XHTTP)
- WS/HTTPUpgrade/XHTTP: Block Vision flow

---

## 8. PROXYCLIENT — THE CENTRAL FACTORY

**File**: `Protocols/Core/ProxyClient.swift` (~1500 LOC)

### Public API
```swift
func connect(to host: String, port: UInt16, initialData: Data?) async throws -> ProxyConnection
func connectUDP(to host: String, port: UInt16) async throws -> ProxyConnection
func connectMux() async throws -> ProxyConnection  // target: v1.mux.cool:666
```

### Connection Build Sequence

1. **Chain resolution** (if `configuration.chain` exists):
   - `buildChainTunnel()` recursively connects through chain
   - Each link targets the next link's server address
   - Final tunnel wrapped as `TunneledTransport` for this proxy's server

2. **Transport + Security selection** (`connectWithCommand`):
   ```
   if WebSocket:
     if TLS → TLSRecordConnection → WebSocketConnection
     if Reality → RealityClient → WebSocketConnection
     else → NWTransport → WebSocketConnection

   if HTTPUpgrade:
     if TLS → TLSRecordConnection → HTTPUpgradeConnection
     else → NWTransport → HTTPUpgradeConnection

   if XHTTP:
     if Reality → RealityClient → XHTTPConnection (HTTP/2)
     if TLS → TLSClient → XHTTPConnection (HTTP/1.1 or HTTP/2 by ALPN)
     else → NWTransport → XHTTPConnection (HTTP/1.1)

   if TCP (direct):
     if Reality → RealityClient → connection
     if TLS → TLSClient → connection
     else → NWTransport → connection
   ```

3. **Protocol handshake** (`sendProtocolHandshake`):
   - **Shadowsocks**: Build request (salt + address header + initial data), no response header wait
   - **VLESS**: Build VLESS request header, optionally wrap with VLESSVisionConnection
   - **SOCKS5**: Full SOCKS5 handshake (auth + connect command)
   - **Naive**: HTTP CONNECT with padding negotiation
   - **Direct**: No handshake

4. **Vision validation** (if flow = "xtls-rprx-vision"):
   - Must be TLS 1.3 (`outerTLSVersion == .tls13`)
   - Must be TCP or Mux (not UDP, not WS/HTTPUpgrade/XHTTP)
   - Wraps with `VLESSVisionConnection` after TLS setup
   - UDP/443 dropped unless flow suffix is "-udp443"

### Key Properties
- `connection: NWTransport?` — Direct TCP
- `realityClient: RealityClient?`, `tlsClient: TLSClient?` — Security
- `webSocketConnection`, `httpUpgradeConnection`, `xhttpConnection` — Transports
- `tunnel: ProxyConnection?` — Chained tunnel
- `chainClients: [ProxyClient]` — Retained for lifecycle

---

## 9. VLESS & VISION FLOW

### VLESS Wire Format (VLESSProtocol.swift)

**Request header**:
```
[Version: 1B = 0x00]
[UUID: 16B]
[Addons length: 1B]
[Addons: protobuf, field 1 = flow string]
[Command: 1B] (0x01=TCP, 0x02=UDP, 0x03=Mux)
[Port: 2B big-endian]
[Address type: 1B] (0x01=IPv4, 0x02=Domain, 0x03=IPv6)
[Address: variable]
```
- Mux (command 0x03): No address/port field

**Response header** (optional):
```
[Version: 1B = 0x00] (if != 0x00, no header — raw data)
[Addons length: 1B]
[Addons: protobuf]
```

### Vision (VLESSVision.swift, ~597 LOC)

**Purpose**: Direct-copy of inner TLS records through outer TLS, reducing double-encryption overhead.

**Padding frame format**:
```
[UUID: 16B, first frame only]
[Command: 1B] (0x00=Continue, 0x01=End, 0x02=Direct)
[Content length: 2B big-endian]
[Padding length: 2B big-endian]
[Content: variable]
[Padding: random bytes]
```

**Testseed** (4 × UInt32): `[contentThreshold, longPaddingMax, longPaddingBase, shortPaddingMax]`
- Default: `[900, 500, 900, 256]`
- If content < threshold AND longPadding: pad 0..(longPaddingMax + longPaddingBase - contentLen)
- Else: pad 0..shortPaddingMax
- Max padding capped at 8192 - 21 - contentLen

**TLS Detection** (first 8 packets):
- ClientHello: `0x16 0x03 ... 0x01`
- ServerHello: `0x16 0x03 0x03 ... 0x02`
- ApplicationData: `0x17 0x03 0x03`
- TLS 1.3: checks `supported_versions` extension
- Cipher suites triggering direct copy: 0x1301, 0x1302, 0x1303, 0x1304

**Data reshaping** (before Vision padding):
- Threshold: 8171 bytes (8192 - 21)
- Splits at last TLS record boundary (`0x17 0x03 0x03`)
- Falls back to midpoint split, recursion until all chunks < threshold

**State machine** (`VisionTrafficState`):
- `numberOfPacketsToFilter`: Counts down from 8
- `enableXtls`, `isTLS12orAbove`, `isTLS`: Detection flags
- `cipher`: Negotiated cipher suite
- Writer/reader padding flags track when to start/stop padding

---

## 10. SHADOWSOCKS PROTOCOL

### Address Header (ShadowsocksProtocol.swift)
```
[ATYP: 1B] (0x01=IPv4, 0x03=Domain, 0x04=IPv6)
[Address: 4B/1+n/16B]
[Port: 2B big-endian]
```

### AEAD Stream (ShadowsocksAEAD.swift, ~527 LOC)

**Ciphers**:
- Legacy: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- SS2022: BLAKE3-AES-128-GCM, BLAKE3-AES-256-GCM, BLAKE3-ChaCha20-Poly1305

**Key derivation**:
- Legacy: `EVP_BytesToKey` (MD5 iterative)
- SS2022: Base64-decoded PSK (multi-user: colon-separated)
- Subkey: HKDF-SHA1(salt, key, info="ss-subkey")

**Chunk format**:
```
[Encrypted(length: 2B big-endian)] [16B tag]
[Encrypted(payload: up to 0x3FFF)] [16B tag]
```

**Nonce**: Starts at 0xFF...FF (all ones), increments little-endian before each use. First actual nonce = 0x00...00.

**Salt/IV**: Random per connection, size = key size, prepended to stream.

### SS2022 (Shadowsocks2022.swift, ~1017 LOC)
- BLAKE3 for identity authentication
- Identity header: 16 bytes = BLAKE3(pskHash || salt)
- Session key negotiation via BLAKE3-derived keys

### UDP Relay (ShadowsocksUDPRelay.swift)
- Per-packet encryption (no chunking)
- Each packet: salt + Encrypt(address + payload)

---

## 11. SOCKS5 PROTOCOL

**File**: `Protocols/SOCKS5/SOCKS5Connection.swift` (~618 LOC)

**Handshake**:
1. Client: `[0x05, nMethods, methods...]`
2. Server: `[0x05, selectedMethod]`
3. If method=0x02: `[0x01, uLen, username, pLen, password]` → `[0x01, 0x00]`
4. Client: `[0x05, cmd, 0x00, atype, addr, port]` (cmd: 0x01=CONNECT, 0x03=UDP)
5. Server: `[0x05, status, 0x00, atype, addr, port]`

**UDP ASSOCIATE**: TCP command with 0.0.0.0:0 → server returns relay endpoint

**SOCKS5Buffer**: Reads 65536B chunks, serves exact byte counts on demand.
**SOCKS5Transport**: Wrapper delivering buffered excess on first receive.

---

## 12. TLS LAYER

### TLSConfiguration.swift
- Fields: `sni`, `alpn: [String]`, `fingerprint: TLSFingerprint`, `minVersion`, `maxVersion`
- Fingerprints: chrome133, firefox148, safari26, ios14, edge85, android11, qq11, 360browser7

### TLSClient.swift (~2020 LOC)

**TLS 1.3 flow**:
1. ClientHello (browser fingerprinted) → 2. ServerHello (extract key_share, cipher)
3. HKDF handshake keys → 4. Encrypted Certificate/CertificateVerify/Finished
5. Verify transcript → 6. Client Finished → 7. Certificate validation (optional)

**TLS 1.2 flow**:
1. ClientHello → 2. ServerHello → 3. Certificate (plain)
4. ServerKeyExchange (ECDHE P-256/P-384) → 5. ClientKeyExchange + CCS + Finished
6. Server CCS + Finished (encrypted)

**Cipher suites**:
- TLS 1.3: AES-128-GCM (0x1301), AES-256-GCM (0x1302), ChaCha20 (0x1303)
- TLS 1.2: ECDHE-RSA-AES-128-GCM, ECDHE-RSA-ChaCha20, AES-CBC variants

**Certificate validation**: Apple Security.framework + user-trusted SHA256 list + allowInsecure bypass

### TLSRecordConnection.swift (~960 LOC)
- TLS 1.3: Content type inside encrypted payload, nonce = IV XOR padded sequence
- TLS 1.2 GCM: Explicit 8B nonce prefix, implicit 4B IV + explicit 8B = 12B nonce
- TLS 1.2 ChaCha20: No explicit nonce, same as 1.3 style (IV XOR seq)
- TLS 1.2 CBC: HMAC-then-encrypt, explicit IV in ciphertext prefix
- Max record: 16384B plaintext
- Buffer: Batches reads up to 256KB
- Direct mode: bypass encryption for Vision direct-copy

---

## 13. REALITY LAYER

### RealityConfiguration.swift
- Fields: `serverName` (SNI), `publicKey` (32B X25519), `shortId` (0-8B hex), `fingerprint`
- Public key: Base64URL encoded, validated 32 bytes

### RealityClient.swift (~843 LOC)

**Authentication**:
```
SessionId (32 bytes):
  [0-3]: Version (26.1.18) + flags
  [4-7]: Timestamp (big-endian UInt32)
  [8-15]: ShortId (zero-padded to 8 bytes)
  [16-31]: Random

Auth key = ECDH(client_ephemeral, server_public_key)
Encrypted SessionId = AES-GCM(auth_key, nonce=zero_padded_timestamp, sessionId)
```

**Verification**: Server auth key from client ephemeral + server public key; validates ServerHello decryption

**Always TLS 1.3**. No PKI/certificate validation (authentication is via X25519 ECDH).

---

## 14. TRANSPORT LAYERS

### WebSocket (WebSocketConnection.swift, ~503 LOC)
- RFC 6455: Frame masking, opcode handling, fragmentation support
- Upgrade: `GET path HTTP/1.1`, `Upgrade: websocket`, `Connection: Upgrade`
- User-Agent: Chrome 144 base, increments every 35 days
- Early data: Base64URL-encoded in configurable header
- Heartbeat: Optional periodic ping
- Buffer limit: 1MB max frame
- Triple transport: plain WS (NWTransport), WSS (TLSRecordConnection), chained (ProxyConnection)

### HTTP Upgrade (HTTPUpgradeConnection.swift, ~283 LOC)
- HTTP/1.1 GET with `Upgrade: websocket` header (WebSocket-compatible)
- Response: HTTP 101 → raw bidirectional tunnel
- Simpler than full WebSocket (no framing after upgrade)

### XHTTP (XHTTPConnection.swift, ~1918 LOC)

**Modes**:
- `stream-one`: Single HTTP request, server streams responses (download)
- `stream-up`: Multiple HTTP requests, single server response (upload)
- `packet-up`: Many small stateless HTTP requests

**HTTP version selection**:
- Reality → HTTP/2 always
- TLS + ALPN h2 → HTTP/2
- TLS + ALPN http/1.1 → HTTP/1.1
- Plain → HTTP/1.1

**Session/sequence tracking**: Placed in path/query/header/cookie/body per configuration

**Upload connection factory**: Creates new connections for packet-up/stream-up modes, supports chain tunnels.

---

## 15. MULTIPLEXING (MUX/XUDP)

### MuxFrame.swift (~314 LOC)
**Frame metadata**:
```
[Session ID: 2B big-endian]
[Status: 1B] (0x01=new, 0x02=keep, 0x03=end, 0x04=keepAlive)
[Option: 1B] (0x01=data, 0x02=error)
For "new" frames:
  [Network: 1B] (0x01=TCP, 0x02=UDP)
  [Port: 2B big-endian]  ← NOTE: port-first, unlike SOCKS5
  [Address type: 1B + address bytes]
  [GlobalID: 8B, optional, UDP+XUDP only]
```

### MuxClient.swift (~335 LOC)
- Session IDs: 1–65535 (unique per client), 0 reserved for XUDP
- Idle timer: 16 seconds
- Write serialization: Queue enforces frame order
- Lazy connection: First session triggers mux connect
- Stateful frame parser for incomplete reads

### MuxManager.swift (~52 LOC)
- Pool of MuxClient instances
- Client reuse/creation

### XUDP.swift (~38 LOC)
- 8-byte GlobalID for Full Cone NAT
- Generated per UDP flow when XUDP enabled

---

## 16. NAIVE PROXY (HTTP CONNECT)

### NaiveProxyConnection.swift (~300 LOC)
- HTTP CONNECT tunnel with padding negotiation
- Padding variant-1: First 8 frames padded
- **Send padding**: Small < 100B biased [255-len, 255]; 400-1024B split 200-300B chunks; else uniform [0, 255]
- **Receive padding**: Uniform random [0, 255]; pure-padding frames re-read

### HTTP/2 Stack
- `HTTP2Session.swift` — Connection pooling
- `HTTP2Connection.swift` — H2 connection
- `HTTP2Framer.swift` — Frame encoding/decoding
- `HTTP2FlowControl.swift` — Window management
- `HPACKEncoder.swift` — Header compression
- Padding: `NaivePaddingNegotiator.swift` + `NaivePaddingFramer.swift`

---

## 17. DIRECT CONNECTION

### DirectProxyConnection.swift (~100 LOC)
- Wraps `RawTransport` (NWTransport or TunneledTransport)
- No protocol layer
- Still processes VLESS response header if present

### DirectTCPRelay.swift
- Direct TCP relay for bypassed connections
- Uses NWTransport → target host

### DirectUDPRelay.swift
- Direct UDP relay for bypassed connections
- NWConnection with UDP protocol

---

## 18. SHARED INFRASTRUCTURE

### RawTransport Protocol (NWTransport.swift)
```swift
protocol RawTransport {
    var isTransportReady: Bool { get }
    func send(data: Data, completion: @escaping (Error?) -> Void)
    func send(data: Data)
    func receive(maximumLength: Int, completion: @escaping (Data?, Bool, Error?) -> Void)
    func forceCancel()
}
```

### NWTransport (NWTransport.swift)
- Network.framework TCP connection
- TCP_NODELAY = true, Fast Open, keepalive (30s idle, 10s interval, 3 count)
- Connect timeout: 16s (matches Xray-core)
- DNS via `ProxyDNSCache.shared.resolveAll()` — bypasses VPN tunnel
- Tries each resolved IP in order on failure
- `betterPathAvailableHandler` for network transitions

### ProxyDNSCache (ProxyDNSCache.swift)
- Singleton, thread-safe (ReadWriteLock)
- `resolveAll(host:)` → [String] IPs
- Active proxy domain: returns stale IPs on TTL expiry, refreshes in background
- Non-active: synchronous refresh
- TTL: 120 seconds
- Uses POSIX `getaddrinfo()` (AF_UNSPEC) on physical interface

### ActivityTimer (ActivityTimer.swift)
- `update()` sets flag, timer fires every N seconds
- If flag clear after timeout → `onTimeout()` callback
- Used for `connectionIdleTimeout`, `downlinkOnlyTimeout`, `uplinkOnlyTimeout`

### UnfairLock / ReadWriteLock (UnfairLock.swift)
- `UnfairLock`: `os_unfair_lock` wrapper, `withLock {}` RAII
- `ReadWriteLock`: `pthread_rwlock_t`, `withReadLock {}` / `withWriteLock {}` RAII

### Blake3Hasher (Blake3Hasher.swift)
- Thin wrapper over SPM `BLAKE3Hasher` (`import BLAKE3`), keeping local API stable
- Modes: plain hash, keyed hash (32B key), derive-key (context string)
- `update(Data)`, `update([UInt8])`, `finalizeData(count:)`
- Static: `hash(_:)`, `deriveKey(context:input:)`

### TunneledTransport (TunneledTransport.swift)
- Adapts `ProxyConnection` to `RawTransport` for proxy chaining
- Calls `sendRaw/receiveRaw` directly (bypasses stats tracking)

### AWCore.swift
- `suiteName = "group.com.argsment.Anywhere"`
- `userDefaults: UserDefaults` for App Group
- `ProxyMode` enum: `.rule`, `.global`
- Migration helper from old documents directory

---

## 19. MAIN APP LAYER

### AnywhereApp.swift
- `@main` SwiftUI app, checks `onboardingCompleted` flag

### ContentView.swift
- TabView: Home, Proxies, Chains, Settings
- iOS 18+: `.sidebarAdaptable` tab style
- Orphaned ruleset alert detection

### VPNViewModel.swift (@MainActor singleton)

**Key published state**:
- `vpnStatus: NEVPNStatus`
- `selectedConfiguration: ProxyConfiguration?`
- `selectedChainId: UUID?`
- `chains: [ProxyChain]`
- `subscriptions: [Subscription]`
- `latencyResults: [UUID: LatencyResult]`
- `bytesIn/bytesOut: Int64`
- `proxyMode: String` ("rule" or "global")

**Key methods**:
- `connectVPN()` — Serialize config → start tunnel with options
- `disconnectVPN()` — Stop tunnel (handles on-demand)
- `sendConfigurationToTunnel()` — IPC config switch while connected
- `syncRoutingConfigurationToNE()` — Push routing rules to App Group
- `syncProxyServerAddresses()` — Push proxy IPs for bypass
- `pollStats()` — Request bytes in/out every 1s
- `serializeConfiguration(_:)` → `[String: Any]` for extension
- `resolveChain()` → Composite config with chain + exit proxy
- `testLatency()` / `testLatencies()` — Via LatencyTester

### Configuration Serialization
- VPNViewModel serializes ProxyConfiguration to dictionary
- Includes: outbound protocol credentials, transport config, security config, chain
- Extension parses via `ProxyConfiguration(from: dict)`

---

## 20. DATA MODELS & PERSISTENCE

### ProxyConfiguration (Codable, Hashable, Identifiable)
**Key fields**:
- `id: UUID`
- `name: String`, `server: String`, `port: Int`
- `outbound: Outbound` — enum: `.vless(uuid, encryption, flow)`, `.shadowsocks(password, method)`, `.socks5(username?, password?)`, `.http11/http2/http3(username, password)`
- `transportLayer: TransportLayer` — enum: `.tcp`, `.ws(WebSocketConfiguration)`, `.httpUpgrade(HTTPUpgradeConfiguration)`, `.xhttp(XHTTPConfiguration)`
- `securityLayer: SecurityLayer` — enum: `.none`, `.tls(TLSConfiguration)`, `.reality(RealityConfiguration)`
- `chain: [ProxyConfiguration]?` — Intermediate proxies
- `resolvedIP: String?`, `subscriptionId: UUID?`
- `muxEnabled: Bool`, `xudpEnabled: Bool`, `fullConeEnabled: Bool`
- `testseed: [UInt32]` — Vision padding config

### ProxyChain (Codable, Identifiable)
- `id: UUID`, `name: String`, `proxyIds: [UUID]`
- Last ID = exit node, preceding = intermediate

### Subscription (Codable, Identifiable)
- `id: UUID`, `name: String`, `url: String`
- `lastUpdate: Date?`, `upload/download/total: Int64`, `expire: Date?`
- `collapsed: Bool`, `isNameCustomized: Bool`

### Persistence
- `ConfigurationStore` → `configurations.json` (App Group container)
- `ChainStore` → `chains.json`
- `SubscriptionStore` → `subscriptions.json`
- `RuleSetStore` → UserDefaults `routingData` key
- `CertificateStore` → UserDefaults `trustedCertificateSHA256s` key
- All stores: `@MainActor` singletons, `@Published` arrays, atomic JSON writes

---

## 21. THREADING MODEL

| Component | Queue/Thread | Purpose |
|-----------|-------------|---------|
| LWIPStack | `lwipQueue` (serial) | ALL lwIP operations, packet I/O, callback dispatch |
| LWIPTCPConnection | `lwipQueue` | TCP connection state, buffer management |
| LWIPUDPFlow | `lwipQueue` | UDP flow state |
| NWTransport | `.global()` | Network.framework connection setup |
| ProxyClient | Caller's queue | Connection factory, completions on caller's queue |
| ProxyConnection | Any (uses UnfairLock) | Stats with atomic counters, response header buffer |
| TLSClient/RealityClient | Caller's queue | TLS handshake state |
| ProxyDNSCache | Any (ReadWriteLock) | Concurrent reads, exclusive writes |
| VPNViewModel | `@MainActor` (main) | All UI state mutations |
| ActivityTimer | Provided serial queue | Timer fire and callbacks |
| MuxClient | Internal serial queue | Frame serialization, session management |

**Key invariant**: All lwIP C API calls MUST happen on `lwipQueue`. The callbacks from lwIP also fire on this queue.

---

## 22. ERROR HANDLING PATTERNS

| Error Type | File | Cases |
|-----------|------|-------|
| `ProxyError` | ProxyConnection.swift | `.connectionFailed`, `.dropped`, `.protocolError` |
| `SocketError` | NWTransport.swift | `.resolutionFailed`, `.socketCreationFailed`, `.connectionFailed`, `.notConnected`, `.sendFailed`, `.receiveFailed` |
| `TLSError` | TLSClient.swift | `.handshakeFailed`, `.certificateValidationFailed`, `.connectionFailed`, `.unsupportedTLSVersion` |
| `RealityError` | RealityClient.swift | `.missingParameter`, `.invalidPublicKey`, `.handshakeFailed`, `.authenticationFailed`, `.connectionFailed`, `.decryptionFailed` |
| `WebSocketError` | WebSocketConnection.swift | `.upgradeFailed`, `.invalidFrame`, `.connectionClosed` |
| `HTTPUpgradeError` | HTTPUpgradeConnection.swift | `.upgradeFailed` |
| `ShadowsocksError` | ShadowsocksAEAD.swift | `.decryptionFailed`, `.invalidAddress` |
| `SOCKS5Error` | SOCKS5Connection.swift | Various handshake failures |

All implement `LocalizedError`. Connection failures propagate up through ProxyClient to LWIPTCPConnection/LWIPUDPFlow which log and close/abort.

**Special case**: `RealityError.decryptionFailed(rawData)` carries raw data — used as Vision direct-copy signal in RealityProxyConnection.

---

## 23. CONSTANTS & MAGIC VALUES

### Tunnel Settings
- Virtual IP: 10.8.0.2, Gateway: 10.8.0.1
- MTU: 1400
- DNS: 1.1.1.1, 1.0.0.1 (Cloudflare)

### Fake-IP Ranges
- IPv4: 198.18.0.0/15 (base 0xC6120000, offsets 1–131071)
- IPv6: fc00::/18 (fc00::1 to fc00::1:ffff)
- DNS TTL: 1 second

### Timeouts (Xray-core compatible)
- TCP connection idle: 300s
- Downlink-only: 1s
- Uplink-only: 1s
- Handshake: 60s
- NWTransport connect: 16s
- UDP idle: 60s
- Mux idle: 16s

### Buffer Sizes
- Upload coalesce: 64KB (UInt16.max)
- Overflow buffer max: 512KB
- UDP buffer: 16KB (Xray-core DiscardOverflow)
- WebSocket max frame: 1MB
- TLS max record: 16384B
- TLS read batch: 256KB
- lwIP TCP read: per-segment
- Max UDP flows: 200

### VLESS Vision
- Default testseed: [900, 500, 900, 256]
- Reshape threshold: 8171 (8192 - 21)
- Packets to filter: 8
- TLS 1.3 cipher suites: 0x1301–0x1304

### Shadowsocks AEAD
- Max chunk payload: 0x3FFF (16383)
- Initial nonce: 0xFF...FF (increments before use → first = 0x00...00)
- Tag size: 16 bytes

### DNS Cache
- Default TTL: 120s

### NWTransport TCP
- TCP_NODELAY: true
- Fast Open: enabled
- Keepalive: idle=30s, interval=10s, count=3

### SOCKS5
- Read buffer: 65536 bytes
- Version: 0x05

### WebSocket
- User-Agent base: Chrome 144 (Jan 13, 2026), increments every 35 days

### Mux
- Session ID range: 1–65535
- XUDP session ID: 0
- Target for mux connect: v1.mux.cool:666

### GeoIP
- Magic: "GEO1" (0x47454F31)
- Entry size: 10 bytes (startIP 4 + endIP 4 + country 2)

---

## 24. FILE INDEX

### Network Extension (8 Swift files)
| File | Lines | Key Type | Purpose |
|------|-------|----------|---------|
| `PacketTunnelProvider.swift` | ~200 | `PacketTunnelProvider` | NEPacketTunnelProvider entry point |
| `LWIPStack.swift` | ~600 | `LWIPStack` | lwIP coordinator, DNS interception, routing |
| `LWIPTCPConnection.swift` | ~500 | `LWIPTCPConnection` | TCP connection with coalescing/overflow |
| `LWIPUDPFlow.swift` | ~400 | `LWIPUDPFlow` | UDP flow with mux/proxy/direct paths |
| `DNSPacket.swift` | ~150 | `DNSPacket` (enum) | DNS parse/generate utilities |
| `FakeIPPool.swift` | ~250 | `FakeIPPool` | LRU fake-IP allocator |
| `DomainRouter.swift` | ~400 | `DomainRouter` | Trie + Aho-Corasick domain routing |
| `GeoIP/GeoIPDatabase.swift` | ~100 | `GeoIPDatabase` | Binary GeoIP lookup |

### Protocol Core (7 files)
| File | Lines | Key Type | Purpose |
|------|-------|----------|---------|
| `Core/ProxyClient.swift` | ~1500 | `ProxyClient` | Central connection factory |
| `Core/ProxyConnection.swift` | ~300 | `ProxyConnection` | Base class + UDPProxyConnection |
| `Core/ProxyConfiguration.swift` | ~600 | `ProxyConfiguration` | Config struct with nested enums |
| `Core/ProxyConfiguration+DictParsing.swift` | ~200 | extension | Dictionary → config |
| `Core/ProxyConfiguration+URLParsing.swift` | ~300 | extension | URL → config |
| `Core/ProxyConfiguration+URLExport.swift` | ~200 | extension | Config → URL |
| `Core/TunneledTransport.swift` | ~50 | `TunneledTransport` | ProxyConnection→RawTransport |
| `Core/UDPFraming.swift` | ~80 | `UDPProxyConnection` | 2-byte length prefix framing |

### Protocol Implementations
| File | Lines | Key Type |
|------|-------|----------|
| `VLESS/VLESSProtocol.swift` | ~150 | `VLESSProtocol` |
| `VLESS/VLESSVision.swift` | ~600 | `VLESSVisionConnection` |
| `Shadowsocks/ShadowsocksProtocol.swift` | ~80 | `ShadowsocksProtocol` |
| `Shadowsocks/ShadowsocksConnection.swift` | ~150 | `ShadowsocksConnection` |
| `Shadowsocks/ShadowsocksAEAD.swift` | ~530 | `ShadowsocksAEAD` |
| `Shadowsocks/Shadowsocks2022.swift` | ~1020 | `Shadowsocks2022` |
| `Shadowsocks/ShadowsocksUDPRelay.swift` | ~200 | `ShadowsocksUDPRelay` |
| `SOCKS5/SOCKS5Connection.swift` | ~620 | `SOCKS5Connection` |
| `TLS/TLSClient.swift` | ~2020 | `TLSClient` |
| `TLS/TLSConfiguration.swift` | ~100 | `TLSConfiguration` |
| `TLS/TLSProxyConnection.swift` | ~80 | `TLSProxyConnection` |
| `TLS/TLS12KeyDerivation.swift` | ~100 | Key derivation |
| `Reality/RealityClient.swift` | ~840 | `RealityClient` |
| `Reality/RealityConfiguration.swift` | ~100 | `RealityConfiguration` |
| `Reality/RealityProxyConnection.swift` | ~80 | `RealityProxyConnection` |
| `Reality/TLS13KeyDerivation.swift` | ~100 | HKDF |
| `Reality/TLSClientHelloBuilder.swift` | ~400 | Browser fingerprinting |
| `Reality/TLSRecordConnection.swift` | ~960 | `TLSRecordConnection` |
| `Reality/TLSRecordCrypto.swift` | ~200 | AES-GCM/ChaCha20/CBC |
| `WebSocket/WebSocketConfiguration.swift` | ~50 | Config |
| `WebSocket/WebSocketConnection.swift` | ~500 | `WebSocketConnection` |
| `WebSocket/WebSocketProxyConnection.swift` | ~50 | Wrapper |
| `HTTPUpgrade/HTTPUpgradeConfiguration.swift` | ~30 | Config |
| `HTTPUpgrade/HTTPUpgradeConnection.swift` | ~280 | `HTTPUpgradeConnection` |
| `HTTPUpgrade/HTTPUpgradeProxyConnection.swift` | ~30 | Wrapper |
| `XHTTP/XHTTPConfiguration.swift` | ~390 | Config with modes/placement |
| `XHTTP/XHTTPConnection.swift` | ~1920 | `XHTTPConnection` |
| `Mux/MuxClient.swift` | ~340 | `MuxClient` |
| `Mux/MuxManager.swift` | ~50 | `MuxManager` |
| `Mux/MuxSession.swift` | ~130 | `MuxSession` |
| `Mux/MuxFrame.swift` | ~310 | Frame format |
| `Mux/XUDP.swift` | ~40 | GlobalID |
| `Naive/NaiveProxyConnection.swift` | ~300 | Padding framing |
| `Naive/HTTP11/HTTP11Connection.swift` | ~200 | HTTP/1.1 CONNECT |
| `Naive/HTTP2/HTTP2Session.swift` | ~200 | Session pool |
| `Naive/HTTP2/HTTP2Connection.swift` | ~300 | H2 connection |
| `Naive/HTTP2/HTTP2Framer.swift` | ~300 | Frame codec |
| `Naive/HTTP2/HTTP2FlowControl.swift` | ~100 | Window management |
| `Naive/HTTP2/HPACKEncoder.swift` | ~200 | Header compression |
| `Direct/DirectProxyConnection.swift` | ~100 | Direct wrapper |
| `Direct/DirectTCPRelay.swift` | ~150 | TCP bypass |
| `Direct/DirectUDPRelay.swift` | ~150 | UDP bypass |

### General Utilities (7 files)
| File | Key Type | Purpose |
|------|----------|---------|
| `NWTransport.swift` | `NWTransport`, `RawTransport` | TCP transport + protocol |
| `ProxyDNSCache.swift` | `ProxyDNSCache` | Stale-while-revalidate DNS |
| `ActivityTimer.swift` | `ActivityTimer` | Inactivity detection |
| `DomainRule.swift` | `DomainRule`, `DomainRuleType` | Rule types |
| `Data+init.swift` | `Data` extension | Hex/Base64URL |
| `UnfairLock.swift` | `UnfairLock`, `ReadWriteLock` | Synchronization |
| `DeviceCensorship.swift` | `DeviceCensorship` | China detection |

### Shared (14+ files)
| File | Key Type | Purpose |
|------|----------|---------|
| `AWCore.swift` | `AWCore`, `ProxyMode` | App Group, migration |
| `Blake3/Blake3Hasher.swift` | `Blake3Hasher` | Wrapper over SPM BLAKE3 |
| `Configuration/ConfigurationStore.swift` | `ConfigurationStore` | CRUD → JSON |
| `Configuration/ChainStore.swift` | `ChainStore` | CRUD → JSON |
| `Configuration/SubscriptionStore.swift` | `SubscriptionStore` | CRUD → JSON |
| `Configuration/RuleSetStore.swift` | `RuleSetStore` | Rule assignments |
| `Configuration/CertificateStore.swift` | `CertificateStore` | Trusted certs |
| `Configuration/LatencyTester.swift` | `LatencyTester` | captive.apple.com test |
| `Configuration/SubscriptionFetcher.swift` | `SubscriptionFetcher` | Remote fetch+parse |
| `Configuration/ClashProxyParser.swift` | `ClashProxyParser` | YAML → config |
| `Configuration/ConfigurationProvider.swift` | `ConfigurationProviding` | Protocol |
| `Models/ProxyChain.swift` | `ProxyChain` | Chain model |
| `Models/Subscription.swift` | `Subscription` | Subscription model |
| `Models/PickerItem.swift` | `PickerItem` | UI model |
| `ViewModels/VPNViewModel.swift` | `VPNViewModel` | VPN state singleton |

### App Views (15+ files)
| File | Purpose |
|------|---------|
| `AnywhereApp.swift` | @main entry |
| `ContentView.swift` | TabView root |
| `Views/HomeView.swift` | VPN toggle + stats |
| `Views/OnboardingView.swift` | First-run flow |
| `Views/ProxyList/ProxyListView.swift` | Proxy list |
| `Views/ProxyList/ProxyEditorView.swift` | Proxy editor form |
| `Views/ProxyList/AddProxyView.swift` | Import (QR/Link/Manual) |
| `Views/ChainList/ChainListView.swift` | Chain list |
| `Views/ChainList/ChainEditorView.swift` | Chain editor |
| `Views/Settings/SettingsView.swift` | Settings |
| `Views/Settings/RuleSetListView.swift` | Rule assignments |
| `Views/Settings/AdvancedSettingsView.swift` | Advanced links |
| `Views/Settings/IPv6SettingsView.swift` | IPv6 toggle |
| `Views/Settings/EncryptedDNSSettingsView.swift` | DoH/DoT |
| `Views/Settings/TrustedCertificatesView.swift` | Cert management |

---

## QUICK REFERENCE: What to Read Before Changing...

| If changing... | Must read | Also check |
|---------------|-----------|------------|
| DNS behavior | `LWIPStack.swift` (handleDNSQuery, resolveFakeIP) | `DNSPacket.swift`, `FakeIPPool.swift` |
| Routing rules | `DomainRouter.swift` | `RuleSetStore.swift`, `LWIPStack.swift` (resolveFakeIP) |
| TCP connection handling | `LWIPTCPConnection.swift` | `ProxyClient.swift`, `ProxyConnection.swift` |
| UDP handling | `LWIPUDPFlow.swift` | `LWIPStack.swift` (udp_recv_fn), `MuxClient.swift` |
| Adding new protocol | `ProxyClient.swift` (connect flow) | `ProxyConnection.swift`, `ProxyConfiguration.swift` |
| TLS behavior | `TLSClient.swift` | `TLSRecordConnection.swift`, `TLSConfiguration.swift` |
| Reality behavior | `RealityClient.swift` | `TLSClientHelloBuilder.swift`, `RealityConfiguration.swift` |
| Vision flow | `VLESSVision.swift` | `ProxyClient.swift` (isVisionFlow), `TLSRecordConnection.swift` |
| Shadowsocks | `ShadowsocksAEAD.swift`, `ShadowsocksConnection.swift` | `Shadowsocks2022.swift`, `ShadowsocksUDPRelay.swift` |
| WebSocket transport | `WebSocketConnection.swift` | `WebSocketConfiguration.swift`, `ProxyClient.swift` |
| XHTTP transport | `XHTTPConnection.swift` | `XHTTPConfiguration.swift`, `ProxyClient.swift` |
| Mux/XUDP | `MuxClient.swift`, `MuxFrame.swift` | `MuxManager.swift`, `XUDP.swift`, `LWIPUDPFlow.swift` |
| Proxy chaining | `ProxyClient.swift` (buildChainTunnel) | `TunneledTransport.swift` |
| App settings UI | `SettingsView.swift` | `VPNViewModel.swift`, Darwin notifications |
| Proxy list UI | `ProxyListView.swift` | `VPNViewModel.swift`, `ConfigurationStore.swift` |
| Config import | `AddProxyView.swift` | `ProxyConfiguration+URLParsing.swift`, `ClashProxyParser.swift`, `SubscriptionFetcher.swift` |
| Config export | `ProxyConfiguration+URLExport.swift` | `ProxyConfiguration.swift` |
| Stats display | `HomeView.swift` | `VPNViewModel.swift` (pollStats), `LWIPStack.swift` (totalBytesIn/Out) |
| Tunnel start/stop | `PacketTunnelProvider.swift` | `VPNViewModel.swift` (connectVPN), `LWIPStack.swift` |
| App Group data | `AWCore.swift` | All stores, `PacketTunnelProvider.swift` |
| Latency testing | `LatencyTester.swift` | `ProxyClient.swift`, `ProxyDNSCache.swift` |
