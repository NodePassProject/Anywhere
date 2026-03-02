# Anywhere Network Extension — Code Analysis

## 1. Architecture Overview

The Anywhere Network Extension is an iOS **packet tunnel provider** that implements a VLESS proxy client with a userspace TCP/IP stack. It runs as a separate process from the main app, communicating via `NETunnelProviderSession` app messages and shared `UserDefaults` (App Group).

```
┌────────────────────────┐     App Messages     ┌──────────────────────────────────┐
│     Anywhere App       │◄─────(IPC)──────────►│  Anywhere Network Extension      │
│                        │     Darwin Notifs    │                                  │
│  VPNViewModel          │─────────────────────►│  PacketTunnelProvider            │
│  NETunnelProviderMgr   │                      │    └─► LWIPStack                 │
│                        │                      │          ├─► lwIP (C)            │
│  UserDefaults (group)  │◄─────shared─────────►│          ├─► FakeIPPool          │
│  routing.json (group)  │◄─────shared─────────►│          ├─► DomainRouter        │
└────────────────────────┘                      │          ├─► GeoIPDatabase       │
                                                │          ├─► LWIPTCPConnection[] │
                                                │          └─► LWIPUDPFlow[]       │
                                                └──────────────────────────────────┘
```

**Zero third-party dependencies.** The entire stack is built on Apple frameworks (`NetworkExtension`, `Security`, `Foundation`) plus vendored C libraries (lwIP, BLAKE3).

---

## 2. Code Structure

### File Layout

```
Anywhere Network Extension/
├── PacketTunnelProvider.swift      (173 lines)  — NE entry point, tunnel lifecycle
├── LWIPStack.swift                 (723 lines)  — Central coordinator, packet I/O, DNS interception
├── LWIPTCPConnection.swift         (542 lines)  — Per-TCP-connection proxy handler
├── LWIPUDPFlow.swift               (372 lines)  — Per-UDP-flow proxy handler
├── DomainRouter.swift              (144 lines)  — Domain-based routing rules
├── FakeIPPool.swift                (261 lines)  — Synthetic IP ↔ domain mapping (LRU)
├── BridgingHeader.h                (18 lines)   — Swift-C bridge
│
├── Crypto/
│   ├── blake3.h / blake3.c + impl  — BLAKE3 hash (for XUDP GlobalID)
│   └── CTLSKeyDerivation.h/.c      — TLS 1.3 key derivation (RFC 8446)
│
├── GeoIP/
│   ├── CGeoIP.h/.c                 — Binary search over GEO1 format
│   ├── GeoIPDatabase.swift          — Swift wrapper
│   └── geoip.dat                   — Bundled database (309 KB)
│
├── lwip/                            — Vendored lwIP TCP/IP stack (~204 C/H files)
│   ├── lwip_bridge.h/.c            — C bridge: callbacks, init, packet I/O
│   ├── port/                       — Platform adaptations (lwipopts.h, sys_arch.c)
│   └── src/                        — Full lwIP source (core, IPv4, IPv6, TCP, UDP)
│
├── Packet/
│   └── CPacket.h/.c               — TLS parsing, DNS query/response, UDP framing
│
└── VLESS/
    └── CVLESS.h/.c                 — VLESS header builder, address parsing
```

### Layer Diagram

```
Layer 0: NEPacketTunnelProvider (OS interface)
Layer 1: PacketTunnelProvider.swift (lifecycle + settings)
Layer 2: LWIPStack.swift (packet dispatch + DNS interception)
Layer 3: lwip_bridge.c ↔ lwIP (userspace TCP/IP reassembly)
Layer 4: LWIPTCPConnection / LWIPUDPFlow (per-connection proxying)
Layer 5: VLESSClient / DirectTCPRelay / MuxManager (protocol layer, in /Protocols)
```

---

## 3. Functionality Breakdown

### 3.1 PacketTunnelProvider (`PacketTunnelProvider.swift`)

The `NEPacketTunnelProvider` subclass — the single entry point the OS calls.

| Method | Purpose |
|---|---|
| `startTunnel(options:)` | Parses `VLESSConfiguration` from options dict, builds tunnel settings (IP/DNS/routes), starts `LWIPStack` |
| `stopTunnel(with:)` | Calls `lwipStack.stop()` |
| `handleAppMessage(_:)` | Two message types: `"stats"` returns `bytesIn/bytesOut`; otherwise treats as configuration switch |
| `buildTunnelSettings()` | Creates `NEPacketTunnelNetworkSettings` — IPv4 `10.8.0.2/24`, optional IPv6 `fd00::2/64`, Cloudflare DNS, MTU 1400, excludes server IP from routes |
| `reapplyTunnelSettings()` | Re-builds and re-applies settings (triggered by IPv6 toggle) |

### 3.2 LWIPStack (`LWIPStack.swift`)

The central coordinator. Singleton within the NE process (`LWIPStack.shared`).

**Key responsibilities:**
- **Packet I/O loop**: Reads IP packets from `NEPacketTunnelFlow` → feeds into lwIP → writes output packets back
- **C callback registration**: Bridges lwIP events (tcp_accept, tcp_recv, tcp_sent, tcp_err, udp_recv, netif output) to Swift
- **DNS interception (Fake-IP)**: Intercepts port-53 UDP queries, returns synthetic IPs for domain-routed traffic
- **DDR blocking**: When DoH is disabled, blocks `_dns.resolver.arpa` SVCB queries to prevent automatic DoH upgrade
- **Settings observation**: Watches Darwin notifications for `settingsChanged` and `routingChanged`, triggers stack restart
- **Traffic stats**: Tracks `totalBytesIn` / `totalBytesOut`
- **UDP flow management**: Maintains `udpFlows` dictionary (max 200, 60s idle timeout)
- **Mux management**: Creates `MuxManager` when Vision + Mux is enabled

**Threading model**: All lwIP calls run on a single serial `DispatchQueue` (`lwipQueue`). Output writes use a separate `outputQueue`. This is critical because lwIP is not thread-safe.

### 3.3 LWIPTCPConnection (`LWIPTCPConnection.swift`)

One instance per TCP connection accepted by lwIP. Handles the full lifecycle:

- **Bypass vs proxy decision**: At `init`, checks `forceBypass` (from FakeIPPool route) or `shouldBypass` (GeoIP)
- **VLESS path**: `connectVLESS()` → `VLESSClient.connect()` → bidirectional data relay
- **Direct path**: `connectDirect()` → `DirectTCPRelay.connect()` → bidirectional relay
- **Backpressure**: Overflow buffer (512 KB max) when lwIP send buffer is full; pauses VLESS receive loop; resumes when `handleSent` drains overflow
- **Timeout model** (matching Xray-core):
  - Handshake: 60s
  - Connection idle: 300s
  - Uplink-only / Downlink-only: 1s after one direction closes

### 3.4 LWIPUDPFlow (`LWIPUDPFlow.swift`)

One instance per UDP 5-tuple. Three paths:

| Path | Condition | Behavior |
|---|---|---|
| **Direct** | `forceBypass` or GeoIP match | `DirectUDPRelay` — raw UDP socket |
| **Mux** | Vision + Mux enabled, default config | `MuxManager.dispatch()` → `MuxSession` — multiplexed over shared VLESS connection |
| **Non-mux** | Everything else | `VLESSClient.connectUDP()` → length-framed payloads over dedicated VLESS connection |

- **Buffer limit**: 16 KB pending buffer (matches Xray-core `DiscardOverflow`)
- **XUDP**: When enabled, generates GlobalID via BLAKE3 hash of `"udp:srcHost:srcPort"` for Full Cone NAT

### 3.5 DomainRouter (`DomainRouter.swift`)

Loads `routing.json` from the App Group container. Three rule types:

1. **Exact domain** — `O(1)` dictionary lookup
2. **Domain suffix** — linear scan (e.g., `.google.com` matches `www.google.com`)
3. **Domain keyword** — linear scan (e.g., `"google"` matches `mail.google.com`)

Each rule maps to either `.direct` or `.proxy(UUID)`, where the UUID references a `VLESSConfiguration` stored in the same JSON file.

### 3.6 FakeIPPool (`FakeIPPool.swift`)

Maps domains to synthetic IPs for DNS interception:

- **IPv4 range**: `198.18.0.0/15` (131,071 usable offsets)
- **IPv6 range**: `fc00::/18` (same offset space)
- **LRU cache**: O(1) doubly-linked list for touch/evict, matching Xray-core's `cache.Lru`
- **`rebuild()`**: On stack restart, updates existing entries' configurations from new routing rules without resetting (preserves cached DNS mappings)

### 3.7 GeoIPDatabase (`GeoIPDatabase.swift` + `CGeoIP.c`)

Binary GEO1 format: 8-byte header + N×10-byte entries (startIP:4, endIP:4, countryCode:2). Binary search lookup. Used for country-based tunnel bypass.

### 3.8 C Components

| File | Purpose |
|---|---|
| `lwip_bridge.c` | Initializes lwIP, creates netif/TCP listener/UDP PCB, dispatches callbacks to Swift |
| `CPacket.c` | TLS record parsing, DNS query parsing + response generation, UDP framing |
| `CVLESS.c` | Builds VLESS protocol request headers, parses IPv4/IPv6/domain addresses |
| `CTLSKeyDerivation.c` | TLS 1.3 HKDF-based key derivation (handshake + application keys, Finished computation) |
| `blake3.c` | BLAKE3 hashing for XUDP GlobalID generation |
| `CGeoIP.c` | Binary search over GEO1 database entries |

---

## 4. Code Paths

### 4.1 Tunnel Start

```
OS calls startTunnel(options:)
  → Parse VLESSConfiguration from options dict
  → Set remoteAddress (server connect IP)
  → Build NEPacketTunnelNetworkSettings (IPv4/IPv6/DNS/routes/MTU)
  → setTunnelNetworkSettings()
  → LWIPStack.start(packetFlow:configuration:ipv6Enabled:)
      → Set LWIPStack.shared singleton
      → Load GeoIPDatabase (once, reused)
      → Load bypass country + DoH setting from UserDefaults
      → Create MuxManager (if Vision + Mux)
      → DomainRouter.loadRoutingConfiguration()
      → Register C callbacks (output, tcp_accept, tcp_recv, tcp_sent, tcp_err, udp_recv)
      → lwip_bridge_init() (init lwIP core, create netif, TCP listener, UDP PCB)
      → Start timeout timer (250ms)
      → Start UDP cleanup timer (1s)
      → Start reading packets from NEPacketTunnelFlow
      → Start observing Darwin notifications
```

### 4.2 TCP Connection (Proxied)

```
App sends SYN → TUN device → NEPacketTunnelFlow
  → startReadingPackets() → lwip_bridge_input()
  → lwIP reassembles TCP handshake
  → tcp_accept callback fires
      → Check IPv6 enabled
      → FakeIPPool lookup (if fake IP → resolve domain + config + isDirect)
      → Create LWIPTCPConnection(pcb, dstHost, dstPort, config, forceBypass)
          → If bypass: connectDirect() → DirectTCPRelay → BSD socket
          → Else: connectVLESS() → VLESSClient.connect()
              → Establish TCP socket to server
              → TLS/Reality/WebSocket/HTTPUpgrade/XHTTP handshake (per transport)
              → Send VLESS request header + initial data
              → Return VLESSConnection
          → Start handshake timeout (60s)
  → App sends data → tcp_recv callback → handleReceivedData()
      → Forward to VLESSConnection.send() or DirectTCPRelay.send()
      → Advance lwIP receive window on send completion
  → VLESS server responds → requestNextReceive() loop
      → VLESSConnection.receive() → writeToLWIP()
      → Write to lwIP TCP send buffer (with overflow/backpressure)
      → lwIP sends ACK → packet flow → TUN → App
  → Close: handleRemoteClose() or idle timeout → close/abort pcb, release VLESS
```

### 4.3 DNS Interception (Fake-IP)

```
App sends DNS query (UDP port 53)
  → udp_recv callback → handleDNSQuery()
      → parse_dns_query_ext() → extract domain + QTYPE
      → If !dohEnabled && domain == "_dns.resolver.arpa":
          → sendNODATA() → block DDR discovery
      → If QTYPE is A(1) or AAAA(28):
          → DomainRouter.matchDomain(domain) → RouteAction?
          → If matched:
              → FakeIPPool.allocate(domain, config, isDirect)
              → Build fake IP bytes (IPv4 or IPv6)
              → generate_dns_response() → craft DNS response with fake IP
              → lwip_bridge_udp_sendto() → send response back to app
              → Return true (handled, no UDP flow created)
      → If unmatched: return false → fall through to normal UDP proxy flow
```

### 4.4 UDP Flow (Mux Path)

```
App sends UDP datagram → udp_recv callback
  → DNS interception check (port 53) → not handled
  → FakeIPPool lookup → resolve domain + config
  → Lookup existing flow by 5-tuple key
  → If new flow:
      → Create LWIPUDPFlow → handleReceivedData()
      → Buffer payload → connectVLESS()
      → If bypass: connectDirectUDP()
      → If mux: MuxManager.dispatch(network: .udp, host, port, globalID)
          → Get/create MuxClient (shared VLESS connection)
          → Create MuxSession (stream within mux)
          → Set dataHandler + closeHandler
          → Send buffered payloads through session
      → Else (non-mux): VLESSClient.connectUDP()
          → Length-frame each payload (2-byte prefix)
          → Send through VLESSConnection.sendRaw()
  → Response received → handleVLESSData()
      → lwip_bridge_udp_sendto() (swap src/dst) → send back to app
```

### 4.5 Settings Change (Live Reload)

```
User toggles setting in SettingsView
  → Save to App Group UserDefaults
  → Post Darwin notification "com.argsment.Anywhere.settingsChanged"

Network Extension receives notification
  → handleSettingsChanged() on lwipQueue
      → Compare: ipv6Enabled, bypassCountry, dohEnabled
      → If ipv6Changed: onTunnelSettingsNeedReapply() → re-apply routes + DNS
      → restartStack(configuration, ipv6Enabled)
          → shutdownInternal() (close all TCP/UDP, cancel mux, shutdown lwIP)
          → Reload settings from UserDefaults
          → Recreate MuxManager if needed
          → DomainRouter.loadRoutingConfiguration()
          → FakeIPPool.rebuild() (preserves mappings, updates configs)
          → Re-init lwIP, restart packet reading
```

### 4.6 Configuration Switch (App Message)

```
User selects different proxy in app
  → VPNViewModel.sendConfigurationToTunnel()
  → NETunnelProviderSession.sendProviderMessage()

Network Extension receives message
  → handleAppMessage() → parse as VLESSConfiguration
  → LWIPStack.switchConfiguration(newConfig)
      → restartStack() (same as settings change path)
```

---

## 5. Key Design Patterns

1. **Userspace TCP/IP (lwIP)**: Rather than using `NEAppProxyProvider` (per-flow), the extension uses `NEPacketTunnelProvider` with a full userspace TCP/IP stack. This gives complete control over every IP packet, enabling DNS interception and Fake-IP routing.

2. **C-Swift bridge via function pointers**: lwIP callbacks are registered as `@convention(c)` closures in Swift, routed through the `LWIPStack.shared` singleton. `Unmanaged` is used to pass `LWIPTCPConnection` references as opaque pointers through C.

3. **Fake-IP DNS**: Domain-based routing without requiring SOCKS/HTTP proxy support in apps. DNS queries are intercepted, synthetic IPs assigned, and later reverse-mapped when connections arrive.

4. **Backpressure**: TCP follows a pull model — VLESS receive is paused when the lwIP send buffer is full, resumed when the local app ACKs. Overflow buffer capped at 512 KB prevents unbounded memory growth.

5. **Xray-core compatibility**: Timeouts (handshake 60s, idle 300s, uplinkOnly/downlinkOnly 1s), UDP buffer limits (16 KB DiscardOverflow), Mux with XUDP Full Cone NAT GlobalID, and FakeIPPool LRU all match Xray-core behavior.
