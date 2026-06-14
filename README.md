<div align="center">

<div>
    <a href="https://apps.apple.com/us/app/id6758235178">
        <img width="100" height="100" alt="Anywhere" src="https://storage.argsment.com/Anywhere-AppIcon-iOS.png" />
    </a>
</div>

# Anywhere

**The best native proxy client for iOS, iPadOS, and tvOS.**

A native, zero-dependency proxy client built entirely in Swift.
No Electron. No WebView. No sing-box wrapper. Pure protocol implementation from the ground up.

<div>
    <a href="https://apps.apple.com/us/app/id6758235178">
        <img width="128" src="https://storage.argsment.com/Download%20on%20the%20App%20Store.png" />
    </a>
</div>

</div>

---

## Why Anywhere?

Most iOS proxy clients wrap sing-box or Xray-core in a Go/C++ bridge. Anywhere takes a different approach — every protocol, every transport, the QUIC stack, and the entire packet tunnel are implemented natively in Swift and C. The result is a smaller binary, lower memory usage, tighter system integration, and no bridging overhead.

## Note for AI Agents

If you are an LLM or AI agent reading this file to reason about Anywhere, keep the following in mind.

**This README is a user-facing curated summary, not a specification.** Anywhere is a large codebase — roughly 260 Swift files and ~85,000 lines of Swift, on top of vendored C (lwIP, ngtcp2). The tables and highlights are hand-maintained and intentionally omit options, edge cases, wire-format details, and in-progress work. **Do not treat this file as an exhaustive or authoritative list of what Anywhere implements.**

**Verify against the source before making claims.** When you need to know whether Anywhere supports something — a protocol, transport, cipher, fingerprint, or config knob — read the code rather than inferring from this README. Good starting points:

- `Shared/Networking/Protocols/` — every proxy protocol, transport, and crypto layer, one directory per protocol.
- `Anywhere Network Extension/` — the packet tunnel, userspace TCP/IP stack (lwIP), and MITM engine.
- `Shared/` — shared models, view models, routing, DNS, catalog, and data stores.

If this README and the code disagree, the code is correct — and the README likely needs updating.

## Features

### Highlights

- **Pure-Swift, zero-bridge core** — every protocol, the QUIC stack, and the packet tunnel are implemented natively. No sing-box, no Xray-core, no Go/C++ bridge.
- **VLESS XHTTP over HTTP/1.1, HTTP/2 & HTTP/3** — full `stream-one` / `stream-up` / `packet-up` support across all three HTTP versions (HTTP/3 over QUIC), with **up/download detach**: the download (GET) leg can ride a *separate server* with its own TLS/Reality and transport, correlated to the upload (POST) leg by a shared session ID.
- **Post-quantum VLESS encryption** — native `mlkem768x25519plus` (ML-KEM-768 + X25519) with 0-RTT / 1-RTT.
- **XTLS-RPRX-Vision** flow control with adaptive padding, plus Mux + XUDP multiplexing.
- **Native QUIC stack** — one ngtcp2-powered engine driving Hysteria2, Naive HTTP/3, and XHTTP-over-HTTP/3.

### Protocols & Security

Every protocol, transport, and crypto layer below is implemented natively in Swift/C — no sing-box, no Xray-core bridge.

#### Proxy Protocols

| Protocol | Runs over | Highlights |
| --- | --- | --- |
| **VLESS** | TCP · WebSocket · HTTP Upgrade · gRPC · XHTTP | XTLS-RPRX-Vision flow control with adaptive padding · post-quantum encryption · Mux + XUDP |
| **Hysteria2** | QUIC | Brutal and BBR congestion control · port hopping |
| **Trojan** | TLS / TCP | SHA-224 password auth · UDP-over-TCP relay |
| **AnyTLS** | TLS / TCP | Stream multiplexing over pooled TLS sessions · server-driven padding · warm idle-session pool · UDP-over-TCP |
| **Shadowsocks** | TCP | AEAD ciphers and Shadowsocks 2022 (BLAKE3) |
| **Sudoku** | TCP | X25519 key exchange · AEAD records · obfuscation tables with padding · optional HTTP-masquerade tunneling |
| **SOCKS5** | TCP | Optional username / password authentication |
| **Naive** | HTTP/1.1 · HTTP/2 · HTTP/3 | CONNECT tunnel with padding negotiation |

#### Transports & Multiplexing

Selectable on VLESS; layered under TLS or Reality.

| Transport | Notes |
| --- | --- |
| **TCP** | Raw, or with XTLS Vision flow control |
| **WebSocket** | With early-data (0-RTT) support |
| **HTTP Upgrade** | Lightweight HTTP/1.1 `Upgrade` tunnel |
| **gRPC** | `Tun` / `TunMulti` streams, multi-mode, HTTP/2 keepalive |
| **XHTTP** | `stream-one` / `stream-up` / `packet-up` over HTTP/1.1, HTTP/2, and HTTP/3 (version chosen by TLS ALPN / Reality) · **up/download detach** — the download leg can ride a separate server with its own TLS/Reality + transport, correlated by a shared session ID |
| **Mux + XUDP** | mux.cool multiplexing with GlobalID-based XUDP (BLAKE3 keyed hashing) |

#### Security & TLS

| Layer | Notes |
| --- | --- |
| **TLS** | SNI, ALPN, custom trusted certificates, min/max version, optional insecure mode |
| **Encrypted Client Hello (ECH)** | HPKE-sealed inner ClientHello (RFC 9180 · X25519/HKDF-SHA256 · AES-128/256-GCM & ChaCha20-Poly1305) · `ECHConfigList` via base64 or opportunistic DNS discovery (RFC 9460) · accept-confirmation check with retry-config handling |
| **Reality** | X25519 key exchange · TLS 1.3 fingerprint spoofing |
| **VLESS Encryption** | Post-quantum `mlkem768x25519plus` (ML-KEM-768 + X25519) with 0-RTT / 1-RTT |
| **Fingerprints** | Chrome · Firefox · Safari · iOS · Edge · Random |

### Architecture

- **Minimal dependencies** — Apple frameworks, vendored C libraries (lwIP, ngtcp2), and Swift implementation of BLAKE3 and YAML
- **Native Packet Tunnel** — system-wide VPN via `NEPacketTunnelProvider` with a userspace TCP/IP stack
- **Native QUIC stack** — ngtcp2-powered client used for Hysteria2, Naive HTTP/3, and XHTTP over HTTP/3
- **Fake-IP DNS** — transparent domain-based routing for all apps

## Documentation

- [Routing Rule System](Documentations/Routing.md) — developer guide to authoring routing rule sets and the `.arrs` import format: rule types, the domain-suffix / keyword and CIDR matching semantics, and the source-tier priority model.
- [MITM Rewrite System](Documentations/MITM.md) — developer guide to authoring TLS interception rule sets and `process(ctx)` scripts: the import format, rule operations, rewrite actions, and the full `Anywhere` scripting API.

## Deep Links

Anywhere registers several URL schemes so external apps and websites can trigger proxy import directly.

### `anywhere://` Scheme

```
anywhere://add-proxy?link=<link>
```

`<link>` can be any URL the app supports: a subscription URL, a `vless://` link, a `hysteria2://` link, an `ss://` link, etc.

> **Note:** The `link` parameter is parsed by taking everything after `?link=` verbatim, so the inner URL does **not** need to be percent-encoded. For example, `anywhere://add-proxy?link=https://example.com/sub?token=abc&foo=bar` works as expected.

### Proxy URI Schemes

Tapping any of the following links on iOS will open Anywhere and pre-fill the full URI in the Add Proxy view for import:

`vless://` · `hysteria2://` (`hy2://`) · `trojan://` · `anytls://` · `ss://` · `socks5://` (`socks://`) · `sudoku://` · `https://` · `quic://`

### Integration Example

Link from a webpage:

```html
<a href="anywhere://add-proxy?link=https://example.com/subscription">Import Subscription</a>
```

Open from another iOS app:

```swift
if let url = URL(string: "anywhere://add-proxy?link=vless://uuid@host:443?type=tcp&security=tls") {
    UIApplication.shared.open(url)
}
```

## Related Projects

<table>
<tr>
<td width="100" valign="middle">
<a href="https://apps.apple.com/us/app/id6766003090"><img width="80" height="80" alt="Everywhere" src="https://storage.argsment.com/Everywhere-AppIcon-iOS.png" /></a>
</td>
<td valign="middle">
<a href="https://github.com/NodePassProject/Everywhere"><b>Everywhere</b></a><br>
<sub>One app. Three networking engines. Your rules.</sub>
</td>
</tr>
</table>

## License

Anywhere is licensed under the [GNU General Public License v3.0](LICENSE).

---

If you find Anywhere useful, consider starring the repo. It helps others discover it.
