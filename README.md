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

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/NodePassProject/Anywhere)

<div>
    <a href="https://apps.apple.com/us/app/id6758235178">
        <img width="128" src="https://storage.argsment.com/Download%20on%20the%20App%20Store.png" />
    </a>
</div>

</div>

---

## Why Anywhere?

Most iOS proxy clients wrap sing-box or Xray-core in a Go/C++ bridge. Anywhere takes a different approach — every protocol, every transport, the QUIC stack, and the entire packet tunnel are implemented natively in Swift and C. The result is a smaller binary, lower memory usage, tighter system integration, and no bridging overhead.

## Features

### Protocols & Security

- **VLESS** with full Vision (XTLS-RPRX-Vision) flow control and adaptive padding
- **Hysteria2** over QUIC with Brutal congestion control
- **Trojan** over TLS with UDP-over-TCP relay
- **Shadowsocks** (AEAD and Shadowsocks 2022)
- **SOCKS5** with optional authentication
- **Naive Proxy** (HTTP/1.1, HTTP/2, HTTP/3) with padding negotiation
- **Reality** with X25519 key exchange and TLS 1.3 fingerprint spoofing
- **TLS** with SNI, ALPN, custom trusted certificates, and optional insecure mode
- **Transports:** TCP, WebSocket (with early data), HTTP Upgrade, XHTTP (stream-one, stream-up, and packet-up over HTTP/1.1 and HTTP/2)
- **Mux** multiplexing with **XUDP** (GlobalID-based, BLAKE3 keyed hashing)
- **Fingerprints:** Chrome, Firefox, Safari, iOS, Edge

### App

- **ASR™ Smart Routing** — reduce latency while routing through proxy on demand
- **One-tap connect** with animated status UI and real-time traffic stats
- **Proxy chains** — cascade traffic through multiple outbounds
- **Subscription import** with auto-detection, auto-refresh, and profile metadata
- **Deep link support** for quick proxy/subscription import (see [Deep Links](#deep-links))
- **QR code scanner** for instant config import
- **Latency testing** per-configuration
- **Custom routing rule sets** with domain/IP/GeoIP matching (MaxMind GeoLite2)
- **Country bypass** — exclude traffic by destination country
- **Built-in ad blocking** rule set
- **Encrypted DNS** (DNS-over-HTTPS, DNS-over-TLS) with auto-upgrade
- **IPv6** support with configurable behavior
- **Always On** / on-demand VPN
- **Trusted certificate** management for private CAs
- **Xray-core compatible** — works with standard V2Ray/Xray server deployments
- **Lock Screen / Control Center widget** for one-tap VPN toggle
- **tvOS companion app** — full proxy management on Apple TV

### Architecture

- **Minimal dependencies** — Apple frameworks, vendored C libraries (lwIP, ngtcp2), and Swift implementation of BLAKE3 and YAML
- **Native Packet Tunnel** — system-wide VPN via `NEPacketTunnelProvider` with a userspace TCP/IP stack
- **Native QUIC stack** — ngtcp2-powered client used for Hysteria2 and Naive HTTP/3
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

Tapping a `vless://`, `hysteria2://`, `hy2://`, `trojan://`, `ss://`, or `quic://` link on iOS will open Anywhere and pre-fill the full URI in the Add Proxy view for import.

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
