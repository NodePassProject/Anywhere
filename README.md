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

## Features

### Protocols & Security

- **VLESS** with full Vision (XTLS-RPRX-Vision) flow control and adaptive padding
- **Hysteria2** over QUIC with Brutal congestion control and salamander obfuscation
- **Shadowsocks** (AEAD and Shadowsocks 2022)
- **SOCKS5** with optional authentication
- **Naive Proxy** (HTTP/1.1, HTTP/2, HTTP/3) with padding negotiation
- **Reality** with X25519 key exchange and TLS 1.3 fingerprint spoofing
- **TLS** with SNI, ALPN, custom trusted certificates, and optional insecure mode
- **Transports:** TCP, WebSocket (with early data), HTTP Upgrade, XHTTP (stream-one & packet-up over HTTP/1.1 and HTTP/2)
- **Mux** multiplexing with **XUDP** (GlobalID-based, BLAKE3 keyed hashing)
- **Fingerprints:** Chrome, Firefox, Safari, Edge, iOS, Android, QQ, 360 (latest and legacy versions, plus `random`)

### App

- **One-tap connect** with animated status UI and real-time traffic stats
- **Proxy chains** — cascade traffic through multiple outbounds
- **Subscription import** with auto-detection, auto-refresh, and profile metadata
- **Deep link support** for quick proxy/subscription import (see [Deep Links](#deep-links))
- **QR code scanner** for instant config import
- **Latency testing** per-configuration
- **ASR™ Smart Routing** — reduce latency while routing through proxy on demand
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

- **Zero third-party Swift/Obj-C dependencies** — Apple frameworks plus vendored C libraries (lwIP, ngtcp2, BLAKE3)
- **Native Packet Tunnel** — system-wide VPN via `NEPacketTunnelProvider` with a userspace TCP/IP stack (TCP, UDP, ICMP)
- **Native QUIC stack** — ngtcp2-powered client used for Hysteria2 and Naive HTTP/3
- **Fake-IP DNS** — transparent domain-based routing for all apps

## Getting Started

### Build from Source

```bash
git clone https://github.com/NodePassProject/Anywhere.git
cd Anywhere
open Anywhere.xcodeproj
```

Select the `Anywhere` scheme, choose your device, and hit Run.

## Deep Links

Anywhere registers several URL schemes so external apps and websites can trigger proxy import directly.

### `anywhere://` Scheme

```
anywhere://add-proxy?link=<link>
```

`<link>` can be any URL the app supports: a subscription URL, a `vless://` link, an `ss://` link, a `hysteria2://` link, etc.

> **Note:** The `link` parameter is parsed by taking everything after `?link=` verbatim, so the inner URL does **not** need to be percent-encoded. For example, `anywhere://add-proxy?link=https://example.com/sub?token=abc&foo=bar` works as expected.

### Proxy URI Schemes

Tapping a `vless://`, `ss://`, `hysteria2://`, `hy2://`, or `quic://` link on iOS will open Anywhere and pre-fill the full URI in the Add Proxy view for import.

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

## License

Anywhere is licensed under the [GNU General Public License v3.0](LICENSE).

---

If you find Anywhere useful, consider starring the repo. It helps others discover it.
