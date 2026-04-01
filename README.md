<div align="center">

<div>
    <a href="https://apps.apple.com/us/app/anywhere-vless-proxy/id6758235178">
        <img width="100" height="100" alt="Anywhere" src="https://github.com/user-attachments/assets/c4ce4299-f9e1-461c-925e-814506952ba4" />
    </a>
</div>

# Anywhere

**The best VLESS client for iOS.**

A native, zero-dependency VLESS client built entirely in Swift.
No Electron. No WebView. No sing-box wrapper. Pure protocol implementation from the ground up.

<div>
    <a href="https://apps.apple.com/us/app/anywhere-vless-proxy/id6758235178">
        <img src="https://github.com/user-attachments/assets/ab9e5ac0-6322-4878-bf16-24a508a81b17" />
    </a>
</div>

</div>

---

## Why Anywhere?

Most iOS proxy clients wrap sing-box or Xray-core in a Go/C++ bridge. Anywhere takes a different approach — every protocol, every transport, and the entire packet tunnel stack is implemented natively in Swift and C. The result is a smaller binary, lower memory usage, tighter system integration, and no bridging overhead.

## Features

### Protocols & Security

- **VLESS** with full Vision (XTLS-RPRX-Vision) flow control and adaptive padding
- **Shadowsocks** (AEAD and Shadowsocks 2022)
- **SOCKS5** with optional authentication
- **Naive Proxy** (HTTP/1.1, HTTP/2, HTTP/3) with padding negotiation
- **Reality** with X25519 key exchange, TLS 1.3 fingerprint spoofing (Chrome, Firefox, Safari, Edge, iOS)
- **TLS** with SNI, ALPN, and optional insecure mode
- **Transports:** TCP, WebSocket (with early data), HTTP Upgrade, XHTTP (stream-one & packet-up)
- **Mux** multiplexing with **XUDP** (GlobalID-based, BLAKE3 keyed hashing)

### App

- **One-tap connect** with animated status UI and real-time traffic stats
- **Deep link support** for quick proxy/subscription import (see [Deep Links](#deep-links))
- **QR code scanner** for instant config import
- **Subscription import** with auto-detection and profile metadata
- **ASR™ Smart Routing** reduce latency while routing through proxy on demand
- **Xray-core compatible** — works with standard V2Ray/Xray server deployments

### Architecture

- **Zero third-party dependencies** — Apple frameworks + vendored C libraries (lwIP, BLAKE3)
- **Native Packet Tunnel** — system-wide VPN via `NEPacketTunnelProvider` with userspace TCP/IP stack
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

Anywhere registers three URL schemes (`anywhere`, `vless`, `ss`) so external apps and websites can trigger proxy import directly.

### Supported Schemes

| Scheme | Example | Behavior |
|--------|---------|----------|
| `anywhere` | `anywhere://add-proxy?link=<link>` | Opens the Add Proxy view with the link pre-filled |
| `vless` | `vless://uuid@host:port?params` | Opens the Add Proxy view with the full URI pre-filled |
| `ss` | `ss://base64@host:port` | Opens the Add Proxy view with the full URI pre-filled |

### `anywhere://` Scheme

```
anywhere://add-proxy?link=<link>
```

`<link>` can be any URL the app supports: a subscription URL, a `vless://` link, an `ss://` link, etc.

> **Note:** The `link` parameter is parsed by taking everything after `?link=` verbatim, so the inner URL does **not** need to be percent-encoded. For example, `anywhere://add-proxy?link=https://example.com/sub?token=abc&foo=bar` works as expected.

### `vless://` and `ss://` Schemes

Tapping a `vless://` or `ss://` link on iOS will open Anywhere and pre-fill the full URI in the Add Proxy view for import.

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
