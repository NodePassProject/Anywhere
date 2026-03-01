<div align="center">
  
<div><img width="100" height="100" alt="Anywhere" src="https://github.com/user-attachments/assets/c4ce4299-f9e1-461c-925e-814506952ba4" /></div>

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

Anywhere is implemented natively in Swift, running directly on Apple's networking stack with smaller binary, lower memory usage, tighter system integration, and no bridging overhead.

## Features

### Protocols & Security

- **VLESS** with full Vision (XTLS-RPRX-Vision) flow control and adaptive padding
- **Reality** with X25519 key exchange, TLS 1.3 fingerprint spoofing (Chrome, Firefox, Safari, Edge, iOS)
- **TLS** with SNI, ALPN, and optional insecure mode
- **Transports:** TCP, WebSocket (with early data), HTTP Upgrade, XHTTP (stream-one & packet-up)
- **Mux** multiplexing with **XUDP** (GlobalID-based, BLAKE3 keyed hashing)

### App

- **One-tap connect** with animated status UI
- **QR code scanner** for instant config import
- **Subscription import** — paste a URL, auto-detect VLESS links vs subscription endpoints
- **Manual editor** for full control over every parameter
- **Country bypass** — GeoIP-based split routing for 10 countries (CN, RU, IR, TM, MM, BY, SA, AE, VN, CU)

### Architecture

- **Zero third-party dependencies** — Apple frameworks only (SwiftUI, NetworkExtension, Security, Foundation)
- **Native Packet Tunnel** — full system-wide VPN via NetworkExtension with lwIP stack

## Getting Started

### Build from Source

```bash
git clone https://github.com/hiDandelion/Anywhere.git
cd Anywhere
open Anywhere.xcodeproj
```

Select the `Anywhere` scheme, choose your device, and hit Run.

## License

Anywhere is licensed under the [GNU General Public License v3.0](LICENSE).

<div align="center">

---

If you find Anywhere useful, consider starring the repo. It helps others discover it.
