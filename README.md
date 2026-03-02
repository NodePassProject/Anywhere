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
- **Reality** with X25519 key exchange, TLS 1.3 fingerprint spoofing (Chrome, Firefox, Safari, Edge, iOS)
- **TLS** with SNI, ALPN, and optional insecure mode
- **Transports:** TCP, WebSocket (with early data), HTTP Upgrade, XHTTP (stream-one & packet-up)
- **Mux** multiplexing with **XUDP** (GlobalID-based, BLAKE3 keyed hashing)

### App

- **One-tap connect** with animated status UI and real-time traffic stats
- **QR code scanner** for instant config import
- **Subscription import** with auto-detection and profile metadata
- **Manual editor** for full control over every parameter
- **Latency testing** with color-coded indicators and batch "Test All"
- **Domain routing rules** with exact, suffix, and keyword matching
- **Country bypass** — GeoIP-based split routing (CN, RU, IR, TM, MM, BY, SA, AE, VN, CU)
- **DNS over HTTPS** toggle
- **IPv6** support
- **Always On VPN**
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

## License

Anywhere is licensed under the [GNU General Public License v3.0](LICENSE).

---

If you find Anywhere useful, consider starring the repo. It helps others discover it.
