# Exclusions

AnywhereQUIC implements the client side of RFC 9000 (QUIC version 1), RFC 9001 (Using TLS to Secure QUIC), RFC 9002 (Loss Detection and Congestion Control) and RFC 9221 (DATAGRAM frames). This document records only where it intentionally departs from those RFCs. QUIC extensions defined in other RFCs, such as QUIC version 2 (RFC 9369), compatible version negotiation (RFC 9368) and greasing the QUIC bit (RFC 9287), are not implemented.

## Optional or server-only behaviour that is not implemented

These parts of the RFCs are optional for a client or apply only to servers. Leaving them out does not violate the RFCs.

| Feature | RFC | Behaviour |
| --- | --- | --- |
| Server role | RFC 9000 §8, §8.1.2, §8.1.3, §19.20 | Not implemented. The package is client-only. It consumes Retry packets and `HANDSHAKE_DONE` frames but never generates them, and it does not apply an anti-amplification limit. |
| 0-RTT | RFC 9001 §4.6 | Not implemented. The client never sends 0-RTT packets. |
| ECN | RFC 9000 §13.4, RFC 9002 §7.1 | Not implemented. The connection never requests ECT marking for outgoing packets, ACK frames never carry ECN counts, and ECN counts in received `ACK_ECN` frames are ignored. |
| Address validation tokens from `NEW_TOKEN` | RFC 9000 §8.1.3 | Tokens are parsed and discarded, and later connections never present them. A Retry token is used only for the connection that received it. |
| Migration to the server's preferred address | RFC 9000 §9.6 | The `preferred_address` transport parameter is decoded, but the client never migrates to it. |
| Sending a Stateless Reset | RFC 9000 §10.3 | Not implemented. Stateless Resets from the peer are detected, but the client never sends one. |
| Skipping packet numbers to detect optimistic ACKs | RFC 9000 §21.4 | Not implemented. Packet numbers are always consecutive. |

## Behaviour that differs from the RFCs

| Behaviour | RFC | Difference |
| --- | --- | --- |
| Hysteria Brutal congestion control | RFC 9002 §7, §7.6 | NewReno as specified in RFC 9002 is the default controller. When `QUICBrutalCongestionController` is selected with a non-zero `bytesPerSecond`, it sends at the configured rate and raises that rate to compensate for up to 20% measured loss instead of backing off. It does not reduce the congestion window on congestion events or persistent congestion, so it does not meet RFC 9002 §7's requirement that alternative controllers follow RFC 8085 §3.1. With `bytesPerSecond` set to 0 it behaves as CUBIC. |
