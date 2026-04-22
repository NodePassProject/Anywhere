# Anywhere Patches to lwIP

This directory holds a vendored copy of lwIP with a small number of
targeted modifications for the Anywhere Network Extension's TUN-based
deployment. Every in-source modification is bracketed with

```
/* --- BEGIN Anywhere Patch: <short tag> --- */
...
/* --- END Anywhere Patch --- */
```

so the full set can be located with:

```
grep -rn "Anywhere Patch" "Anywhere Network Extension/lwip/src"
```

## Deployment context

lwIP runs inside the Network Extension as the peer TCP stack for the
local iOS kernel. A proxied TCP connection flows through:

```
iOS app
  │  (kernel TCP)
NEPacketTunnelFlow  ◀─── in-memory "link", no loss / reorder / congestion
  │
LWIPStack.outputPackets / lwip_bridge_input
  │
lwIP (this vendored copy)
  │  (tcp_write / tcp_recv)
LWIPTCPConnection.swift
  │
ProxyConnection (VLESS / direct / …)
  │
Real internet
```

The segment between the iOS kernel and lwIP is in-process memory. It
does not lose, reorder, or congest packets; the only real bottleneck
is the proxy connection and the remote server beyond it. This
asymmetry motivates the patches below.

---

## Patches

### 1. `src/core/tcp_out.c` — disable cwnd for TUN

**What:** In `tcp_output`, stop clamping the sendable window by the
congestion window. Use `pcb->snd_wnd` alone.

```c
/* before */
wnd = LWIP_MIN(pcb->snd_wnd, pcb->cwnd);

/* after */
wnd = pcb->snd_wnd;
```

**Why:** The peer is the local kernel over an in-memory flow, so cwnd
cannot legitimately indicate congestion here. Left enabled, it produces
only spurious throttles:

- **Initial slow-start ramp.** `cwnd` starts at
  `LWIP_TCP_CALC_INITIAL_CWND(mss)` and ramps through slow start up to
  `ssthresh = TCP_SND_BUF`, unnecessarily limiting the first few RTTs
  of every new connection.
- **RTO collapse** (`tcp_slowtmr`, `src/core/tcp.c`). Any spurious
  timeout — a brief `outputPackets` drain stall, a delayed app-side
  ACK, a `lwipQueue` scheduling hiccup — resets `cwnd = 1 · MSS` and
  halves `ssthresh`. Recovery then takes many RTTs of slow start.
- **Fast-retransmit halving** on 3 duplicate ACKs
  (`tcp_rexmit_fast`, `src/core/tcp_out.c`) — rare in TUN but not
  impossible under packet reordering.

`snd_wnd` (the app kernel's advertised receive window, scaled per
RFC 1323) remains in the expression, so peer-side flow control keeps
working.

**What is unaffected:**

- Retransmissions still fire. Both `tcp_slowtmr` (RTO) and
  `tcp_rexmit_fast` drive off `pcb->unacked` and the `TF_INFR` flag,
  not cwnd.
- All cwnd / ssthresh bookkeeping in `tcp_in.c` and `tcp_out.c` keeps
  running. It simply no longer gates output.
- `TCP_SND_BUF` and `TCP_SND_QUEUELEN` still bound the in-flight data
  held in `pcb->unsent` + `pcb->unacked`.
- Nagle, delayed ACKs, window scaling, SACK, and persist timer logic
  are unchanged.

**Upgrade notes:** When bumping the vendored lwIP version, re-apply
this one-line change. Search for

```
wnd = LWIP_MIN(pcb->snd_wnd, pcb->cwnd);
```

in `src/core/tcp_out.c` inside `tcp_output()`.

---

### 2. `src/include/lwip/priv/tcp_priv.h` — disable delayed ACK

**What:** Redefine the `tcp_ack` macro to always queue an immediate
ACK (`TF_ACK_NOW`) instead of the stretch-ACK pattern that ACKs every
other received segment and falls back to a 250 ms timer for the tail.

```c
/* before */
#define tcp_ack(pcb) \
  do { \
    if ((pcb)->flags & TF_ACK_DELAY) { \
      tcp_clear_flags(pcb, TF_ACK_DELAY); \
      tcp_ack_now(pcb); \
    } else { \
      tcp_set_flags(pcb, TF_ACK_DELAY); \
    } \
  } while (0)

/* after */
#define tcp_ack(pcb) tcp_set_flags(pcb, TF_ACK_NOW)
```

**Why:** The original stretch-ACK logic delays the ACK for odd-count
segment bursts by up to one `tcp_fasttmr` tick (250 ms in our build).
On the in-memory TUN flow, ACK packets cost essentially nothing — they
take the `netif_output → outputPackets → writePackets` path back to
the iOS kernel with no real link in between — while the 250 ms tail is
a direct user-visible latency tax on short flows (HTTP GET headers,
TLS handshake tail segments, single-segment request/response).

Doubling the ACK rate on bulk upload is negligible; the cost is a few
hundred extra ~40-byte ACK packets per second at 1 MB/s upload.

**What is unaffected:**

- `tcp_ack_now` is untouched; call sites that explicitly want an
  immediate ACK still behave the same.
- `TF_ACK_DELAY` is still read by `tcp_fasttmr` (`src/core/tcp.c`) and
  still set by `tcp_send_empty_ack` as the ERR_MEM retry hook. Those
  paths keep working because they don't depend on `tcp_ack` ever
  setting the flag; they set it themselves when a send fails and rely
  on the next fasttmr tick to retry.
- Nagle on the send side and the persist timer are unrelated.

**Upgrade notes:** When bumping lwIP, re-apply. Search for
`#define tcp_ack(pcb)` in `src/include/lwip/priv/tcp_priv.h`.

---

## Non-patch customizations

The lwIP build is additionally tuned via `port/lwipopts.h`, using only
standard lwIP options (no source edits). Notable entries relevant to
the TUN deployment:

- `LWIP_TCP_CALC_INITIAL_CWND(mss) = 32 · mss` — a large initial cwnd.
  Redundant given the cwnd patch above, but harmless to keep as belt
  and suspenders.
- `TCP_WND`, `TCP_SND_BUF = 1024 · TCP_MSS` with `LWIP_WND_SCALE = 1`,
  `TCP_RCV_SCALE = 7` — high-throughput windowing.
- `CHECKSUM_CHECK_IP/TCP/UDP/ICMP/ICMP6 = 0` on input — we trust the
  packets the iOS TUN interface hands us.
- `TCP_QUEUE_OOSEQ = 0`, `LWIP_TCP_SACK_OUT = 0` — out-of-order
  receive and SACK output are dead code on an in-memory flow. Disabled
  together since `init.c` requires it; also drops the
  `TCP_OOSEQ_MAX_BYTES`, `TCP_OOSEQ_MAX_PBUFS`, and
  `LWIP_TCP_MAX_SACK_NUM` options.
- `NO_SYS = 1`, `LWIP_CALLBACK_API = 1`, `LWIP_SINGLE_NETIF = 1` —
  single-netif, callback-driven, no OS threading layer.
- **Nagle is disabled per-PCB** in `lwip_bridge.c` via
  `tcp_nagle_disable(newpcb)` on every `tcp_accept`, for the same
  reason as the delayed-ACK patch above (small writes on an in-memory
  flow don't benefit from coalescing).

These knobs live entirely in `port/lwipopts.h` / `lwip_bridge.c`; no
edit to the vendored lwIP source is required to tune them.
