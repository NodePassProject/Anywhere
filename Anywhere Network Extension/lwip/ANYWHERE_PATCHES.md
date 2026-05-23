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

### 3. `src/core/tcp_in.c` + `src/include/lwip/priv/tcp_priv.h` — defer per-segment `tcp_output` during input batch

**What:** At the end of `tcp_input()`, the implicit `tcp_output(pcb)`
that flushes queued ACKs / `pcb->unsent` is gated on a global flag:

```c
/* before */
tcp_output(pcb);

/* after */
if (!lwip_anywhere_input_batch_mode) {
  tcp_output(pcb);
}
```

The flag is declared in `tcp_priv.h` (`extern int lwip_anywhere_input_batch_mode;`)
and defined in `lwip_bridge.c`. The bridge sets it to 1 around each
kernel `readPackets` batch — see `lwip_bridge_input_batch_begin/end` —
and `_end` then issues `tcp_output(pcb)` once per active PCB.

**Why:** Patch 2 forces immediate ACK on every received segment
(`TF_ACK_NOW`). Combined with the `tcp_output` call at the bottom of
`tcp_input`, this produces one ACK packet per input segment. The bridge
processes one kernel `readPackets` callback as a tight loop of
`lwip_bridge_input` calls (typical batch under bulk upload is 10-22
packets, observed maximum 64). One ACK per segment in that loop emits
N ACK packets where 1 would convey the same cumulative acknowledgement
number to the peer.

Before the patch, on a saturated upload we observed ~980 ACK packets
per 1000 received segments and an average input batch of 22 packets —
i.e. ~22 ACK packets where 1 would have sufficed (22× coalescing
potential).

After the patch, `TF_ACK_NOW` accumulates per PCB through the batch
(the flag is idempotent — multiple sets are no-ops) and `_end` collapses
to one ACK packet per PCB. For a typical upload that concentrates on a
single connection, that drops ACK rate from ~1900/s to ~85/s at the
same throughput, with all the per-packet machinery (netif_output,
outputBufferLock, drainOutputLoop, writePackets, batched release)
scaled down proportionally.

**What is unaffected:**

- ACK semantics: `TF_ACK_NOW` is still set per segment. The peer sees
  exactly the same cumulative ACK number, just delivered in fewer
  packets. RFC 1122's "ACK within 500 ms" is met easily — a batch
  completes in microseconds.
- Patch 2's original motivation (no 250 ms delayed-ACK tail on
  download): preserved. The deferral is bounded by one input batch
  duration, not by `tcp_fasttmr`.
- `tcp_send_empty_ack`, `tcp_rst`, and the zero-window-probe response
  in `tcp_input` itself remain direct calls; they don't go through the
  end-of-loop `tcp_output` gate.
- Retransmission, RTO, persist timer, Nagle: unchanged.
- Pending payload (`pcb->unsent`) deferred from "mid-batch" to
  "end-of-batch" — sub-millisecond additional latency under load,
  recovered by larger `tcp_output` segments since more snd_buf has
  been freed by the accumulated ACKs.

**Upgrade notes:** When bumping the vendored lwIP version, re-apply
both halves:

- `src/core/tcp_in.c`: search for `/* Try to send something out. */`
  near the bottom of `tcp_input()`.
- `src/include/lwip/priv/tcp_priv.h`: search for `lwip_anywhere_input_batch_mode`.

The flag definition (`int lwip_anywhere_input_batch_mode = 0;`) and the
begin/end functions live in `lwip/lwip_bridge.c` outside vendored lwIP
and don't need re-applying.

---

### 4. `src/core/tcp_in.c` + `src/include/lwip/priv/tcp_priv.h` — SYN-level reject filter

**What:** In `tcp_listen_input`, immediately after the `TCP_SYN` flag
check, call a host-provided filter that returns one of
`PASS` / `DROP` / `RESET`. `DROP` returns silently (the SYN goes
unanswered, client times out); `RESET` responds with a RST
(`tcp_rst_netif(netif, 0, seqno + tcplen, ...)`); `PASS` falls
through to the normal allocation + SYN-ACK path.

```c
} else if (flags & TCP_SYN) {
  if (lwip_anywhere_tcp_syn_filter != NULL) {
    /* extract src/dst bytes from ip_current_*_addr() */
    int verdict = lwip_anywhere_tcp_syn_filter(...);
    if (verdict == LWIP_ANYWHERE_SYN_DROP)  { return; }
    if (verdict == LWIP_ANYWHERE_SYN_RESET) {
      tcp_rst_netif(ip_data.current_input_netif, 0, seqno + tcplen,
                    ip_current_dest_addr(), ip_current_src_addr(),
                    tcphdr->dest, tcphdr->src);
      return;
    }
  }
  /* original code path: tcp_alloc, send SYN-ACK, etc. */
```

The filter pointer is declared in `tcp_priv.h`
(`extern int (*lwip_anywhere_tcp_syn_filter)(...)`) and defined in
`lwip_bridge.c`; Swift registers it via
`lwip_bridge_set_tcp_syn_filter_fn`.

**Why:** Without this patch, every rejected connection still completes
the 3-way handshake (lwIP's `tcp_accept_cb` fires only after the
final ACK). The host then has to close — and a close in the middle of
a still-fresh ESTABLISHED state is ambiguous to TLS / HTTP clients
(they treat it as a transient peer drop and retry aggressively). It
also wastes a SYN-ACK + final ACK + an accept_cb dispatch on every
rejected SYN, which is significant for misbehaving apps that retry in
tight loops on blocked hostnames.

By short-circuiting at SYN we get the same semantics as `sing-tun`'s
system stack / gvisor `Complete(sendReset=true)`: the client sees a
plain TCP `ECONNREFUSED` for `RESET` or a connect timeout for `DROP`,
which is the natural "server doesn't exist / refuses" signal that
client TCP stacks and apps already know how to handle without
retrying.

**What is unaffected:**

- SNI-based rejects are not visible at SYN time (the ClientHello
  arrives later), so they keep landing in `LWIPTCPConnection` and
  emit a fatal TLS Alert post-handshake (`rejectWithTLSAlert`).
- If the filter pointer is `NULL` (e.g. Swift hasn't registered yet),
  the patch is a no-op — `tcp_listen_input` proceeds exactly as
  upstream lwIP.
- `LISTEN`/`SYN_RCVD`/`ESTABLISHED` state machine, retransmission,
  backlog accounting: all unchanged.
- IPv4 and IPv6 are handled symmetrically via `IP_IS_V6` and
  `ip_2_ip4` / `ip_2_ip6`.

**RST argument note:** `seqno + tcplen` follows the same convention
the function uses a few lines above for the "ACK in LISTEN" RST
response. For a SYN with no payload `tcplen` is 1 (SYN counts as one
byte), giving the standard `ack = client_seq + 1` RST. For a SYN
carrying TFO data it correctly covers the payload as well.

**Upgrade notes:** When bumping the vendored lwIP version, re-apply:

- `src/core/tcp_in.c`: search for `else if (flags & TCP_SYN)` in
  `tcp_listen_input`.
- `src/include/lwip/priv/tcp_priv.h`: search for
  `lwip_anywhere_tcp_syn_filter`.

The pointer storage and bridge setter live in `lwip/lwip_bridge.c` and
don't need re-applying.

---

## UDP handled outside lwIP (`LWIP_UDP = 0`)

UDP is not handled by lwIP at all. `port/lwipopts.h` sets `LWIP_UDP 0`, so
`src/core/udp.c` compiles to nothing and lwIP is built TCP-only (ICMP stays
on). UDP datagrams are intercepted in Swift before they ever reach lwIP:

- **Inbound:** `LWIPStack+IO.startReadingPackets` peeks each packet's IP
  protocol and routes UDP to `UDPPacket.parse` → `LWIPStack+UDP.handleInboundUDP`
  (the logic that used to live in the bridge's `udp_recv_cb`). Only TCP/ICMP
  are fed to `lwip_bridge_input`.
- **Outbound:** responses are built by `UDPPacket.build` (IP+UDP header +
  checksums, mirroring the ICMP builder) and queued via
  `LWIPStack.enqueueOutbound`, replacing the former `lwip_bridge_udp_sendto`.

Parity with the old lwIP path is preserved by `UDPPacket.parse`: fragments and
IPv6 extension headers are dropped, matching lwIP's `IP_REASSEMBLY` /
`LWIP_IPV6_REASS` = 0 posture.

**Consequence for upgrades:** there is an in-source udp.c modification
(`/* Anywhere patch: fallback to wildcard PCB with local_port == 0 */`). It is
now **inert** — the whole file is `#if LWIP_UDP` — and does **not** need
re-applying. If you ever re-enable `LWIP_UDP`, you would also have to restore
the UDP catch-all listeners and `udp_recv_cb` in `lwip_bridge.c` (removed when
UDP moved to Swift); prefer keeping UDP in Swift.
