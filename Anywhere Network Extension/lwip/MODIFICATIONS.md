# Anywhere downstream modifications to lwIP

This directory contains a vendored copy of **lwIP 2.2.2** (upstream:
<https://savannah.nongnu.org/projects/lwip/>, modified-BSD 3-clause).

All source-level downstream code is gated by the single compile-time define

```c
#define ANYWHERE_LWIP_AGGRESSIVE_CC
```

set in `port/lwipopts.h`. With that define unset, every modified source file
below compiles to exactly the upstream behavior (each patch is an
`#ifdef / #else / #endif` wrapper around the original line — no upstream line
is deleted or rewritten outside an `#ifdef` block).

Every downstream hunk is bracketed with the sentinel pair

```
/* --- BEGIN ANYWHERE PATCH: <short reason> ----------------------------- */
...
/* --- END ANYWHERE PATCH ------------------------------------------------- */
```

so `grep -rn 'ANYWHERE PATCH' "Anywhere Network Extension/lwip"` over the
tree lists every site.

---

## Feature: aggressive TCP congestion control

Purpose: lwIP ships Reno-style congestion control (RFC 5681 + RFC 3465). In
our deployment — a TUN-interface VPN where the lwIP stack only terminates
the inner tunneled TCP flows between the device and the tunnel endpoint —
Reno's conservatism costs throughput without buying much fairness:

- The other flows on the device's physical uplink are not ours to be fair
  with; they are the host's and the kernel already runs its own CC there.
- Inside the tunnel, the only competing flows are other lwIP flows from the
  same user, so softer MD / faster ramp just means we reach steady state
  faster without starving siblings.
- The tunnel's underlying transport (QUIC with BBR, or TLS-over-TCP with the
  host kernel's CC) already does its own pacing on the outside; our inner
  lwIP CC is stacked on top of that.

Three deviations from stock lwIP, selected in order of increasing cost to
fairness:

### 1. IW10 — RFC 6928 initial congestion window

Stock: `LWIP_TCP_CALC_INITIAL_CWND(mss) = min(4*MSS, max(2*MSS, 4380))`
(RFC 2581), typically 3 MSS in practice.

Downstream: `10 * MSS` — matches RFC 6928 / Linux default since 2.6.39.

Biggest win for short flows (HTTP responses, TLS handshakes, small DNS
replies) because they never leave slow start.

This override lives only in `port/lwipopts.h`, a project-owned file that
redefines the upstream macro's default. No upstream source file is touched.
It is *unconditional* — not gated by `ANYWHERE_LWIP_AGGRESSIVE_CC` — because
it affects only a header macro with no branch cost.

### 2. Softer multiplicative decrease (β = 0.85)

Stock: on loss, `ssthresh = eff_wnd / 2` (Reno / NewReno).

Downstream: `ssthresh = eff_wnd * 17 / 20` — more aggressive than CUBIC's
0.7; in HighSpeed / lossy-link controller territory. Chosen because the
VPN's inner tunnel carries mostly non-congestion loss (wireless / TUN queue
drops), so a deeper backoff than 0.85 overreacts and wastes throughput.
The intermediate multiply is widened to `u64_t` so large window-scaled
`eff_wnd` values don't wrap.

Applied at both loss events: fast retransmit (3 dup-ACKs) and RTO. The RTO
path still resets `cwnd = 1 MSS` (no change); only `ssthresh` is softened,
so slow start comes back up a bit further before re-entering CA.

### 3. Scalable congestion avoidance (+8×MSS per RTT)

Stock: per RFC 3465 §2.1 byte-counting, `cwnd += MSS` once `bytes_acked >=
cwnd` — i.e. +1 MSS per RTT in steady state.

Downstream: `cwnd += 8 * MSS` — +8 MSS per RTT. Crude scalable-TCP-lite;
not loss-adaptive like CUBIC's cubic function, but trivially correct. At
8× the stock ramp, CA recovers the β=0.85 cut (~19 MSS) in 2–3 RTTs. Past
this point `TCP_SND_BUF` / peer rwnd caps matter more than the CA constant.

---

### Files modified

| File | Sections | Upstream-diff sentinel |
|---|---|---|
| `port/lwipopts.h`                | adds `ANYWHERE_LWIP_AGGRESSIVE_CC` + `LWIP_TCP_CALC_INITIAL_CWND` override | n/a (project-owned file) |
| `src/core/tcp_out.c`             | β=0.85 in `tcp_rexmit_fast` (was `/2`)                                     | `ANYWHERE PATCH: softer MD on fast-retransmit (β=0.85)` |
| `src/core/tcp.c`                 | β=0.85 in `tcp_slowtmr` RTO branch (was `>> 1`)                            | `ANYWHERE PATCH: softer MD on RTO (β=0.85)` |
| `src/core/tcp_in.c`              | CA increase `+= 8*MSS` in `tcp_receive` (was `+= MSS`)                     | `ANYWHERE PATCH: scalable CA increase (+8*MSS per RTT)` |

### Functions modified

| Symbol | File | Upstream line (v2.2.2) | Change |
|---|---|---|---|
| `tcp_rexmit_fast`  | `src/core/tcp_out.c` | 1801 | On successful fast retransmit, set `ssthresh = 0.85 * min(cwnd, snd_wnd)` instead of `/2`. Existing floor (`ssthresh >= 2*MSS`) is unchanged and still applies. |
| `tcp_slowtmr`      | `src/core/tcp.c`     | 1301 | On RTO, set `ssthresh = 0.85 * eff_wnd` instead of `eff_wnd >> 1`. Existing floor (`ssthresh >= 2*MSS`) and `cwnd = MSS` reset are unchanged. |
| `tcp_receive`      | `src/core/tcp_in.c`  | 1292 | In the congestion-avoidance branch of `TCP_WND_INC(pcb->cwnd, ...)`, increase by `8*MSS` per RTT instead of `MSS`. Slow-start branch above (lines 1283–1285) is unchanged. |

### How to revert to stock upstream

Comment out `#define ANYWHERE_LWIP_AGGRESSIVE_CC` in `port/lwipopts.h`.
(1) remains active because it is a separate macro override. To revert (1)
as well, also remove the `LWIP_TCP_CALC_INITIAL_CWND` definition from
`port/lwipopts.h`; lwIP will then fall back to the upstream default in
`tcp.c`.
