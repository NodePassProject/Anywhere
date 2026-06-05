#ifndef LWIP_BRIDGE_H
#define LWIP_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

/* --- Callback types (implemented in Swift with @convention(c)) --- */

/* Release callback: called by Swift after the output packet's `Data` is
 * released. `release_ctx` is whatever the bridge passed in `lwip_output_fn`'s
 * `release_ctx` argument — either the underlying `pbuf*` (zero-copy single-pbuf
 * path, freed via `pbuf_free`) or a `mem_malloc`'d buffer (chained-pbuf flatten
 * path, freed via `mem_free`). MUST be invoked on `lwipQueue` since both
 * `pbuf_free` and `mem_free` are not thread-safe under NO_SYS=1. */
typedef void (*lwip_release_fn)(void *release_ctx);

/* Netif output: lwIP wants to send an IP packet back to the TUN interface.
 *
 * Swift constructs `Data(bytesNoCopy: data, count: len, deallocator: ...)` and
 * the deallocator hops to `lwipQueue` to call `release(release_ctx)`. This
 * lets `NEPacketTunnelFlow.writePackets` consume the bytes directly out of
 * lwIP's pbuf payload (or a flattened chain copy) without an extra
 * `Data(bytes:count:)` memcpy. */
typedef void (*lwip_output_fn)(const void *data, int len, int is_ipv6,
                                void *release_ctx, lwip_release_fn release);

/* TCP accept: new TCP connection accepted. Returning a non-NULL pointer
 * stores it as the PCB's tcp_arg; returning NULL aborts (RST). Rule-based
 * rejects that can be classified before the handshake (IP-CIDR / fake-IP)
 * are handled by `lwip_tcp_syn_filter_fn` at SYN time so they never reach
 * this callback. SNI-based rejects, which require the ClientHello, are
 * still handled inside the connection after it is accepted.
 *
 * IP addresses are raw bytes: 4 bytes for IPv4, 16 bytes for IPv6. */
typedef void *(*lwip_tcp_accept_fn)(const void *src_ip, uint16_t src_port,
                                     const void *dst_ip, uint16_t dst_port,
                                     int is_ipv6, void *pcb);

/* SYN filter: lets the host decide drop/reset/passthrough for an incoming
 * SYN before lwIP allocates a pcb or sends SYN-ACK. Returns one of the
 * `LWIP_BRIDGE_SYN_*` verdicts below. */
#define LWIP_BRIDGE_SYN_PASS  0
#define LWIP_BRIDGE_SYN_DROP  1
#define LWIP_BRIDGE_SYN_RESET 2
typedef int (*lwip_tcp_syn_filter_fn)(const void *src_ip, uint16_t src_port,
                                       const void *dst_ip, uint16_t dst_port,
                                       int is_ipv6);

/* TCP recv: data received on a TCP connection */
typedef void (*lwip_tcp_recv_fn)(void *conn, const void *data, int len);

/* TCP sent: send buffer space freed (bytes acknowledged) */
typedef void (*lwip_tcp_sent_fn)(void *conn, uint16_t len);

/* TCP err: TCP error or connection aborted */
typedef void (*lwip_tcp_err_fn)(void *conn, int err);

/* --- Callback registration --- */
void lwip_bridge_set_output_fn(lwip_output_fn fn);
void lwip_bridge_set_tcp_accept_fn(lwip_tcp_accept_fn fn);
void lwip_bridge_set_tcp_syn_filter_fn(lwip_tcp_syn_filter_fn fn);
void lwip_bridge_set_tcp_recv_fn(lwip_tcp_recv_fn fn);
void lwip_bridge_set_tcp_sent_fn(lwip_tcp_sent_fn fn);
void lwip_bridge_set_tcp_err_fn(lwip_tcp_err_fn fn);

/* --- Lifecycle --- */
void lwip_bridge_init(void);
void lwip_bridge_shutdown(void);

/* Abort every active TCP PCB and clear TIME_WAIT, keeping the netif and
 * listeners intact. The blanket RST is the right tool for a full stack
 * shutdown/restart; the network-recovery path uses lwip_bridge_for_each_tcp
 * for a gentler, per-connection close instead. */
void lwip_bridge_abort_all_tcp(void);

/* Iterate every active TCP PCB, invoking `fn` with each PCB's Swift
 * callback_arg (the retained TCPConnection, or NULL if already cleared).
 * `next` is captured before each call, so `fn` may gracefully close or abort
 * the PCB it is handed; it must not touch other PCBs. The recovery path uses
 * this to FIN idle legs and let lwIP downgrade in-flight legs to RST, rather
 * than the blanket RST of lwip_bridge_abort_all_tcp. */
void lwip_bridge_for_each_tcp(void (*fn)(void *arg));

/* Count active TCP PCBs — connections in the `tcp_active_pcbs` list
 * (established, connecting, and closing). LISTEN pcbs (`tcp_listen_pcbs`) and
 * TIME_WAIT pcbs (`tcp_tw_pcbs`) are excluded, so the result tracks live
 * app-facing connections. Must be called on lwipQueue, like the other
 * `tcp_active_pcbs` walkers; surfaced as the live TCP connection-count stat. */
int lwip_bridge_active_tcp_count(void);

/* --- Packet input (from TUN) ---
 *
 * Bracket a kernel readPackets batch with `_batch_begin` / `_batch_end`.
 * While open, the vendored tcp_in.c patch suppresses the per-segment
 * `tcp_output(pcb)` flush; `_end` then calls `tcp_output` once per
 * active PCB, coalescing accumulated TF_ACK_NOW flags into one ACK
 * per PCB. See lwip/ANYWHERE_PATCHES.md (Patch 3). */
void lwip_bridge_input_batch_begin(void);
void lwip_bridge_input_batch_end(void);
void lwip_bridge_input(const void *data, int len);

/* --- TCP operations (called from Swift on lwipQueue) --- */
int  lwip_bridge_tcp_write(void *pcb, const void *data, uint16_t len);
void lwip_bridge_tcp_output(void *pcb);
void lwip_bridge_tcp_recved(void *pcb, uint16_t len);
void lwip_bridge_tcp_close(void *pcb);
void lwip_bridge_tcp_abort(void *pcb);
int  lwip_bridge_tcp_sndbuf(void *pcb);
int  lwip_bridge_tcp_snd_queuelen(void *pcb);

/* UDP is handled in Swift (UDPPacket / TunnelStack+UDP), so lwIP is built
 * TCP-only (LWIP_UDP=0) and exposes no UDP bridge entry points. */

/* --- Timer --- */
void lwip_bridge_check_timeouts(void);

/* --- IP address utility --- */

/// Convert raw IP address bytes to a null-terminated string.
/// @param addr Raw IP bytes (4 for IPv4, 16 for IPv6)
/// @param is_ipv6 Non-zero for IPv6
/// @param out Output buffer (must be >= 46 bytes / INET6_ADDRSTRLEN)
/// @param out_len Size of output buffer
/// @return Pointer to out on success, NULL on failure
const char *lwip_ip_to_string(const void *addr, int is_ipv6,
                               char *out, size_t out_len);

#endif /* LWIP_BRIDGE_H */
