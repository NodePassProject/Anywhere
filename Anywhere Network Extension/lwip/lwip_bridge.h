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

/* TCP accept: new TCP connection accepted (returns opaque pointer stored as PCB arg)
 * IP addresses are raw bytes: 4 bytes for IPv4, 16 bytes for IPv6 */
typedef void *(*lwip_tcp_accept_fn)(const void *src_ip, uint16_t src_port,
                                     const void *dst_ip, uint16_t dst_port,
                                     int is_ipv6, void *pcb);

/* TCP recv: data received on a TCP connection */
typedef void (*lwip_tcp_recv_fn)(void *conn, const void *data, int len);

/* TCP sent: send buffer space freed (bytes acknowledged) */
typedef void (*lwip_tcp_sent_fn)(void *conn, uint16_t len);

/* TCP err: TCP error or connection aborted */
typedef void (*lwip_tcp_err_fn)(void *conn, int err);

/* UDP recv: UDP datagram received
 * IP addresses are raw bytes: 4 bytes for IPv4, 16 bytes for IPv6 */
typedef void (*lwip_udp_recv_fn)(const void *src_ip, uint16_t src_port,
                                  const void *dst_ip, uint16_t dst_port,
                                  int is_ipv6, const void *data, int len);

/* --- Callback registration --- */
void lwip_bridge_set_output_fn(lwip_output_fn fn);
void lwip_bridge_set_tcp_accept_fn(lwip_tcp_accept_fn fn);
void lwip_bridge_set_tcp_recv_fn(lwip_tcp_recv_fn fn);
void lwip_bridge_set_tcp_sent_fn(lwip_tcp_sent_fn fn);
void lwip_bridge_set_tcp_err_fn(lwip_tcp_err_fn fn);
void lwip_bridge_set_udp_recv_fn(lwip_udp_recv_fn fn);

/* --- Lifecycle --- */
void lwip_bridge_init(void);
void lwip_bridge_shutdown(void);

/* Abort every active TCP PCB and clear TIME_WAIT, keeping the netif and
 * listeners intact. Used on device wake to invalidate outbound proxy sockets
 * the kernel killed during sleep without a full stack rebuild. */
void lwip_bridge_abort_all_tcp(void);

/* --- Packet input (from TUN) --- */
void lwip_bridge_input(const void *data, int len);

/* --- TCP operations (called from Swift on lwipQueue) --- */
int  lwip_bridge_tcp_write(void *pcb, const void *data, uint16_t len);
void lwip_bridge_tcp_output(void *pcb);
void lwip_bridge_tcp_recved(void *pcb, uint16_t len);
void lwip_bridge_tcp_close(void *pcb);
void lwip_bridge_tcp_abort(void *pcb);
int  lwip_bridge_tcp_sndbuf(void *pcb);
int  lwip_bridge_tcp_snd_queuelen(void *pcb);

/* --- UDP operations ---
 * IP addresses are raw bytes: 4 bytes for IPv4, 16 bytes for IPv6 */
void lwip_bridge_udp_sendto(const void *src_ip_bytes, uint16_t src_port,
                             const void *dst_ip_bytes, uint16_t dst_port,
                             int is_ipv6,
                             const void *data, int len);

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
