//
//  ngtcp2_swift_bridge.h
//  Anywhere
//
//  Created by Argsment Limited on 4/10/26.
//

#ifndef NGTCP2_SWIFT_BRIDGE_H
#define NGTCP2_SWIFT_BRIDGE_H

#include <ngtcp2/ngtcp2.h>
#include "shared.h"
/* Exposes `ngtcp2_conn_stat` (cwnd / pacing_interval_m / smoothed_rtt / …)
 * to Swift so BrutalCongestionControl can read and write the fields the
 * ngtcp2 CC callbacks hand it. Safe to include from Swift — this header
 * only depends on the public ngtcp2.h and a plain enum. */
#include "ngtcp2_conn_stat.h"

/* `ngtcp2_cc`, `ngtcp2_cc_pkt` and `ngtcp2_cc_ack` live in the internal
 * `ngtcp2_cc.h` which transitively pulls in ngtcp2-crypto types that we
 * don't want to bridge into Swift. Forward-declare them as opaque so the
 * extern prototypes below type-check everywhere without leaking those
 * dependencies. Swift sees these as `OpaquePointer`s; the C side that
 * implements the trampolines pulls in `ngtcp2_cc.h` normally. */
typedef struct ngtcp2_cc ngtcp2_cc;
typedef struct ngtcp2_cc_pkt ngtcp2_cc_pkt;
typedef struct ngtcp2_cc_ack ngtcp2_cc_ack;

/* Wrappers for versioned API macros */

static inline int ngtcp2_swift_conn_client_new(
    ngtcp2_conn **pconn, const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
    const ngtcp2_path *path, uint32_t version,
    const ngtcp2_callbacks *callbacks, const ngtcp2_settings *settings,
    const ngtcp2_transport_params *params, const ngtcp2_mem *mem,
    void *user_data) {
  return ngtcp2_conn_client_new(pconn, dcid, scid, path, version,
                                callbacks, settings, params, mem, user_data);
}

static inline void ngtcp2_swift_settings_default(ngtcp2_settings *settings) {
  ngtcp2_settings_default(settings);
}

static inline void ngtcp2_swift_transport_params_default(
    ngtcp2_transport_params *params) {
  ngtcp2_transport_params_default(params);
}

static inline ngtcp2_ssize ngtcp2_swift_conn_write_pkt(
    ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi,
    uint8_t *dest, size_t destlen, ngtcp2_tstamp ts) {
  return ngtcp2_conn_write_pkt(conn, path, pi, dest, destlen, ts);
}

static inline int ngtcp2_swift_conn_read_pkt(
    ngtcp2_conn *conn, const ngtcp2_path *path, const ngtcp2_pkt_info *pi,
    const uint8_t *pkt, size_t pktlen, ngtcp2_tstamp ts) {
  return ngtcp2_conn_read_pkt(conn, path, pi, pkt, pktlen, ts);
}

static inline ngtcp2_ssize ngtcp2_swift_conn_writev_stream(
    ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi,
    uint8_t *dest, size_t destlen, ngtcp2_ssize *pdatalen,
    uint32_t flags, int64_t stream_id,
    const ngtcp2_vec *datav, size_t datavcnt, ngtcp2_tstamp ts) {
  return ngtcp2_conn_writev_stream(conn, path, pi, dest, destlen,
                                    pdatalen, flags, stream_id,
                                    datav, datavcnt, ts);
}

static inline const ngtcp2_transport_params *ngtcp2_swift_conn_get_remote_transport_params(
    ngtcp2_conn *conn) {
  return ngtcp2_conn_get_remote_transport_params(conn);
}

static inline ngtcp2_ssize ngtcp2_swift_conn_write_datagram(
    ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi,
    uint8_t *dest, size_t destlen, int *paccepted,
    uint32_t flags, uint64_t dgram_id,
    const uint8_t *data, size_t datalen, ngtcp2_tstamp ts) {
  return ngtcp2_conn_write_datagram(conn, path, pi, dest, destlen,
                                     paccepted, flags, dgram_id,
                                     data, datalen, ts);
}

/* ----- Brutal CC hook -----------------------------------------------------
 *
 * Hysteria v2 runs a custom congestion controller ("Brutal") that picks a
 * target send rate rather than probing for one. Since ngtcp2 doesn't expose a
 * plug-in CC API, we initialize `conn` with a built-in CC (CUBIC, via
 * `settings.cc_algo`) and then overwrite the CC callback table with Swift
 * trampolines. The underlying CC-specific state (cubic_vars, etc.) is simply
 * left untouched — none of Brutal's callbacks look at it.
 *
 * The Swift side defines the trampolines via `@_cdecl`; we forward-declare
 * them here so the install helper can assign them. The `cc` pointer that
 * trampolines receive matches `&conn->cc` of the connection being driven,
 * which Swift uses as a key to locate the `BrutalCongestionControl` instance.
 */

extern void ngtcp2_swift_brutal_on_pkt_acked(
    ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
    const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts);

extern void ngtcp2_swift_brutal_on_pkt_lost(
    ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
    const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts);

extern void ngtcp2_swift_brutal_on_ack_recv(
    ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
    const ngtcp2_cc_ack *ack, ngtcp2_tstamp ts);

extern void ngtcp2_swift_brutal_on_pkt_sent(
    ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
    const ngtcp2_cc_pkt *pkt);

extern void ngtcp2_swift_brutal_reset(
    ngtcp2_cc *cc, ngtcp2_conn_stat *cstat, ngtcp2_tstamp ts);

/// Overwrites `conn`'s CC callback table with Swift Brutal trampolines and
/// returns the `ngtcp2_cc *` Swift should use as a registry key. Defined in
/// `ngtcp2_swift_brutal.c` — not inlined here because reaching into
/// `conn->cc` pulls in ngtcp2-internal crypto types that we don't want
/// bridged into Swift.
ngtcp2_cc *ngtcp2_swift_install_brutal(ngtcp2_conn *conn);

#endif /* NGTCP2_SWIFT_BRIDGE_H */
