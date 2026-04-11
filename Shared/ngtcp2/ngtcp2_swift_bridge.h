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

#endif /* NGTCP2_SWIFT_BRIDGE_H */
