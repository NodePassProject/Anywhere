//
//  ngtcp2_swift_brutal.c
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

#include "ngtcp2_conn.h"
#include "ngtcp2_cc.h"
#include "ngtcp2_swift_bridge.h"

/* Forward-declare the Swift @_cdecl'd trampolines. Swift emits matching C
 * symbols; see BrutalCongestionControl.swift. */
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

ngtcp2_cc *ngtcp2_swift_install_brutal(ngtcp2_conn *conn) {
  ngtcp2_cc *cc = &conn->cc;
  cc->on_pkt_acked = ngtcp2_swift_brutal_on_pkt_acked;
  cc->on_pkt_lost = ngtcp2_swift_brutal_on_pkt_lost;
  cc->on_ack_recv = ngtcp2_swift_brutal_on_ack_recv;
  cc->on_pkt_sent = ngtcp2_swift_brutal_on_pkt_sent;
  cc->reset = ngtcp2_swift_brutal_reset;
  /* Brutal handles loss through on_pkt_lost; other congestion events do
   * not affect cwnd. NULL'ing these hooks is allowed by ngtcp2_cc.h
   * ("All callback functions are optional"). */
  cc->congestion_event = NULL;
  cc->on_spurious_congestion = NULL;
  cc->on_persistent_congestion = NULL;
  return cc;
}
