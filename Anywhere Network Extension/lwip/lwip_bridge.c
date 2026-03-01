#include "lwip_bridge.h"

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/udp.h"
#include "lwip/timeouts.h"
#include "lwip/ip.h"
#include "lwip/ip_addr.h"

#include <string.h>
#include <arpa/inet.h>
#include <os/log.h>

static os_log_t s_log = NULL;

/* ========================================================================
 *  Registered callbacks (set by Swift)
 * ======================================================================== */

static lwip_output_fn     s_output_fn     = NULL;
static lwip_tcp_accept_fn s_tcp_accept_fn = NULL;
static lwip_tcp_recv_fn   s_tcp_recv_fn   = NULL;
static lwip_tcp_sent_fn   s_tcp_sent_fn   = NULL;
static lwip_tcp_err_fn    s_tcp_err_fn    = NULL;
static lwip_udp_recv_fn   s_udp_recv_fn   = NULL;

void lwip_bridge_set_output_fn(lwip_output_fn fn)     { s_output_fn = fn; }
void lwip_bridge_set_tcp_accept_fn(lwip_tcp_accept_fn fn) { s_tcp_accept_fn = fn; }
void lwip_bridge_set_tcp_recv_fn(lwip_tcp_recv_fn fn)   { s_tcp_recv_fn = fn; }
void lwip_bridge_set_tcp_sent_fn(lwip_tcp_sent_fn fn)   { s_tcp_sent_fn = fn; }
void lwip_bridge_set_tcp_err_fn(lwip_tcp_err_fn fn)     { s_tcp_err_fn = fn; }
void lwip_bridge_set_udp_recv_fn(lwip_udp_recv_fn fn)   { s_udp_recv_fn = fn; }

/* ========================================================================
 *  Network interface
 * ======================================================================== */

static struct netif tun_netif;
static struct tcp_pcb *tcp_listen_pcb_v4 = NULL;
static struct tcp_pcb *tcp_listen_pcb_v6 = NULL;
static struct udp_pcb *udp_listen_pcb_v4 = NULL;
static struct udp_pcb *udp_listen_pcb_v6 = NULL;

/* File-scope variable to capture UDP destination port during synchronous input processing.
 * Since NO_SYS=1, lwip_bridge_input() → ip_input() → udp_input() → udp_recv_cb
 * all execute synchronously on the same thread, so this is safe. */
static uint16_t s_current_udp_dst_port = 0;
static ip_addr_t s_current_udp_dst_ip;


/* ========================================================================
 *  Netif output callback
 * ======================================================================== */

static err_t netif_output_ip4(struct netif *netif, struct pbuf *p,
                               const ip4_addr_t *ipaddr) {
    (void)netif; (void)ipaddr;
    if (s_output_fn && p) {
        if (p->next != NULL) {
            void *buf = mem_malloc(p->tot_len);
            if (buf) {
                pbuf_copy_partial(p, buf, p->tot_len, 0);
                s_output_fn(buf, p->tot_len, 0);
                mem_free(buf);
            } else {
                os_log_error(s_log, "[Bridge] netif_output_ip4: mem_malloc failed for %u bytes", p->tot_len);
            }
        } else {
            s_output_fn(p->payload, p->tot_len, 0);
        }
    }
    return ERR_OK;
}

static err_t netif_output_ip6(struct netif *netif, struct pbuf *p,
                               const ip6_addr_t *ipaddr) {
    (void)netif; (void)ipaddr;
    if (s_output_fn && p) {
        if (p->next != NULL) {
            void *buf = mem_malloc(p->tot_len);
            if (buf) {
                pbuf_copy_partial(p, buf, p->tot_len, 0);
                s_output_fn(buf, p->tot_len, 1);
                mem_free(buf);
            } else {
                os_log_error(s_log, "[Bridge] netif_output_ip6: mem_malloc failed for %u bytes", p->tot_len);
            }
        } else {
            s_output_fn(p->payload, p->tot_len, 1);
        }
    }
    return ERR_OK;
}

static err_t tun_netif_init_fn(struct netif *netif) {
    netif->name[0] = 't';
    netif->name[1] = 'n';
    netif->mtu = 1400;
    netif->output = netif_output_ip4;
    netif->output_ip6 = netif_output_ip6;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

/* ========================================================================
 *  TCP callbacks
 * ======================================================================== */

/* Helper to extract raw IP bytes from ip_addr_t */
static void ip_addr_to_bytes(const ip_addr_t *addr, uint8_t *out, int *is_ipv6) {
    if (IP_IS_V6(addr)) {
        memcpy(out, ip_2_ip6(addr), 16);
        *is_ipv6 = 1;
    } else {
        memcpy(out, ip_2_ip4(addr), 4);
        *is_ipv6 = 0;
    }
}

/* Forward declarations for TCP callbacks used in tcp_accept_cb */
static err_t tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static err_t tcp_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t len);
static void  tcp_err_cb(void *arg, err_t err);

static err_t tcp_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err) {
    (void)arg; (void)err;
    if (!s_tcp_accept_fn || !newpcb) {
        os_log_error(s_log, "[Bridge] tcp_accept_cb: no accept fn or no pcb");
        return ERR_ABRT;
    }

    uint8_t src_bytes[16], dst_bytes[16];
    int is_ipv6 = 0;
    ip_addr_to_bytes(&newpcb->remote_ip, src_bytes, &is_ipv6);
    ip_addr_to_bytes(&newpcb->local_ip, dst_bytes, &is_ipv6);

    void *conn = s_tcp_accept_fn(src_bytes, newpcb->remote_port,
                                  dst_bytes, newpcb->local_port,
                                  is_ipv6, newpcb);
    if (!conn) {
        os_log_error(s_log, "[Bridge] tcp_accept_cb: Swift returned NULL conn, aborting");
        tcp_abort(newpcb);
        return ERR_ABRT;
    }

    tcp_arg(newpcb, conn);
    tcp_recv(newpcb, tcp_recv_cb);
    tcp_sent(newpcb, tcp_sent_cb);
    tcp_err(newpcb, tcp_err_cb);

    return ERR_OK;
}

static err_t tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    (void)err;
    if (!arg) {
        os_log_error(s_log, "[Bridge] tcp_recv_cb: arg is NULL, aborting");
        if (p) pbuf_free(p);
        return ERR_ABRT;
    }

    if (!p) {
        /* Remote closed connection (graceful FIN) */
        if (s_tcp_recv_fn) {
            s_tcp_recv_fn(arg, NULL, 0);
        }
        return ERR_OK;
    }

    if (s_tcp_recv_fn) {
        if (p->next != NULL) {
            void *buf = mem_malloc(p->tot_len);
            if (buf) {
                pbuf_copy_partial(p, buf, p->tot_len, 0);
                s_tcp_recv_fn(arg, buf, p->tot_len);
                mem_free(buf);
            } else {
                os_log_error(s_log, "[Bridge] tcp_recv_cb: mem_malloc failed for %u bytes", p->tot_len);
            }
        } else {
            s_tcp_recv_fn(arg, p->payload, p->tot_len);
        }
    }

    pbuf_free(p);
    return ERR_OK;
}

static err_t tcp_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    (void)tpcb;
    if (arg && s_tcp_sent_fn) {
        s_tcp_sent_fn(arg, len);
    }
    return ERR_OK;
}

static void tcp_err_cb(void *arg, err_t err) {
    /* PCB is already freed by lwIP when this is called */
    if (arg && s_tcp_err_fn) {
        s_tcp_err_fn(arg, (int)err);
    }
}

/* ========================================================================
 *  UDP callback
 * ======================================================================== */

static void udp_recv_cb(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                          const ip_addr_t *addr, u16_t port) {
    (void)arg; (void)pcb;
    if (!p || !s_udp_recv_fn) {
        if (p) pbuf_free(p);
        return;
    }

    uint8_t src_bytes[16], dst_bytes[16];
    int is_ipv6 = 0;
    ip_addr_to_bytes(addr, src_bytes, &is_ipv6);
    ip_addr_to_bytes(&s_current_udp_dst_ip, dst_bytes, &is_ipv6);

    if (p->next != NULL) {
        void *buf = mem_malloc(p->tot_len);
        if (buf) {
            pbuf_copy_partial(p, buf, p->tot_len, 0);
            s_udp_recv_fn(src_bytes, port,
                          dst_bytes, s_current_udp_dst_port,
                          is_ipv6, buf, p->tot_len);
            mem_free(buf);
        } else {
            os_log_error(s_log, "[Bridge] udp_recv_cb: mem_malloc failed for %u bytes", p->tot_len);
        }
    } else {
        s_udp_recv_fn(src_bytes, port,
                      dst_bytes, s_current_udp_dst_port,
                      is_ipv6, p->payload, p->tot_len);
    }

    pbuf_free(p);
}

/* ========================================================================
 *  Initialization / Shutdown
 * ======================================================================== */

void lwip_bridge_init(void) {
    s_log = os_log_create("com.argsment.Anywhere.Network-Extension", "LWIP-Bridge");

    lwip_init();

    /* Add TUN netif with 0.0.0.0/0 (catch-all for IPv4) */
    ip4_addr_t ipaddr, netmask, gw;
    IP4_ADDR(&ipaddr, 0, 0, 0, 0);
    IP4_ADDR(&netmask, 0, 0, 0, 0);
    IP4_ADDR(&gw, 0, 0, 0, 0);

    netif_add(&tun_netif, &ipaddr, &netmask, &gw, NULL, tun_netif_init_fn, ip_input);
    netif_set_default(&tun_netif);
    netif_set_up(&tun_netif);

    /* IPv6: set first address to :: (unspecified) for catch-all */
    ip6_addr_t ip6any;
    memset(&ip6any, 0, sizeof(ip6any));
    netif_ip6_addr_set(&tun_netif, 0, &ip6any);
    netif_ip6_addr_set_state(&tun_netif, 0, IP6_ADDR_VALID);

    /* --- TCP catch-all listeners --- */

    /* IPv4 TCP listener on port 0 (wildcard, see tcp_in.c patch) */
    tcp_listen_pcb_v4 = tcp_new();
    if (tcp_listen_pcb_v4) {
        tcp_bind(tcp_listen_pcb_v4, IP4_ADDR_ANY, 0);
        tcp_listen_pcb_v4 = tcp_listen(tcp_listen_pcb_v4);
        if (tcp_listen_pcb_v4) {
            /* Force port 0 for catch-all wildcard matching (tcp_bind assigns ephemeral) */
            tcp_listen_pcb_v4->local_port = 0;
            tcp_accept(tcp_listen_pcb_v4, tcp_accept_cb);
        } else {
            os_log_error(s_log, "[Bridge] TCP v4 tcp_listen() failed!");
        }
    } else {
        os_log_error(s_log, "[Bridge] TCP v4 tcp_new() failed!");
    }

    /* IPv6 TCP listener on port 0 (wildcard) */
    tcp_listen_pcb_v6 = tcp_new_ip_type(IPADDR_TYPE_V6);
    if (tcp_listen_pcb_v6) {
        tcp_bind(tcp_listen_pcb_v6, IP6_ADDR_ANY, 0);
        tcp_listen_pcb_v6 = tcp_listen(tcp_listen_pcb_v6);
        if (tcp_listen_pcb_v6) {
            tcp_listen_pcb_v6->local_port = 0;
            tcp_accept(tcp_listen_pcb_v6, tcp_accept_cb);
        } else {
            os_log_error(s_log, "[Bridge] TCP v6 tcp_listen() failed!");
        }
    } else {
        os_log_error(s_log, "[Bridge] TCP v6 tcp_new_ip_type() failed!");
    }

    /* --- UDP catch-all listeners --- */

    /* IPv4 UDP listener on port 0 (wildcard, see udp.c patch) */
    udp_listen_pcb_v4 = udp_new();
    if (udp_listen_pcb_v4) {
        udp_bind(udp_listen_pcb_v4, IP4_ADDR_ANY, 0);
        udp_listen_pcb_v4->local_port = 0;
        udp_recv(udp_listen_pcb_v4, udp_recv_cb, NULL);
    } else {
        os_log_error(s_log, "[Bridge] UDP v4 udp_new() failed!");
    }

    /* IPv6 UDP listener on port 0 (wildcard) */
    udp_listen_pcb_v6 = udp_new_ip_type(IPADDR_TYPE_V6);
    if (udp_listen_pcb_v6) {
        udp_bind(udp_listen_pcb_v6, IP6_ADDR_ANY, 0);
        udp_listen_pcb_v6->local_port = 0;
        udp_recv(udp_listen_pcb_v6, udp_recv_cb, NULL);
    } else {
        os_log_error(s_log, "[Bridge] UDP v6 udp_new_ip_type() failed!");
    }

}

void lwip_bridge_shutdown(void) {
    /* Abort all active TCP connections.
     * Keep callbacks intact so tcp_abort() fires the err callback, which
     * notifies the Swift LWIPTCPConnection (sets closed=true, cancels VLESS,
     * balances Unmanaged retain via takeRetainedValue in the callback).
     * tcp_abort() removes the PCB from tcp_active_pcbs, so we always grab
     * the new list head each iteration. */
    while (tcp_active_pcbs != NULL) {
        tcp_abort(tcp_active_pcbs);
    }

    /* Clean up TIME_WAIT PCBs. These have no active Swift connection (the
     * LWIPTCPConnection was already released during normal close), so we
     * just remove and free without firing callbacks. */
    while (tcp_tw_pcbs != NULL) {
        struct tcp_pcb *pcb = tcp_tw_pcbs;
        tcp_pcb_remove(&tcp_tw_pcbs, pcb);
        tcp_free(pcb);
    }

    if (tcp_listen_pcb_v4) { tcp_close(tcp_listen_pcb_v4); tcp_listen_pcb_v4 = NULL; }
    if (tcp_listen_pcb_v6) { tcp_close(tcp_listen_pcb_v6); tcp_listen_pcb_v6 = NULL; }
    if (udp_listen_pcb_v4) { udp_remove(udp_listen_pcb_v4); udp_listen_pcb_v4 = NULL; }
    if (udp_listen_pcb_v6) { udp_remove(udp_listen_pcb_v6); udp_listen_pcb_v6 = NULL; }
    netif_set_down(&tun_netif);
    netif_remove(&tun_netif);
}

/* ========================================================================
 *  Packet Input
 * ======================================================================== */

void lwip_bridge_input(const void *data, int len) {
    if (!data || len <= 0) return;

    /* Parse IP version for UDP destination capture */
    const uint8_t *pkt = (const uint8_t *)data;
    uint8_t version = (pkt[0] >> 4) & 0x0F;

    if (version == 4 && len >= 20) {
        uint8_t proto = pkt[9];
        uint8_t ihl = (pkt[0] & 0x0F) * 4;

        if (proto == 17 && len >= ihl + 8) {
            s_current_udp_dst_port = ((uint16_t)pkt[ihl + 2] << 8) | pkt[ihl + 3];
            ip4_addr_t dst4;
            memcpy(&dst4.addr, pkt + 16, 4);
            ip_addr_copy_from_ip4(s_current_udp_dst_ip, dst4);
        }
    } else if (version == 6 && len >= 40) {
        uint8_t proto = pkt[6];

        if (proto == 17 && len >= 48) {
            s_current_udp_dst_port = ((uint16_t)pkt[42] << 8) | pkt[43];
            ip6_addr_t dst6;
            memcpy(&dst6, pkt + 24, 16);
            ip_addr_copy_from_ip6(s_current_udp_dst_ip, dst6);
        }
    } else {
        return;
    }

    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_POOL);
    if (!p) {
        os_log_error(s_log, "[Bridge] input: pbuf_alloc failed for %d bytes", len);
        return;
    }

    pbuf_take(p, data, (u16_t)len);

    err_t input_err = tun_netif.input(p, &tun_netif);
    if (input_err != ERR_OK) {
        os_log_error(s_log, "[Bridge] input: ip_input err=%d", (int)input_err);
        pbuf_free(p);
    }
}

/* ========================================================================
 *  TCP Operations
 * ======================================================================== */

int lwip_bridge_tcp_write(void *pcb, const void *data, uint16_t len) {
    struct tcp_pcb *tpcb = (struct tcp_pcb *)pcb;
    err_t err = tcp_write(tpcb, data, len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        os_log_error(s_log, "[Bridge] tcp_write: err=%d len=%u sndbuf=%u",
                     (int)err, len, tcp_sndbuf(tpcb));
    }
    return (int)err;
}

void lwip_bridge_tcp_output(void *pcb) {
    tcp_output((struct tcp_pcb *)pcb);
}

void lwip_bridge_tcp_recved(void *pcb, uint16_t len) {
    tcp_recved((struct tcp_pcb *)pcb, len);
}

void lwip_bridge_tcp_close(void *pcb) {
    struct tcp_pcb *tpcb = (struct tcp_pcb *)pcb;
    tcp_arg(tpcb, NULL);
    tcp_recv(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_err(tpcb, NULL);
    err_t err = tcp_close(tpcb);
    if (err != ERR_OK) {
        os_log_error(s_log, "[Bridge] tcp_close failed (err=%d), falling back to abort", (int)err);
        tcp_abort(tpcb);
    }
}

void lwip_bridge_tcp_abort(void *pcb) {
    struct tcp_pcb *tpcb = (struct tcp_pcb *)pcb;
    tcp_arg(tpcb, NULL);
    tcp_recv(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_err(tpcb, NULL);
    tcp_abort(tpcb);
}

int lwip_bridge_tcp_sndbuf(void *pcb) {
    return (int)tcp_sndbuf((struct tcp_pcb *)pcb);
}

/* ========================================================================
 *  UDP Operations
 * ======================================================================== */

void lwip_bridge_udp_sendto(const void *src_ip_bytes, uint16_t src_port,
                             const void *dst_ip_bytes, uint16_t dst_port,
                             int is_ipv6,
                             const void *data, int len) {
    if (!data || len <= 0) return;

    /* Reconstruct ip_addr_t from raw bytes */
    ip_addr_t src_addr, dst_addr;
    if (is_ipv6) {
        memset(&src_addr, 0, sizeof(src_addr));
        memset(&dst_addr, 0, sizeof(dst_addr));
        memcpy(ip_2_ip6(&src_addr), src_ip_bytes, 16);
        IP_SET_TYPE_VAL(src_addr, IPADDR_TYPE_V6);
        memcpy(ip_2_ip6(&dst_addr), dst_ip_bytes, 16);
        IP_SET_TYPE_VAL(dst_addr, IPADDR_TYPE_V6);
    } else {
        memset(&src_addr, 0, sizeof(src_addr));
        memset(&dst_addr, 0, sizeof(dst_addr));
        memcpy(ip_2_ip4(&src_addr), src_ip_bytes, 4);
        IP_SET_TYPE_VAL(src_addr, IPADDR_TYPE_V4);
        memcpy(ip_2_ip4(&dst_addr), dst_ip_bytes, 4);
        IP_SET_TYPE_VAL(dst_addr, IPADDR_TYPE_V4);
    }

    struct udp_pcb *pcb = udp_new_ip_type(is_ipv6 ? IPADDR_TYPE_V6 : IPADDR_TYPE_V4);
    if (!pcb) {
        os_log_error(s_log, "[Bridge] udp_sendto: udp_new_ip_type failed");
        return;
    }

    err_t bind_err = udp_bind(pcb, &src_addr, src_port);
    if (bind_err != ERR_OK) {
        os_log_error(s_log, "[Bridge] udp_sendto: udp_bind failed err=%d", (int)bind_err);
        udp_remove(pcb);
        return;
    }

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)len, PBUF_RAM);
    if (!p) {
        os_log_error(s_log, "[Bridge] udp_sendto: pbuf_alloc failed for %d bytes", len);
        udp_remove(pcb);
        return;
    }
    memcpy(p->payload, data, len);

    /* Use udp_sendto_if_src to bypass routing (lwIP can't route arbitrary IPs
     * through our TUN netif without a full routing table) */
    err_t send_err = udp_sendto_if_src(pcb, p, &dst_addr, dst_port, &tun_netif, &src_addr);
    if (send_err != ERR_OK) {
        os_log_error(s_log, "[Bridge] udp_sendto: failed err=%d is_ipv6=%d", (int)send_err, is_ipv6);
    }
    pbuf_free(p);
    udp_remove(pcb);
}

/* ========================================================================
 *  Timer
 * ======================================================================== */

void lwip_bridge_check_timeouts(void) {
    sys_check_timeouts();
}

/* ========================================================================
 *  IP Address Utility
 * ======================================================================== */

const char *lwip_ip_to_string(const void *addr, int is_ipv6,
                               char *out, size_t out_len) {
    int af = is_ipv6 ? AF_INET6 : AF_INET;
    return inet_ntop(af, addr, out, (socklen_t)out_len);
}
