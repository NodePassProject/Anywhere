#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* --- NO_SYS mode (bare-metal, callback-driven) --- */
#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_TIMERS                     1

/* --- Core protocol support --- */
#define LWIP_TCP                        1
#define LWIP_UDP                        1
#define LWIP_IPV4                       1
#define LWIP_IPV6                       1
#define LWIP_ICMP                       1
#define LWIP_ICMP6                      1
#define LWIP_RAW                        0

/* --- Disabled features (not needed for TUN interface) --- */
#define LWIP_SOCKET                     0
#define LWIP_NETCONN                    0
#define LWIP_DNS                        0
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_ARP                        0
#define LWIP_IGMP                       0
#define LWIP_MLD6                       0
#define LWIP_ND6                        0
#define LWIP_IPV6_REASS                 0
#define LWIP_IPV6_MLD                   0
#define LWIP_IPV6_AUTOCONFIG            0
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS   0
#define LWIP_NETIF_STATUS_CALLBACK      0
#define LWIP_NETIF_LINK_CALLBACK        0
#define LWIP_STATS                      0
#define LWIP_STATS_DISPLAY              0

/* --- Single network interface optimization --- */
#define LWIP_SINGLE_NETIF               1

/* --- Raw API only (no sockets/netconn) --- */
#define LWIP_CALLBACK_API               1

/* --- Memory configuration --- */
#define MEM_LIBC_MALLOC                 1
#define MEM_ALIGNMENT                   8
#define MEMP_OVERFLOW_CHECK             0
#define MEMP_SANITY_CHECK               0
#define LWIP_CHECKSUM_ON_COPY           1

/* --- Pool sizes --- */
#define MEMP_NUM_TCP_PCB                256
#define MEMP_NUM_TCP_PCB_LISTEN         2
#define MEMP_NUM_UDP_PCB                64
#define MEMP_NUM_TCP_SEG                32768
#define MEMP_NUM_PBUF                   64
#define MEMP_NUM_NETBUF                 0
#define MEMP_NUM_NETCONN                0

/* --- Pbuf configuration --- */
#define PBUF_POOL_SIZE                  2048
#define PBUF_POOL_BUFSIZE               1400

/* --- TCP configuration --- */
#define TCP_MSS                         1360
#define TCP_WND                         (1024 * TCP_MSS)
#define TCP_SND_BUF                     (1024 * TCP_MSS)
#define TCP_SND_QUEUELEN                (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_SNDLOWAT                    ((2 * TCP_MSS) + 1)
#define TCP_QUEUE_OOSEQ                 1
#define TCP_OOSEQ_MAX_BYTES             (1024 * 1024)
#define TCP_OOSEQ_MAX_PBUFS             1024
#define TCP_OVERSIZE                    TCP_MSS
#define TCP_WND_UPDATE_THRESHOLD        LWIP_MIN((TCP_WND / 4), (TCP_MSS * 8))
#define TCP_MAXRTX                      8
#define TCP_SYNMAXRTX                   3
#define LWIP_TCP_TIMESTAMPS             0
#define LWIP_TCP_SACK_OUT               1
#define LWIP_TCP_MAX_SACK_NUM           8
#define LWIP_TCP_CALC_INITIAL_CWND(mss) ((tcpwnd_size_t)(32U * (mss)))

#define TCP_LISTEN_BACKLOG              0

/* --- TCP window scaling (RFC 1323) --- */
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   7

/* --- Checksum configuration --- */
#define LWIP_CHKSUM_ALGORITHM           3
/* Trust incoming packets from iOS TUN interface */
#define CHECKSUM_CHECK_IP               0
#define CHECKSUM_CHECK_TCP              0
#define CHECKSUM_CHECK_UDP              0
#define CHECKSUM_CHECK_ICMP             0
#define CHECKSUM_CHECK_ICMP6            0
/* lwIP generates outgoing checksums */
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_TCP                1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_ICMP               1
#define CHECKSUM_GEN_ICMP6              1

/* --- IPv6 --- */
#define LWIP_IPV6_NUM_ADDRESSES         3
#define LWIP_IPV6_FORWARD               0
#define LWIP_IPV6_FRAG                  0

/* --- IP reassembly --- */
#define IP_REASSEMBLY                   0
#define IP_FRAG                         0
#define IP_OPTIONS_ALLOWED              0

/* --- Misc --- */
#define LWIP_NETIF_TX_SINGLE_PBUF       1
#define LWIP_HAVE_LOOPIF                0
#define LWIP_NETIF_LOOPBACK             0
#define LWIP_RANDOMIZE_INITIAL_LOCAL_PORTS 1

/* --- PPP (disabled, provide default for opt.h) --- */
#define PPP_SUPPORT                     0
#define PPP_NUM_TIMEOUTS                0

/* --- Debug (disable in release) --- */
#define LWIP_DEBUG                      0

#endif /* LWIPOPTS_H */
