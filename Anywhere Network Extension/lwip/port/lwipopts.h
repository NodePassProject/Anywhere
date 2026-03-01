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
#define LWIP_ICMP                       0
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
#define LWIP_SINGLE_NETIF              1

/* --- Raw API only (no sockets/netconn) --- */
#define LWIP_CALLBACK_API               1

/* --- Memory configuration (iOS NE ~15MB limit) --- */
#define MEM_SIZE                        (512 * 1024)
#define MEM_ALIGNMENT                   4
#define MEMP_OVERFLOW_CHECK             0
#define MEMP_SANITY_CHECK               0

/* --- Pool sizes --- */
#define MEMP_NUM_TCP_PCB                128
#define MEMP_NUM_TCP_PCB_LISTEN         2
#define MEMP_NUM_UDP_PCB                4
#define MEMP_NUM_TCP_SEG                512
#define MEMP_NUM_PBUF                   64
#define MEMP_NUM_NETBUF                 0
#define MEMP_NUM_NETCONN                0

/* --- Pbuf configuration --- */
#define PBUF_POOL_SIZE                  256
#define PBUF_POOL_BUFSIZE               1500

/* --- TCP configuration --- */
#define TCP_MSS                         1360
#define TCP_WND                         (64 * TCP_MSS)
#define TCP_SND_BUF                     (64 * TCP_MSS)
#define TCP_SND_QUEUELEN                (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_QUEUE_OOSEQ                 1
#define TCP_OVERSIZE                    TCP_MSS
#define LWIP_TCP_TIMESTAMPS             0
#define LWIP_TCP_SACK_OUT               0
#define TCP_LISTEN_BACKLOG              0

/* --- TCP window scaling (RFC 1323) --- */
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   7

/* --- Checksum configuration --- */
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
#define CHECKSUM_GEN_ICMP               0
#define CHECKSUM_GEN_ICMP6              1

/* --- IPv6 --- */
#define LWIP_IPV6_NUM_ADDRESSES         3
#define LWIP_IPV6_FORWARD               0
#define LWIP_IPV6_FRAG                  0

/* --- IP reassembly --- */
#define IP_REASSEMBLY                   0
#define IP_FRAG                         0

/* --- Misc --- */
#define LWIP_NETIF_TX_SINGLE_PBUF       1
#define LWIP_HAVE_LOOPIF                0
#define LWIP_NETIF_LOOPBACK             0
#define LWIP_RANDOMIZE_INITIAL_LOCAL_PORTS 1

/* --- Debug (disable in release) --- */
#define LWIP_DEBUG                      0

#endif /* LWIPOPTS_H */
