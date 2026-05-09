//
//  config.h
//  Anywhere
//
//  Created by Argsment Limited on 4/10/26.
//

#ifndef NGTCP2_CONFIG_H
#define NGTCP2_CONFIG_H

#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_UNISTD_H 1
#define HAVE_MEMSET_S 1

/* Apple platforms use machine/endian.h, not endian.h or sys/endian.h */
/* #undef HAVE_ENDIAN_H */
/* #undef HAVE_SYS_ENDIAN_H */
/* #undef HAVE_BYTESWAP_H */
/* #undef HAVE_ASM_TYPES_H */
/* #undef HAVE_LINUX_NETLINK_H */
/* #undef HAVE_LINUX_RTNETLINK_H */

#define HAVE_DECL_BE64TOH 0
#define HAVE_DECL_BSWAP_64 0

/* Not big endian on ARM64 */
/* #undef WORDS_BIGENDIAN */

/* No brotli */
/* #undef HAVE_LIBBROTLI */

/* Apple has explicit_bzero on newer SDKs, but memset_s is preferred */
/* #undef HAVE_EXPLICIT_BZERO */

/* No debug output */
/* #undef DEBUGBUILD */

#endif /* NGTCP2_CONFIG_H */
