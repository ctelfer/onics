#ifndef __pkttools_config_h
#define __pkttools_config_h

#define HAS_PCAP

#define FMT64   "ll"
/* #define FMT64   "l" */ /* use this one for 64-bit machines */

#if CAT_USE_INLINE
#define INLINE inline
#else
#define INLINE
#endif

#endif /* __pkttools_config_h */
