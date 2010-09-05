#ifndef __pkttools_config_h
#define __pkttools_config_h

#define HAS_PCAP

#define FMT32   ""
/* #define FMT32   "l" *//* use this one for 16-bit machines */

#if CAT_USE_INLINE
#define NETTOOLS_INLINE inline
#else
#define NETTOOLS_INLINE
#endif

#endif /* __pkttools_config_h */
