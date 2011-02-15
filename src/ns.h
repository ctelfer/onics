#ifndef __NS_H
#define __NS_H

#include <cat/cat.h>
#include "protoparse.h"

enum {
	NST_NAMESPACE,
	NST_PKTFLD,
	NST_SCALAR,
	NST_BYTESTR,
	NST_MASKSTR,
};


enum {
	NSF_VARLEN = 0x1,
	NSF_INBITS = 0x2,
	NSF_ISSIGNED = 0x4,
	NSF_BITOFF_SHF = 4,
	NSF_WIDTH_SHF = 4,
};

#define NSF_IS_VARLEN(flags) (((flags) & NSF_VARLEN) != 0)
#define NSF_IS_INBITS(flags) (((flags) & NSF_INBITS) != 0)
#define NSF_IS_SIGNED(flags) (((flags) & NSF_ISSIGNED) != 0)
#define NSF_BITOFF(flags) (((flags) >> 4) & 0xF)
#define NSF_WIDTH(flags) (((flags) >> 4) & 0xF)


struct ns_elem {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	const char *		name;
};


typedef int (*ns_format_f)(struct ns_elem *, byte_t *pkt, struct prparse *, 
		           struct raw *);

struct ns_namespace {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	const char *		name;
	uint			ppt;
	uint			oidx;
	ulong			len;
	const char *		fmtstr;
	ns_format_f		fmt;
	struct ns_elem **	elems;
	uint			nelem;
};

#define NS_NAMESPACE_ROOT(elem, nelem) \
	{ NST_NAMESPACE, 0, NULL, "", PPT_NONE, 0, 0, 0, NULL, (elem), (nelem) }

#define NS_NAMESPACE_I(name, par, ppt, desc, elems, nelem)\
	{ NST_NAMESPACE, (NSF_VARLEN), (par), (name), (ppt), PRP_OI_SOFF, \
	  PRP_OI_EOFF, (desc), &ns_fmt_hdr, (elems), (nelem) }

#define NS_NAMESPACE_IDX_I(name, par, ppt, oidx, len, desc, elems, nelem)\
	{ NST_NAMESPACE, 0, (par), (name), (ppt), (oidx), \
	  (len), (desc), &ns_fmt_hdr, (elems), (nelem) }

#define NS_NAMESPACE_VARLEN_I(name, par, ppt, oidx, eidx, desc, elems, nelem)\
	{ NST_NAMESPACE, (NSF_VARLEN), (par), (name), (ppt), (oidx), \
	  (eidx), (desc), &ns_fmt_hdr, (elems), (nelem) }


struct ns_pktfld {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	const char *		name;
	uint			ppt;
	uint			oidx;		/* offset index */
	ulong			off;		/* in bytes */
	ulong			len;		/* len in bits or bytes/oidx */
	const char *		fmtstr;
	ns_format_f		fmt;
};

#define NS_BITFIELD_I(name, par, ppt, off, bitoff, len, desc, fmtf) \
	{ NST_PKTFLD, (NSF_INBITS | ((bitoff) << NSF_BITOFF_SHF)), \
	  (par), (name), (ppt), PRP_OI_SOFF, (off), (len), (desc), (fmtf) }

#define NS_BYTEFIELD_I(name, par, ppt, off, len, desc, fmtf) \
	{ NST_PKTFLD, 0, \
	  (par), (name), (ppt), PRP_OI_SOFF, (off), (len), (desc), (fmtf) }

#define NS_BITFIELD_IDX_I(name, par, ppt, oidx, off, bitoff, len, desc, fmtf) \
	{ NST_PKTFLD, (NSF_INBITS | ((bitoff) << NSF_BITOFF_SHF)), \
	  (par), (name), (ppt), (oidx), (off), (len), (desc), (fmtf) }

#define NS_BYTEFIELD_IDX_I(name, par, ppt, oidx, off, len, desc, fmtf) \
	{ NST_PKTFLD, 0, \
	  (par), (name), (ppt), (oidx), (off), (len), (desc), (fmtf) }

#define NS_BYTEFIELD_VARLEN_I(name, par, ppt, oidx, off, eidx, desc, fmtf) \
	{ NST_PKTFLD, (NSF_VARLEN), \
	  (par), (name), (ppt), (oidx), (off), (eidx), (desc), (fmtf) }

struct ns_scalar {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	const char *		name;
	uint			ppt;
	long			value;
};

#define NS_INT8_I(name, par, ppt, val) \
	{ NST_SCALAR, (NSF_ISSIGNED|(1 << NSF_WIDTH_SHF)),\
	  (par), (name), (ppt), (val) }
#define NS_INT16_I(name, par, ppt, val) \
	{ NST_SCALAR, (NSF_ISSIGNED|(2 << NSF_WIDTH_SHF)),\
	  (par), (name), (ppt), (val) }
#define NS_INT32_I(name, par, ppt, val) \
	{ NST_SCALAR, (NSF_ISSIGNED|(4 << NSF_WIDTH_SHF)),\
	  (par), (name), (ppt), (val) }
#define NS_INT64_I(name, par, ppt, val) \
	{ NST_SCALAR, (NSF_ISSIGNED|(8 << NSF_WIDTH_SHF)),\
	  (par), (name), (ppt), (val) }
#define NS_UINT8_I(name, par, ppt, val) \
	{ NST_SCALAR, (1 << NSF_WIDTH_SHF), (par), (name), (ppt), (long)(val) }
#define NS_UINT16_I(name, par, ppt, val) \
	{ NST_SCALAR, (2 << NSF_WIDTH_SHF), (par), (name), (ppt), (long)(val) }
#define NS_UINT32_I(name, par, ppt, val) \
	{ NST_SCALAR, (4 << NSF_WIDTH_SHF), (par), (name), (ppt), (long)(val) }
#define NS_UINT64_I(name, par, ppt, val) \
	{ NST_SCALAR, (8 << NSF_WIDTH_SHF), (par), (name), (ppt), (long)(val) }


struct ns_bytestr {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	uint			ppt;
	const char *		name;
	struct raw		value;
};

#define NS_BYTESTR_I(name, par, ppt, arr) \
	{ NST_BYTESTR, (par), (name), (ppt), { (str), array_length(str) } } 
#define NS_ASCIISTR_I(name, par, ppt, str) NS_BYTESTR_I(name, par, ppt, str)
#define NS_BYTESTR_I_LEN(name, par, ppt, arr, len) \
	{ NST_BYTESTR, (par), (name), (ppt), { (arr), (len) } } 


struct ns_maskstr {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	const char *		name;
	uint			ppt;
	struct raw		value;
	struct raw		mask;
};

#define NS_MASKSTR_I(name, par, ppt, val, mask) \
	{ NST_MASKSTR, (par), (name), (ppt), { (val), array_length(val) }, \
	  { (mask), array_length(val) } } 
#define NS_MASKSTR_I_LEN(name, par, ppt, val, mask, len) \
	{ NST_MASKSTR, (par), (name), (ppt), { (val), (len) }, \
	  { (mask), (len) } }


int ns_add_elem(struct ns_namespace *ns, struct ns_elem *e);
void ns_rem_elem(struct ns_elem *e);
struct ns_elem *ns_lookup(struct ns_namespace *ns, const char *name);



/* Field format functions */

/* element format must take no parameters */
int ns_fmt_hdr(struct ns_elem *em, byte_t *pkt, struct prparse *prp,
	       struct raw *str);

/* element format must take a single unsigned long */
int ns_fmt_num(struct ns_elem *em, byte_t *pkt, struct prparse *prp,
	       struct raw *str);

/* element format must contain a two unsigned long parameters*/
int ns_fmt_wlen(struct ns_elem *em, byte_t *pkt, struct prparse *prp,
	        struct raw *str);

/* element format must contain a single %s */
int ns_fmt_ipv4a(struct ns_elem *em, byte_t *pkt, struct prparse *prp,
	         struct raw *str);

/* element format must contain a single %s */
int ns_fmt_ipv6a(struct ns_elem *em, byte_t *pkt, struct prparse *prp,
	         struct raw *str);

/* element format must contain a single %s */
int ns_fmt_etha(struct ns_elem *em, byte_t *pkt, struct prparse *prp,
	        struct raw *str);

#endif /* __NS_H */
