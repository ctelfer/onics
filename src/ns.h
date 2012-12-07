/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * ns.h -- API for protocol namespaces.
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __NS_H
#define __NS_H

#include <cat/cat.h>
#include "protoparse.h"

enum {
	NST_NAMESPACE = 0,
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
	uint			prid;
	uint			pclass;
	uint			oidx;
	ulong			len;
	const char *		fmtstr;
	ns_format_f		fmt;
	struct ns_elem **	elems;
	uint			nelem;
};

#define NS_NAMESPACE_ROOT(elem, nelem)					    \
	{ NST_NAMESPACE, 0, NULL, "", PRID_NONE, PRID_NONE, 0, 0, 0, NULL,  \
	  (elem), (nelem) }

#define NS_NAMESPACE_I(name, par, prid, pc, desc, elems, nelem)		    \
	{ NST_NAMESPACE, (NSF_VARLEN), (par), (name), (prid), (pc),	    \
	  PRP_OI_SOFF, PRP_OI_EOFF, (desc), &ns_fmt_hdr, (elems), (nelem) }

#define NS_NAMESPACE_NOFLD(name, par, prid, pc, desc, elems, nelem)	    \
	{ NST_NAMESPACE, (NSF_VARLEN), (par), (name), (prid), (pc),	    \
	  PRP_OI_INVALID, PRP_OI_INVALID, (desc), &ns_fmt_hdr, (elems), (nelem)}

#define NS_NAMESPACE_IDX_I(name, par, prid, pc, oidx, len, desc, elems, nelem)\
	{ NST_NAMESPACE, 0, (par), (name), (prid), (pc), (oidx), 	      \
	  (len), (desc), &ns_fmt_hdr, (elems), (nelem) }

#define NS_NAMESPACE_VARLEN_I(name, par, prid, pc, oidx, eidx, desc, elems, \
			      nelem)					    \
	{ NST_NAMESPACE, (NSF_VARLEN), (par), (name), (prid), (pc), (oidx), \
	  (eidx), (desc), &ns_fmt_hdr, (elems), (nelem) }


struct ns_pktfld {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	const char *		name;
	uint			prid;
	uint			oidx;		/* offset index */
	ulong			off;		/* in bytes */
	ulong			len;		/* len in bits or bytes/oidx */
	const char *		fmtstr;
	ns_format_f		fmt;
};

#define NS_BITFIELD_I(name, par, prid, off, bitoff, len, desc, fmtf)	\
	{ NST_PKTFLD, (NSF_INBITS | ((bitoff) << NSF_BITOFF_SHF)),	\
	  (par), (name), (prid), PRP_OI_SOFF, (off), (len), (desc), (fmtf) }

#define NS_BYTEFIELD_I(name, par, prid, off, len, desc, fmtf)		\
	{ NST_PKTFLD, 0,						\
	  (par), (name), (prid), PRP_OI_SOFF, (off), (len), (desc), (fmtf) }

#define NS_BITFIELD_IDX_I(name, par, prid, oidx, off, bitoff, len, desc, fmtf) \
	{ NST_PKTFLD, (NSF_INBITS | ((bitoff) << NSF_BITOFF_SHF)),	       \
	  (par), (name), (prid), (oidx), (off), (len), (desc), (fmtf) }

#define NS_BYTEFIELD_IDX_I(name, par, prid, oidx, off, len, desc, fmtf)	\
	{ NST_PKTFLD, 0,						\
	  (par), (name), (prid), (oidx), (off), (len), (desc), (fmtf) }

#define NS_BYTEFIELD_VARLEN_I(name, par, prid, oidx, off, eidx, desc, fmtf)    \
	{ NST_PKTFLD, (NSF_VARLEN),					       \
	  (par), (name), (prid), (oidx), (off), (eidx), (desc), (fmtf) }

struct ns_scalar {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	const char *		name;
	uint			prid;
	long			value;
};

#define NS_INT8_I(name, par, prid, val)				\
	{ NST_SCALAR, (NSF_ISSIGNED|(1 << NSF_WIDTH_SHF)),	\
	  (par), (name), (prid), (val) }
#define NS_INT16_I(name, par, prid, val)			\
	{ NST_SCALAR, (NSF_ISSIGNED|(2 << NSF_WIDTH_SHF)),	\
	  (par), (name), (prid), (val) }
#define NS_INT32_I(name, par, prid, val)			\
	{ NST_SCALAR, (NSF_ISSIGNED|(4 << NSF_WIDTH_SHF)),	\
	  (par), (name), (prid), (val) }
#define NS_INT64_I(name, par, prid, val)			\
	{ NST_SCALAR, (NSF_ISSIGNED|(8 << NSF_WIDTH_SHF)),	\
	  (par), (name), (prid), (val) }
#define NS_UINT8_I(name, par, prid, val) 			\
	{ NST_SCALAR, (1 << NSF_WIDTH_SHF), (par), (name), (prid), (long)(val) }
#define NS_UINT16_I(name, par, prid, val) 			\
	{ NST_SCALAR, (2 << NSF_WIDTH_SHF), (par), (name), (prid), (long)(val) }
#define NS_UINT32_I(name, par, prid, val) 			\
	{ NST_SCALAR, (4 << NSF_WIDTH_SHF), (par), (name), (prid), (long)(val) }
#define NS_UINT64_I(name, par, prid, val)			\
	{ NST_SCALAR, (8 << NSF_WIDTH_SHF), (par), (name), (prid), (long)(val) }


struct ns_bytestr {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	const char *		name;
	uint			prid;
	struct raw		value;
};

#define NS_BYTESTR_I_LEN(name, par, prid, arr, len)			\
	{ NST_BYTESTR, 0, (par), (name), (prid), { (len), (arr) } } 
#define NS_BYTESTR_I(name, par, prid, arr)				\
	NS_BYTESTR_I_LEN(name, par, prid, arr, array_length(arr))
#define NS_ASCIISTR_I(name, par, prid, str)				\
	NS_BYTESTR_I(name, par, prid, str)


struct ns_maskstr {
	ushort			type;
	ushort			flags;
	struct ns_namespace *	parent;
	const char *		name;
	uint			prid;
	struct raw		value;
	struct raw		mask;
};

#define NS_MASKSTR_I_LEN(name, par, prid, val, mask, len)		\
	{ NST_MASKSTR, 0, (par), (name), (prid), { (len), (val) },	\
	  { (len), (mask) } }
#define NS_MASKSTR_I(name, par, prid, val, mask)			\
	NS_MASKSTR_I_LEN(name, par, prid, val, mask, array_length(val))


int ns_add_elem(struct ns_namespace *ns, struct ns_elem *e);
void ns_rem_elem(struct ns_elem *e);
struct ns_elem *ns_lookup(struct ns_namespace *ns, const char *name);
struct ns_namespace *ns_lookup_by_prid(uint prid);



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
