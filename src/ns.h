#ifndef __NS_H
#define __NS_H

#include <cat/cat.h>

enum {
	NST_NAMESPACE,
	NST_PKTFLD,
	NST_SCALAR,
	NST_BYTESTR,
	NST_MASKSTR,
};


struct ns_elem {
	int			type;
	struct ns_namespace *	parent;
	const char *		name;
	uint			ppt;
};


struct ns_namespace {
	int			type;
	struct ns_namespace *	parent;
	const char *		name;
	uint			ppt;
	struct ns_elem **	elems;
	int			nelem;
	char			oidx;
	char			pad[3];
};

#define NS_NAMESPACE_I(name, par, ppt, elems)\
	{ NST_NAMESPACE, (par), (name), (ppt), (elems), array_length(elems), \
	  0, { 0, 0, 0 } }

#define NS_NAMESPACE_I_EXLEN(name, par, ppt, elems, nelem)\
	{ NST_NAMESPACE, (par), (name), (ppt), (elems), (nelem), \
	  0, { 0, 0, 0 } }

#define NS_NAMESPACE_IDX_I(name, par, ppt, oidx, elems)\
	{ NST_NAMESPACE, (par), (name), (ppt), (elems), array_length(elems), \
	  (oidx), { 0, 0, 0 } }

#define NS_NAMESPACE_IDX_I_EXLEN(name, par, ppt, oidx, elems, nelem)\
	{ NST_NAMESPACE, (par), (name), (ppt), (elems), (nelem), \
	  (oidx), { 0, 0, 0 } }

struct ns_pktfld {
	int			type;
	struct ns_namespace *	parent;
	const char *		name;
	uint			ppt;
	long			off;		/* in bytes */
	long			len;		/* in bits or bytes */
	char			oidx;		/* offset index */
	char			inbits;		/* len in bits */
	char			bitoff;		/* counting from MSB if */
	char			pad;
};

#define NS_BITFIELD_I(name, par, ppt, off, bitoff, len) \
	{ NST_PKTFLD, (par), (name), (ppt), (off), (len), PRP_OI_SOFF, \
	  1, (bitoff), 0}

#define NS_BYTEFIELD_I(name, par, ppt, off, len) \
	{ NST_PKTFLD, (par), (name), (ppt), (off), (len), PRP_OI_SOFF, 0, 0, 0 }

#define NS_BITFIELD_IDX_I(name, par, ppt, off, bitoff, len, oidx) \
	{ NST_PKTFLD, (par), (name), (ppt), (off), (len), (oidx), 1, \
	  (bitoff), 0 }

#define NS_BYTEFIELD_IDX_I(name, par, ppt, off, len, oidx) \
	{ NST_PKTFLD, (par), (name), (ppt), (off), (len), (oidx), 0, 0, 0 }


struct ns_scalar {
	int			type;
	struct ns_namespace *	parent;
	const char *		name;
	uint			ppt;
	long			value;
	char			issigned;
	char			width;
};

#define NS_INT8_I(name, par, ppt, val) \
	{ NST_PKTFLD, (par), (name), (ppt), (val), 1, 1 }
#define NS_INT16_I(name, par, ppt, val) \
	{ NST_PKTFLD, (par), (name), (ppt), (val), 1, 2 }
#define NS_INT32_I(name, par, ppt, val) \
	{ NST_PKTFLD, (par), (name), (ppt), (val), 1, 4 }
#define NS_INT64_I(name, par, ppt, val) \
	{ NST_PKTFLD, (par), (name), (ppt), (val), 1, 8 }
#define NS_UINT8_I(name, par, ppt, val) \
	{ NST_PKTFLD, (par), (name), (ppt), ((long)(val)), 0, 1 }
#define NS_UINT16_I(name, par, ppt, val) \
	{ NST_PKTFLD, (par), (name), (ppt), ((long)(val)), 0, 2 }
#define NS_UINT32_I(name, par, ppt, val) \
	{ NST_PKTFLD, (par), (name), (ppt), ((long)(val)), 0, 4 }
#define NS_UINT64_I(name, par, ppt, val) \
	{ NST_PKTFLD, (par), (name), (ppt), ((long)(val)), 0, 8 }


struct ns_bytestr {
	int			type;
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
	int			type;
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

#endif /* __NS_H */
