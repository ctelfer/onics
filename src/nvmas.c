#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include <cat/cat.h>
#include <cat/str.h>
#include <cat/err.h>
#include <cat/hash.h>
#include <cat/optparse.h>
#include <cat/emalloc.h>

#include "netvm.h"
#include "netvm_prog.h"
#include "netvm_op_macros.h"
#include "util.h"

#define MAXSTR 256

/*
 Example code: 

# comment
.include "filename"
.define PRID_TCP	0x0006
.define RWSEG		0
.define RWPERMS 	3
.segment RWSEG RWPERMS  1024
.define CPT_XPKT	1
.coproc 0 CPT_XPKT
.mem name segnum addr nbytes [init]
.entry (start|packet|end) @label

label:	add 
	jmpi, @label
	bzi, 3
	cpop 0, 0, z, w
	pkfxli *PKTN:PRID:INDEX:FIELD[OFFSET]
*/

struct clopt options[] = { 
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help and exit"), 
	CLOPT_INIT(CLOPT_NOARG, 'd', "--disassemble", "disassemble file"),
	CLOPT_INIT(CLOPT_NOARG, 'e', "--skip_error", 
				     "skip any errors during disassembly"),
};
struct clopt_parser optparser = CLOPTPARSER_INIT(options, array_length(options));


struct nvmop {
	char *		iname;
	uint8_t		opcode;
	uchar 		nargs;
	ushort		argmask;
};


int skip_errors = 0;


/* in argmask */
#define ARGX 1 
#define ARGY 2
#define ARGZ 4
#define ARGW 8
#define PDONLY 0x10
#define BRREL  0x20
#define ASWAP  0x40
#define MAXARGS 5
#define MAXTOKS (MAXARGS+1)
#define IDCHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" \
		"0123456789_"
#define WS	" \n\t"
#define LABELCHARS IDCHARS
#define ARGCHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" \
		 "0123456789_*[]@:.-%"


struct nvmop Operations[] = {
	{ "pop",    NETVM_OC_POP,    1, ARGW },
	{ "popto",  NETVM_OC_POPTO,  1, ARGW },
	{ "push",   NETVM_OC_PUSH,   1, ARGW },
	{ "orhi",   NETVM_OC_ORHI,   1, ARGW },
	{ "zpush",  NETVM_OC_ZPUSH,  1, ARGW },
	{ "dup",    NETVM_OC_DUP,    1, ARGW },
	{ "swap",   NETVM_OC_SWAP,   2, ARGX|ARGW },
	{ "ldbp",   NETVM_OC_LDBP,   1, ARGX },
	{ "ldbpi",  NETVM_OC_LDBPI,  2, ARGX|ARGW },
	{ "stbp",   NETVM_OC_STBP,   0, 0 },
	{ "stbpi",  NETVM_OC_STBPI,  1, ARGW },
	{ "pushfr", NETVM_OC_PUSHFR, 0, 0 },
	{ "popfr",  NETVM_OC_POPFR,  2, ARGX|ARGW },
	{ "ldpf",   NETVM_OC_LDPF,   0, 0 },
	{ "ldpfi",  NETVM_OC_LDPFI,  3, ARGY|ARGZ|ARGW|PDONLY },
	{ "ld",     NETVM_OC_LD,     0, 0 },
	{ "ldli",   NETVM_OC_LDLI,   1, ARGX },
	{ "ldi",    NETVM_OC_LDI,    3, ARGX|ARGY|ARGW },
	{ "ldpd",   NETVM_OC_LDPD,   1, ARGX },
	{ "ldpdi",  NETVM_OC_LDPDI,  4, ARGX|ARGY|ARGZ|ARGW|PDONLY },
	{ "cmp",    NETVM_OC_CMP,    0, 0 },
	{ "pcmp",   NETVM_OC_PCMP,   0, 0 },
	{ "mskcmp", NETVM_OC_MSKCMP, 0, 0 },
	{ "not",    NETVM_OC_NOT,    0, 0 },
	{ "invert", NETVM_OC_INVERT, 0, 0 },
	{ "tobool", NETVM_OC_TOBOOL, 0, 0 },
	{ "popl",   NETVM_OC_POPL,   0, 0 },
	{ "nlz",    NETVM_OC_NLZ,    0, 0 },
	{ "add",    NETVM_OC_ADD,    0, ASWAP },
	{ "addi",   NETVM_OC_ADDI,   1, ARGW|ASWAP },
	{ "sub",    NETVM_OC_SUB,    0, ASWAP },
	{ "subi",   NETVM_OC_SUBI,   1, ARGW|ASWAP },
	{ "mul",    NETVM_OC_MUL,    0, ASWAP },
	{ "muli",   NETVM_OC_MULI,   1, ARGW|ASWAP },
	{ "div",    NETVM_OC_DIV,    0, ASWAP },
	{ "divi",   NETVM_OC_DIVI,   1, ARGW|ASWAP },
	{ "mod",    NETVM_OC_MOD,    0, ASWAP },
	{ "modi",   NETVM_OC_MODI,   1, ARGW|ASWAP },
	{ "shl",    NETVM_OC_SHL,    0, ASWAP },
	{ "shli",   NETVM_OC_SHLI,   1, ARGW|ASWAP },
	{ "shr",    NETVM_OC_SHR,    0, ASWAP },
	{ "shri",   NETVM_OC_SHRI,   1, ARGW|ASWAP },
	{ "shra",   NETVM_OC_SHRA,   0, ASWAP },
	{ "shrai",  NETVM_OC_SHRAI,  1, ARGW|ASWAP },
	{ "and",    NETVM_OC_AND,    0, ASWAP },
	{ "andi",   NETVM_OC_ANDI,   1, ARGW|ASWAP },
	{ "or",     NETVM_OC_OR,     0, ASWAP },
	{ "ori",    NETVM_OC_ORI,    1, ARGW|ASWAP },
	{ "xor",    NETVM_OC_XOR,    0, ASWAP },
	{ "xori",   NETVM_OC_XORI,   1, ARGW|ASWAP },
	{ "eq",     NETVM_OC_EQ,     0, ASWAP },
	{ "eqi",    NETVM_OC_EQI,    1, ARGW|ASWAP },
	{ "neq",    NETVM_OC_NEQ,    0, ASWAP },
	{ "neqi",   NETVM_OC_NEQI,   1, ARGW|ASWAP },
	{ "lt",     NETVM_OC_LT,     0, ASWAP },
	{ "lti",    NETVM_OC_LTI,    1, ARGW|ASWAP },
	{ "le",     NETVM_OC_LE,     0, ASWAP },
	{ "lei",    NETVM_OC_LEI,    1, ARGW|ASWAP },
	{ "gt",     NETVM_OC_GT,     0, ASWAP },
	{ "gti",    NETVM_OC_GTI,    1, ARGW|ASWAP },
	{ "ge",     NETVM_OC_GE,     0, ASWAP },
	{ "gei",    NETVM_OC_GEI,    1, ARGW|ASWAP },
	{ "ult",    NETVM_OC_ULT,    0, ASWAP },
	{ "ulti",   NETVM_OC_ULTI,   1, ARGW|ASWAP },
	{ "ule",    NETVM_OC_ULE,    0, ASWAP },
	{ "ulei",   NETVM_OC_ULEI,   1, ARGW|ASWAP },
	{ "ugt",    NETVM_OC_UGT,    0, ASWAP },
	{ "ugti",   NETVM_OC_UGTI,   1, ARGW|ASWAP },
	{ "uge",    NETVM_OC_UGE,    0, ASWAP },
	{ "ugei",   NETVM_OC_UGEI,   1, ARGW|ASWAP },
	{ "min",    NETVM_OC_MIN,    0, ASWAP },
	{ "mini",   NETVM_OC_MINI,   1, ARGW|ASWAP },
	{ "max",    NETVM_OC_MAX,    0, ASWAP },
	{ "maxi",   NETVM_OC_MAXI,   1, ARGW|ASWAP },
	{ "umin",   NETVM_OC_UMIN,   0, ASWAP },
	{ "umini",  NETVM_OC_UMINI,  1, ARGW|ASWAP },
	{ "umax",   NETVM_OC_UMAX,   0, ASWAP },
	{ "umaxi",  NETVM_OC_UMAXI,  1, ARGW|ASWAP },
	{ "getcpt", NETVM_OC_GETCPT, 0, 0 },
	{ "cpopi",  NETVM_OC_CPOPI,  4, ARGX|ARGY|ARGZ|ARGW },
	{ "bri",    NETVM_OC_BRI,    1, ARGW|BRREL },
	{ "bnzi",   NETVM_OC_BNZI,   1, ARGW|BRREL },
	{ "bzi",    NETVM_OC_BZI,    1, ARGW|BRREL },
	{ "jmpi",   NETVM_OC_JMPI,   1, ARGW },
	{ "halt",   NETVM_OC_HALT,   0, 0 },
	{ "cpop",   NETVM_OC_CPOP,   0, 0 },
	{ "br",     NETVM_OC_BR,     0, 0 },
	{ "bnz",    NETVM_OC_BNZ,    0, 0 },
	{ "bz",     NETVM_OC_BZ,     0, 0 },
	{ "pushpc", NETVM_OC_PUSHPC, 1, ARGW },
	{ "jmp",    NETVM_OC_JMP,    0, 0 },
	{ "call",   NETVM_OC_CALL,   0, 0 },
	{ "ret",    NETVM_OC_RET,    2, ARGX|ARGW },
	{ "st",     NETVM_OC_ST,     0, 0 },
	{ "stli",   NETVM_OC_STLI,   1, ARGX },
	{ "sti",    NETVM_OC_STI,    3, ARGX|ARGY|ARGW },
	{ "stpd",   NETVM_OC_STPD,   1, ARGX },
	{ "stpdi",  NETVM_OC_STPDI,  4, ARGX|ARGY|ARGZ|ARGW|PDONLY },
	{ "move",   NETVM_OC_MOVE,   0, 0 },
	{ "pknew",  NETVM_OC_PKNEW,  0, 0 },
	{ "pkswap", NETVM_OC_PKSWAP, 0, 0 },
	{ "pkcopy", NETVM_OC_PKCOPY, 0, 0 },
	{ "pkdel",  NETVM_OC_PKDEL,  0, 0 },
	{ "pksla",  NETVM_OC_PKSLA,  1, ARGX },
	{ "pkcla",  NETVM_OC_PKCLA,  1, ARGX },
	{ "pkppsh", NETVM_OC_PKPPSH, 1, ARGX },
	{ "pkppop", NETVM_OC_PKPPOP, 1, ARGX },
	{ "pkprs",  NETVM_OC_PKPRS,  1, ARGX },
	{ "pkfxd",  NETVM_OC_PKFXD,  0, 0 },
	{ "pkpup",  NETVM_OC_PKPUP,  0, 0 },
	{ "pkfxl",  NETVM_OC_PKFXL,  0, 0 },
	{ "pkfxli", NETVM_OC_PKFXLI, 3, ARGY|ARGZ|ARGW|PDONLY },
	{ "pkfxc",  NETVM_OC_PKFXC,  0, 0 },
	{ "pkfxci", NETVM_OC_PKFXCI, 3, ARGY|ARGZ|ARGW|PDONLY },
	{ "pkins",  NETVM_OC_PKINS,  1, ARGX },
	{ "pkcut",  NETVM_OC_PKCUT,  1, ARGX },
	{ "pkadj",  NETVM_OC_PKADJ,  0, 0 },

	{ NULL,  0,  0, 0 },
};


#define TABLESIZE	256
#define MAXINSTR	65536
#define MAXCONST	65536
#define MAXFILES	256
#define MAXMEMINIT	1024

struct instruction {
	char *			str;
	uint			inum;
	char *			fname;
	uint			lineno;
	struct netvm_inst 	instr;
};


struct constant {
	struct hnode hn;
	ulong val;
};


struct asmctx {
	int 			matchonly;
	struct instruction  	instrs[MAXINSTR];
	uint			numi;
	char 			eps[NVMP_EP_NUMEP][MAXSTR];
	char			files[MAXFILES][MAXSTR];
	uint			numf;
	char *			curfile;
	struct constant		consts[MAXCONST];
	uint			numc;
	struct hnode *		celem[TABLESIZE];
	struct htab 		ctab;
	struct netvm_segdesc    sdescs[NETVM_MAXMSEGS];
	uint64_t                cpreqs[NETVM_MAXCOPROC];
	struct netvm_meminit	minits[MAXMEMINIT];
	uint			ninits;
};


const char *epnames[NVMP_EP_NUMEP] = {
	"start", "packet", "end"
};


static int assemble(struct asmctx *ctx, const char *fn, FILE *input);


static struct nvmop *name2op(const char *iname)
{
	struct nvmop *op;
	for (op = Operations; op->iname != NULL ; ++op)
		if (strcmp(op->iname, iname) == 0)
			return op;
	return NULL;
}


static struct nvmop *oc2op(uint8_t oc)
{
	struct nvmop *op;
	for (op = Operations; op->iname != NULL ; ++op)
		if (op->opcode == oc)
			return op;
	return NULL;
}


int find_const(struct htab *t, const char *name, ulong *v)
{
	struct hnode *hn;
	struct constant *c;
	if ((hn = ht_lkup(t, name, NULL)) == NULL)
		return 0;
	c = hn->data;
	if (v != NULL)
		*v = c->val;
	return 1;
}


void add_const(struct htab *t, struct constant *c, const char *name, ulong v)
{
	c->val = v;
	ht_ninit(&c->hn, estrdup(name), c);
	ht_ins_h(t, &c->hn);
}



#define ERR_OK		0
#define ERR_BADNAME	1
#define ERR_NARG	2
#define ERR_PDESC	3
#define ERR_TOOLONG	4
#define ERR_BADTOK	5
#define ERR_BADNUM	6
#define ERR_UNKLBL	7
#define ERR_UNKSYM	8
#define NUMERR		9


static const char *estrs[NUMERR] = { 
	"ok",
	"Invalid instruction name",
	"Invalid number of arguments",
	"Invalid packet descriptor",
	"String too long",
	"Invalid token in string",
	"Invalid number format",
	"Unknown label",
	"Unknown symbol",
};


static char *parse_quoted_string(char *str, size_t *len)
{
	char *d, *s;

	d = s = str;
	while (*s != '"') {
		if (*s == '\0')
			return NULL;
		if (*s == '\\') {
			if (s[1] == '\0')
				return NULL;
			if (s[1] == 'x') {
				if (!isxdigit(s[2]) || !isxdigit(s[3]))
					return NULL;
				*d++ = chnval(s[2]) * 16 + chnval(s[3]);
				s += 4;

			} else {
				*d++ = *++s;
				++s;
			}
		} else {
			*d++ = *s++;
		}
	}

	*d = '\0';
	if (len != NULL)
		*len = d - str;
	return s+1;
}


static int tokenize(char *s, struct raw toks[], uint maxtoks, int csep)
{
	int nt = 0;
	int first = 1;
	struct raw *r = toks;
	char *e;

	s = s + strspn(s, WS);

	while (*s != '\0') {
		if (nt == maxtoks)
			return -ERR_NARG;
		if (*s == '"') {
			r->data = s+1;
			s = parse_quoted_string(s+1, &r->len);
			if (s == NULL)
				return -ERR_BADTOK;
		} else {
			r->data = s;
			s = s + strspn(s, ARGCHARS);
			r->len = (byte_t*)s - r->data;
			if (r->len == 0)
				return -ERR_BADTOK;
		}

		++nt;
		++r;
		e = s + strspn(s, WS);

		if (*e == '#') {
			*s = '\0';
			return nt;
		} else if (*e != '\0') {
			if (csep && !first) {
				if (*e != ',')
					return -ERR_BADTOK;
				++e;
				e = e + strspn(e, WS);
				if (*e == '\0')
					return -ERR_NARG;
			}
		}
		*s = '\0';
		s = e;

		first = 0;
	}

	return nt;
}


static int intarg(const struct raw *r, struct htab *ct, ulong *v)
{
	char *cp;
	int negval = 0;

	if (r->data[0] == '@') {
		if (isdigit(r->data[1])) {
			*v = strtoul(r->data+1, &cp, 0);
			if (cp != (char *)r->data + r->len)
				return ERR_UNKLBL;
		} else {
			if (!find_const(ct, r->data, v))
				return ERR_UNKLBL;
		}
	} else if (isalpha(r->data[0])) {
		if (ct == NULL || !find_const(ct, r->data, v))
			return ERR_UNKSYM;
	} else {
		cp = (char *)r->data;
		if (cp[0] == '-') {
			negval = 1;
			++cp;
		}
		abort_unless(r->len > 0);
		*v = strtoul(cp, &cp, 0);
		if (cp != (char *)r->data + r->len)
			return ERR_BADNUM;
		if (negval)
			*v = -*v;
	}

	return 0;
}


static int pdf2int(char *s, char **e, char nxtc, struct htab *ct, ulong *v)
{
	struct raw r;
	char tok[MAXSTR];
	char *cp;

	if (((cp = s + strspn(s, IDCHARS)) == s) || (*cp != nxtc))
		return ERR_PDESC;
	memcpy(tok, s, cp - s);
	tok[cp - s] = '\0';
	r.data = tok;
	r.len = cp - s;
	*e = cp;
	return intarg(&r, ct, v);
}


/* example: *0:tcp:0:0[3] */
/* example: *0:0x0103:0:0[4] */
static int read_pdesc(char *s, struct netvm_inst *ni, struct htab *ct)
{
	int rv;
	uchar pktnum, index, field;
	uint prid, offset;
	ulong v;

	if ((rv = pdf2int(s, &s, ':', ct, &v)) != 0)
		return rv;
	if ((pktnum = v) >= NETVM_MAXPKTS)
		return ERR_PDESC;

	if ((rv = pdf2int(s+1, &s, ':', ct, &v)) != 0)
		return rv;
	prid = v & NETVM_PPD_PRID_MASK;

	if ((rv = pdf2int(s+1, &s, ':', ct, &v)) != 0)
		return rv;
	index = v & NETVM_PPD_IDX_MASK;

	if ((rv = pdf2int(s+1, &s, '[', ct, &v)) != 0)
		return rv;
	field = v & NETVM_PPD_FLD_MASK;

	if ((rv = pdf2int(s+1, &s, ']', ct, &v)) != 0)
		return rv;
	offset = v & NETVM_PPD_OFF_MASK;

	ni->y = pktnum | NETVM_SEG_ISPKT;
	ni->z = (index << NETVM_PPD_IDX_OFF) | (field << NETVM_PPD_FLD_OFF);
	ni->w = (prid << NETVM_PPD_PRID_OFF) | (offset << NETVM_PPD_OFF_OFF);

	return 0;
}


int str2inst(const char *s, struct htab *ct, uint inum, struct netvm_inst *ni)
{
	char ns[MAXSTR];
	struct raw toks[MAXTOKS], *r;
	int nt, rv;
	struct nvmop *op;
	ulong v;
	int argswap = 0;

	if (str_copy(ns, s, sizeof(ns)) > sizeof(ns))
		return ERR_TOOLONG;
	if ((nt = tokenize(ns, toks, array_length(toks), 1)) <= 0)
		return nt == 0 ? ERR_NARG : -nt;
	if (toks[0].data[toks[0].len-1] == '%') {
		toks[0].data[toks[0].len-1] = '\0';
		toks[0].len--;
		argswap = 1;
	}
	if ((op = name2op(toks[0].data)) == NULL)
		return ERR_BADNAME;
	if (argswap && ((op->argmask & ASWAP) == 0)) {
		abort_unless((op->argmask & ARGX) == 0);
		err("opcode '%s' can not be swapped\n");
	}

	ni->x = argswap;
	ni->y = ni->z = ni->w = 0;
	ni->op = op->opcode;

	if ((nt == 2 && toks[1].data[0] == '*') ||
	    (nt == 3 && toks[2].data[0] == '*')) {
		if (op->nargs != nt + 1)
			return ERR_NARG;
		r = toks + 1;
		if ((op->argmask & ARGX) != 0) {
			if ((rv = intarg(r++, ct, &v)) != 0)
				return rv;
			ni->x = v;
		}
		rv = read_pdesc(r->data + 1, ni, ct);
		if (rv != 0)
			return rv;
	} else if (nt - 1 == op->nargs) {
		r = toks + 1;
		if ((op->argmask & ARGX) != 0) {
			if ((rv = intarg(r++, ct, &v)) != 0)
				return rv;
			ni->x = v;
		}
		if ((op->argmask & ARGY) != 0) {
			if ((rv = intarg(r++, ct, &v)) != 0)
				return rv;
			ni->y = v;
		}
		if ((op->argmask & ARGZ) != 0) {
			if ((rv = intarg(r++, ct, &v)) != 0)
				return rv;
			ni->z = v;
		}
		if ((op->argmask & ARGW) != 0) {
			if ((rv = intarg(r, ct, &v)) != 0)
				return rv;
			if (((op->argmask & BRREL) != 0) && 
			    (r->data[0] == '@')) {
				abort_unless(v < UINT_MAX);
				ni->w = (uint32_t)(v - inum);
			} else {
				ni->w = v;
			}
			r++;
		}
	} else {
		return ERR_NARG;
	}

	return 0;
}


static int pdesc2str(const struct netvm_inst *ni, char *s, size_t len, int xa)
{
	char pfx[16] = "";
	uint prid = (ni->w >> NETVM_PPD_PRID_OFF) & NETVM_PPD_PRID_MASK;

	if (xa)
		str_fmt(pfx, sizeof(pfx), "%02x, ", ni->x);

	/* example: *0:0x0103.0.0[3] */
	str_fmt(s, len, "%s*%u:%u.%u.%u[%u]", pfx, ni->y, prid, 
		(ni->z >> NETVM_PPD_IDX_OFF) & NETVM_PPD_IDX_MASK,
		(ni->z >> NETVM_PPD_FLD_OFF) & NETVM_PPD_FLD_MASK,
		(ni->w >> NETVM_PPD_OFF_OFF) & NETVM_PPD_OFF_MASK);

	return 0;
}


int inst2str(const struct netvm_inst *ni, char *s, size_t len, uint inum)
{
	struct nvmop *op;
	ulong args[MAXARGS], *ap = args;
	int fr = 0;
	char a0p[2] = "";
	char *iname;
	char swname[11];

	if ((op = oc2op(ni->op)) == NULL)
		return -1;

	if ((strlen(op->iname) > 8) || len < 11)
		return -1;

	iname = op->iname;
	if (((op->argmask & ASWAP) != 0) && ni->x) {
		str_copy(swname, op->iname, sizeof(swname));
		str_cat(swname, "%", sizeof(swname));
		iname = swname;
	}
	str_fmt(s, len, "%-10s", iname);
	s += 10;
	len -= 10;
	
	if ((op->argmask & PDONLY) != 0)
		return pdesc2str(ni, s, len, (op->argmask & ARGX));

	if ((op->argmask & ARGX) != 0) *ap++ = ni->x;
	if ((op->argmask & ARGY) != 0) *ap++ = ni->y;
	if ((op->argmask & ARGZ) != 0) *ap++ = ni->z;
	if ((op->argmask & ARGW) != 0) {
		if ((op->argmask & BRREL) != 0) {
			*ap++ = sxt64(ni->w, 32) + inum;
			str_copy(a0p, "@", sizeof(a0p));
		} else {
			*ap++ = ni->w;
		}
	}

	switch(op->nargs) {
	case 0: fr = 0;
		break;
	case 1: fr = str_fmt(s, len, "%s%lu", a0p, args[0]);
		break;
	case 2: fr = str_fmt(s, len, "%lu, %lu", args[0], args[1]);
		break;
	case 3: fr = str_fmt(s, len, "%lu, %lu, %lu", args[0], args[1],
			     args[2]);
		break;
	case 4: fr = str_fmt(s, len, "%lu, %lu, %lu, %lu", args[0], args[1],
			     args[2], args[3]);
		break;
	default: abort_unless(0);
	}
	if (fr < 0 || len < fr)
		return -1;

	return len + fr;
}


static void init_asmctx(struct asmctx *ctx)
{
	int i;
	ctx->matchonly = 0;
	for (i = 0; i < NVMP_EP_NUMEP; ++i)
		str_copy(ctx->eps[i], "", sizeof(ctx->eps[0]));
	memset(ctx->consts, 0, sizeof(ctx->consts));
	for (i = 0; i < array_length(ctx->celem); ++i)
		ctx->celem[i] = NULL;
	ht_init(&ctx->ctab, ctx->celem, TABLESIZE, cmp_str, ht_shash, NULL);
	for (i = 0; i < NETVM_MAXMSEGS; ++i)
		ctx->sdescs[i].perms = 0;
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		ctx->cpreqs[i] = NETVM_CPT_NONE;
	ctx->numi = 0;
	ctx->numf = 0;
	ctx->numc = 0;
	ctx->curfile = NULL;
	ctx->ninits = 0;
}


static void free_asmctx(struct asmctx *ctx)
{
	int i;
	struct constant *c;

	for (i = 0; i < ctx->numi; ++i) {
		free(ctx->instrs[i].str);
		ctx->instrs[i].str = NULL;
	}

	i = 0;
	c = &ctx->consts[0];
	while (i < MAXCONST && c->hn.key != NULL) {
		free(c->hn.key);
		c->hn.key = NULL;
		++i;
		++c;
	}
}


static int do_include(struct asmctx *ctx, char *fn, uint lineno,
		      struct raw toks[], uint nt)
{
	FILE *fp;
	int ne;

	if (nt != 2) {
		logrec(1, "invalid number of args for .include "
			  "in file %s on line %u; expected 2\n",
		       fn, lineno);
		return 1;
	}
	if ((fp = fopen(toks[1].data, "r")) == NULL) {
		logsys(1, "unable to open file %s "
			  "(included on line %s line %u)", 
		       toks[1].data, fn, lineno);
		return 1;
	}
	ne = assemble(ctx, toks[1].data, fp);
	fclose(fp);

	return ne;
}


static int do_define(struct asmctx *ctx, char *fn, uint lineno,
		     struct raw toks[], uint nt)
{
	ulong v;
	int rv;

	if (nt != 3) {
		logrec(1, "invalid number of args for .define "
			  "in file %s on line %u; expected 3\n",
		       fn, lineno);
		return 1;
	}
	if (!isalnum(toks[1].data[0]) || 
	    strspn(toks[1].data, IDCHARS) != toks[1].len) {
		logrec(1, "invalid .define token "
			  "in file %s on line %u\n",
		       fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[2], &ctx->ctab, &v)) != 0) {
		logrec(1, "invalid numeric value '%s' in .define "
			  "directive in file %s on line %u: %s\n",
		       toks[2].data, fn, lineno, estrs[rv]);
		return 1;
	}

	if (find_const(&ctx->ctab, toks[1].data, NULL)) {
		logrec(1, "attempting to redefine '%s' in .define "
			  "directive in file %s on line %u\n",
		       toks[1].data, fn, lineno);
		return 1;
	} else if (ctx->numc == MAXCONST) {
		logrec(1, "Out of space for constants adding const '%s'\n", 
		       toks[1].data);
		return -1;
	} else {
		add_const(&ctx->ctab, &ctx->consts[ctx->numc++], toks[1].data,
			  v);
	}

	return 0;
}


static int do_segment(struct asmctx *ctx, char *fn, uint lineno,
		      struct raw toks[], uint nt)
{
	ulong segnum;
	ulong perms;
	ulong seglen;
	struct netvm_segdesc *sd;
	int rv;

	if (nt != 4) {
		logrec(1, "invalid number of args for .segment "
			  "in file %s on line %u; expected 3\n",
		       fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[1], &ctx->ctab, &segnum)) != 0) {
		logrec(1, "invalid segment number '%s' in .segment "
		          "directive in file %s on line %u: %s\n",
		       toks[1].data, fn, lineno, estrs[rv]);
		return 1;
	}
	if (segnum >= NETVM_MAXMSEGS) {
		logrec(1, "Invalid memory segment (%u) in file %s"
		          "on line %s\n", (uint)segnum, fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[2], &ctx->ctab, &perms)) != 0) {
		logrec(1, "invalid permissions value '%s' in .segment "
		          "directive in file %s on line %u: %s\n",
		       toks[2].data, fn, lineno, estrs[rv]);
		return 1;
	}
	if ((perms & ~NETVM_SEG_PMASK) != 0) {
		logrec(1, "Invalid permissions for segment %u in file %s"
		          "on line %s\n", (uint)segnum, fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[3], &ctx->ctab, &seglen)) != 0) {
		logrec(1, "invalid segment length '%s' in .segment "
		          "directive in file %s on line %u: %s\n",
		       toks[3].data, fn, lineno, estrs[rv]);
		return 1;
	}
	if (seglen > UINT_MAX) {
		logrec(1, "Invalid segment length (%lu) in file %s"
		          "on line %s\n", seglen, fn, lineno);
		return 1;
	}

	sd = &ctx->sdescs[segnum];
	if (sd->perms != 0) {
		logrec(1, "redefinition of segment %u in file %s"
		          "on line %s\n", (uint)segnum, fn, lineno);
		return 1;
	}

	sd->len = seglen;
	sd->perms = perms;

	return 0;
}


static int do_matchonly(struct asmctx *ctx, char *fn, uint lineno, 
			struct raw toks[], uint nt)
{
	if (nt != 1) {
		logrec(1, "unexpected arguments in .matchonly " 
			  "directive in file %s on line %u\n",
		       fn, lineno);
		return 1;
	}
	ctx->matchonly = 1;
	return 0;
}


static int do_mem(struct asmctx *ctx, char *fn, uint lineno, 
		  struct raw toks[], uint nt)
{
	ulong segnum, addr, len;
	struct netvm_meminit *mi;
	int rv;
	char *k;

	if (nt < 5 || nt > 6) {
		logrec(1, "invalid number of arguments in .mem directive "
			  "in file %s on line %u: expected 5 or 6\n",
		       fn, lineno, nt);
		return 1;
	}

	if (ctx->ninits >= MAXMEMINIT) {
		logrec(1, "out of memory initialization slots for .mem "
			  "directive in file %s on line %u\n",
		       fn, lineno);
		return 1;
	}
	if (ctx->numc > MAXCONST-2) {
		logrec(1, "out of space for constants for .mem "
			  "directive in file %s on line %u\n",
		       fn, lineno);
		return 1;
	}

	if (!isalnum(toks[1].data[0]) || 
	    (toks[1].len > MAXSTR - 6) ||
	    strspn(toks[1].data, IDCHARS) != toks[1].len) {
		logrec(1, "invalid .mem name in file %s on line %u\n",
		       fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[2], &ctx->ctab, &segnum)) != 0) {
		logrec(1, "invalid segment number '%s' in .mem "
		          "directive in file %s on line %u: %s\n",
		       toks[2].data, fn, lineno, estrs[rv]);
		return 1;
	}
	if (segnum >= NETVM_MAXMSEGS) {
		logrec(1, "invalid segment number '%u' in .mem "
		          "directive in file %s on line %u\n",
		       segnum, fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[3], &ctx->ctab, &addr)) != 0) {
		logrec(1, "invalid address '%s' in .mem "
		          "directive in file %s on line %u: %s\n",
		       toks[3].data, fn, lineno, estrs[rv]);
		return 1;
	}

	if ((rv = intarg(&toks[4], &ctx->ctab, &len)) != 0) {
		logrec(1, "invalid number of bytes '%s' in .mem "
		          "directive in file %s on line %u: %s\n",
		       toks[4].data, fn, lineno, estrs[rv]);
		return 1;
	}

	if ((len > UINT_MAX) || (UINT_MAX - len < addr)) {
		logrec(1, "invalid mem region (%lu to %lu) in .mem "
		          "directive in file %s on line %u\n",
		       addr, addr + len - 1, fn, lineno);
		return 1;
	}

	if ((nt == 6) && (toks[5].len > len)) {
		logrec(1, "initialization data in .mem larger than region "
		          "in file %s on line %u\n",
		       fn, lineno);
		return 1;
	}

	k = emalloc(toks[1].len + 6);
	memcpy(k, toks[1].data, toks[1].len);
	str_copy(k + toks[1].len, ".addr", 6);
	if (find_const(&ctx->ctab, k, NULL)) {
		logrec(1, "duplicate .mem name '%s' in file %s on line %u\n",
		       toks[1].data, fn, lineno);
		return 1;
	}
	add_const(&ctx->ctab, &ctx->consts[ctx->numc++], k, addr);

	k = emalloc(toks[1].len + 5);
	memcpy(k, toks[1].data, toks[1].len);
	str_copy(k + toks[1].len, ".seg", 5);
	abort_unless(!find_const(&ctx->ctab, k, NULL));
	add_const(&ctx->ctab, &ctx->consts[ctx->numc++], k, segnum);

	mi = &ctx->minits[ctx->ninits++];
	mi->segnum = segnum;
	mi->off = addr;
	mi->val.len = len;
	if (nt == 6) {
		mi->val.data = ecalloc(1, len);
		memcpy(mi->val.data, toks[5].data, toks[5].len);
	} else {
		mi->val.data = NULL;
	}

	return 0;
}


static int do_coproc(struct asmctx *ctx, char *fn, uint lineno,
		     struct raw toks[], uint nt)
{
	int rv;
	ulong cpi, cpt;

	if (nt != 3) {
		logrec(1, "invalid number of args for .segment "
			  "in file %s on line %u; expected 2\n",
		       fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[1], &ctx->ctab, &cpi)) != 0) {
		logrec(1, "invalid coprocessor index '%s' in .coproc "
		          "directive in file %s on line %u: %s\n",
		       toks[1].data, fn, lineno, estrs[rv]);
		return 1;
	}

	if ((rv = intarg(&toks[2], &ctx->ctab, &cpt)) != 0) {
		logrec(1, "invalid coprocessor type '%s' in .segment "
		          "directive in file %s on line %u: %s\n",
		       toks[2].data, fn, lineno, estrs[rv]);
		return 1;
	}

	if (cpi >= NETVM_MAXCOPROC) {
		logrec(1, "coprocessor index %lu out of range in .coproc "
		          "directive in file %s on line %u\n",
		       cpi, fn, lineno);
		return 1;
	}

	ctx->cpreqs[cpi] = cpt;

	return 0;
}


static int do_entry(struct asmctx *ctx, char *fn, uint lineno,
		    struct raw toks[], uint nt)
{
	int epi;
	if (nt != 3) {
		logrec(1, "invalid number of args for .entry "
			  "in file %s on line %u; expected 3\n",
		       fn, lineno);
		return 1;
	}
	for (epi = 0; epi < NVMP_EP_NUMEP; ++epi)
		if (strcmp(toks[1].data, epnames[epi]) == 0)
			break;
	if (epi == NVMP_EP_NUMEP) {
		logrec(1, "erroneous entry point type: '%s'"
			  " in file %s on line %u\n",
		       toks[1].data, fn, lineno);
		return 1;
	}
	if (strcmp(ctx->eps[epi], "") != 0) {
		logrec(1, "multiple %s entry points specified:"
			  " dup is in file %s on line %u\n",
		       toks[1], fn, lineno);
		return 1;
	}
	if (strcmp(toks[2].data, "") == 0 || 
	    toks[2].len == sizeof(ctx->eps[0])) {
		logrec(1, "invalid entry point '%s' specified"
			  " in file %s on line %u\n", 
		       toks[2].data, fn, lineno);
		return 1;
	}
	str_copy(ctx->eps[epi], toks[2].data, sizeof(ctx->eps[0]));

	return 0;
}


int parse_asm_directive(struct asmctx *ctx, char *s, char *fn, uint lineno)
{
	struct raw toks[MAXTOKS];
	int nt;

	if ((nt = tokenize(s, toks, array_length(toks), 0)) <= 0) {
		logrec(1, "invalid directive in file %s on line %u\n",
		       fn, lineno);
		return 1;
	}

	if (strcmp(toks[0].data, "include") == 0) {
		return do_include(ctx, fn, lineno, toks, nt);
	} else if (strcmp(toks[0].data, "define") == 0) {
		return do_define(ctx, fn, lineno, toks, nt);
	} else if (strcmp(toks[0].data, "segment") == 0) {
		return do_segment(ctx, fn, lineno, toks, nt);
	} else if (strcmp(toks[0].data, "matchonly") == 0) {
		return do_matchonly(ctx, fn, lineno, toks, nt);
	} else if (strcmp(toks[0].data, "mem") == 0) {
		return do_mem(ctx, fn, lineno, toks, nt);
	} else if (strcmp(toks[0].data, "coproc") == 0) {
		return do_coproc(ctx, fn, lineno, toks, nt);
	} else if (strcmp(toks[0].data, "entry") == 0) {
		return do_entry(ctx, fn, lineno, toks, nt);
	} else {
		logrec(1, "unknown directive '%s' on file %s line %u\n",
		       toks[0].data, fn, lineno);
		return 1;
	}
}


static int assemble(struct asmctx *ctx, const char *fn, FILE *input)
{
	struct instruction *in;
	char line[MAXSTR], *cp, *ep, buf[MAXSTR];
	uint lineno = 0;
	int rv;
	uint i;
	uint ne = 0;
	char *prevfile;

	if (ctx->numf >= MAXFILES) {
		logrec(1, "Can't add file '%s' to the assembly "
		          "-- too many files\n", fn);
		return 1;
	}
	str_copy(ctx->files[ctx->numf], fn, MAXSTR);
	prevfile = ctx->curfile;
	ctx->curfile = ctx->files[ctx->numf++];

	while (fgets(line, sizeof(line), input)) {
		lineno += 1;
		cp = line + strspn(line, WS);
		if (*cp == '\0' || *cp == '#')
			continue;
		if (*cp == '.') {
			ne += parse_asm_directive(ctx, cp+1, ctx->curfile, lineno);
			continue;
		}
		ep = cp + strspn(cp, LABELCHARS);
		if (*ep == ':') {
			*ep = '\0';
			buf[0] = '@';
			str_copy(buf+1, cp, MAXSTR-1);
			if (find_const(&ctx->ctab, buf, NULL)) {
				logrec(1, "Duplicate label '%s:' in %s:%u\n",
				       buf+1, ctx->curfile, lineno);
				ne += 1;
			} else if (ctx->numc == MAXCONST) {
				logrec(1, "Out of space for constants "
					  "adding label '%s'\n", buf);
				return ne + 1;
			} else {
				add_const(&ctx->ctab, &ctx->consts[ctx->numc++],
					  buf, ctx->numi);
			}
			cp = ep + 1;
			cp = cp + strspn(cp, WS);
			if (*cp == '\0')
				continue;
		}

		if (ctx->numi == MAXINSTR) {
			logrec(1, "Out of space for instructions "
			          "on file '%s' line %u\n", ctx->curfile,
			       lineno);
			return ne + 1;
		}

		in = ctx->instrs + ctx->numi;
		in->str = estrdup(cp);
		in->inum = ctx->numi;
		in->lineno = lineno;
		in->fname = ctx->curfile;
		ctx->numi++;
	}

	ctx->curfile = prevfile;

	if (prevfile == NULL) {
		/* if we've exited the first file in the system, finalize: */
		for (i = 0; i < ctx->numi; ++i) {
			in = &ctx->instrs[i];
			rv = str2inst(in->str, &ctx->ctab, in->inum,
				      &in->instr);
			if (rv != 0) {
				logrec(1, "Error assembling file %s:%u -- %s\n",
				       in->fname, in->lineno, estrs[rv]);
				ne += 1;
			}
		}
	}

	return ne;
}


static void resolve_entry_points(struct asmctx *ctx, struct netvm_program *prog)
{
	int hasep = 0;
	int i;
	ulong ep = 0;

	for (i = 0; i < NVMP_EP_NUMEP; ++i) {
		prog->eps[i] = NVMP_EP_INVALID;
		if (strcmp(ctx->eps[i], "") != 0) {
			if (isdigit(ctx->eps[i][0])) {
				ep = strtoul(ctx->eps[i], NULL, 0);
			} else {
				if (!find_const(&ctx->ctab, ctx->eps[i], &ep))
					err("entry point '%s' unknown",
					    ctx->eps[i]);
			}
			prog->eps[i] = ep;
			hasep = 1;
		}
	}

	/* if there are no entry points specified, default to a starting the */
	/* program with the start entry point at instruction 0 */
	if (!hasep)
		prog->eps[NVMP_EP_START] = 0;
}


void emit_program(struct asmctx *ctx, FILE *outfile)
{
	struct netvm_program prog;
	struct netvm_inst *istore;
	struct netvm_meminit *mi;
	int i;

	resolve_entry_points(ctx, &prog);

	istore = emalloc(sizeof(struct netvm_inst) * ctx->numi);
	prog.matchonly = ctx->matchonly;
	prog.inst = istore;
	prog.ninst = ctx->numi;
	for (i = 0; i < ctx->numi; ++i)
		istore[i] = ctx->instrs[i].instr;
	for (i = 0; i < NETVM_MAXMSEGS; ++i)
		prog.sdescs[i] = ctx->sdescs[i];
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		prog.cpreqs[i] = ctx->cpreqs[i];
	prog.inits = NULL;
	prog.ninits = ctx->ninits;
	if (prog.ninits != 0) {
		mi = ecalloc(sizeof(struct netvm_meminit), prog.ninits);
		abort_unless(SIZE_MAX / sizeof(struct netvm_meminit) >= 
			     prog.ninits);
		memcpy(mi, ctx->minits, 
		       sizeof(struct netvm_meminit) * prog.ninits);
		prog.inits = mi;
	}

	nvmp_write(&prog, outfile);
	nvmp_clear(&prog);
}


void disassemble(FILE *infile, FILE *outfile)
{
	struct netvm_program prog;
	char line[MAXSTR];
	uint i;
	struct netvm_segdesc *sd;

	if (nvmp_read(&prog, infile, &i) < 0)
		err("unable to read input file: %d\n", i);

	fprintf(outfile, "# Declarations\n");

	if (prog.matchonly)
		fprintf(outfile, ".matchonly\n");
	for (i = 0; i < NVMP_EP_NUMEP; ++i)
		if (prog.eps[i] != NVMP_EP_INVALID)
			fprintf(outfile, ".entry %s %u\n", epnames[i], 
				prog.eps[i]);

	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		sd = &prog.sdescs[i];
		if (sd->perms == 0)
			continue;
		fprintf(outfile, ".segment %u, %u, %u\n", i, sd->perms, 
			sd->len);
	}

	for (i = 0; i < NETVM_MAXCOPROC; ++i) {
		if (prog.cpreqs[i] != NETVM_CPT_NONE)
			fprintf(outfile, ".coproc %u %llu\n", i, 
			        (unsigned long long)prog.cpreqs[i]);
	}

	fprintf(outfile, "\n# Instructions (%u total)\n", prog.ninst);
	for (i = 0; i < prog.ninst; ++i) {
		struct netvm_inst *ni = &prog.inst[i];
		if (inst2str(ni, line, sizeof(line), i) < 0) {
			if (skip_errors) {
				fprintf(outfile, "#%4u: 0x%02x 0x%02x 0x%02x "
						 "0x%02x 0x%08lx\n",
					i, ni->op, ni->x, ni->y, ni->z,
					(ulong)ni->w);
				fprintf(outfile, "*Could not disassemble*\n");
			} else {
				err("error disassembling instruction %u\n", i);
			}
		} else {
			fprintf(outfile, "#%4u: 0x%02x 0x%02x 0x%02x 0x%02x "
					 "0x%08lx\n\t%s\n", 
				i, ni->op, ni->x, ni->y, ni->z, (ulong)ni->w,
				line);
		}
	}

	nvmp_clear(&prog);
}


void usage()
{
	char buf[4096];
	fprintf(stderr, "usage: nvmas [options] [infile [outfile]]\n");
	optparse_print(&optparser, buf, sizeof(buf));
	str_cat(buf, "\n", sizeof(buf));
	fprintf(stderr, "%s", buf);
	exit(1);
}


int main(int argc, char *argv[])
{
	struct clopt *opt;
	int rv;
	int do_assemble = 1;
	const char *ifn = "<stdin>";
	FILE *infile = stdin;
	FILE *outfile = stdout;
	struct asmctx ctx;

	optparse_reset(&optparser, argc, argv);
	while ((rv = optparse_next(&optparser, &opt)) == 0) {
		if (opt->ch == 'h')
			usage();
		if (opt->ch == 'd')
			do_assemble = 0;
		if (opt->ch == 'e')
			skip_errors = 1;
	}
	if (rv < 0)
		usage();

	if (rv < argc) {
		ifn = argv[rv];
		if (strcmp(ifn, "-") == 0) {
			infile = stdin;
			ifn = "<stdin>";
		} else {
			infile = fopen(ifn, "r");
			if (infile == NULL)
				errsys("Unable to open file '%s' for reading\n", 
				       ifn);
		}
	}

	if (rv < argc - 1) {
		if (strcmp(argv[rv+1], "-") == 0) {
			outfile = stdout;
		} else {
			outfile = fopen(argv[rv+1], "w");
			if (outfile == NULL)
				errsys("Unable to open file '%s' for writing\n",
				       argv[rv+1]);

		}
	}


	if (do_assemble) {
		init_asmctx(&ctx);
		if ((rv = assemble(&ctx, ifn, infile)) != 0)
			err("Exiting:  %d errors\n", rv);
		fclose(infile);
		emit_program(&ctx, outfile);
		free_asmctx(&ctx);
		fclose(outfile);
	} else {
		disassemble(infile, outfile);
	}

	return 0;
}
