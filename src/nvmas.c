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

#define MAXSTR 256

/*
 Example code: 

# comment
.include "filename"
.define PPT_TCP		0x0006
.define RWSEG		0
.define RWPERMS 	3
.segment RWSEG RWPERMS 1024
.define CPT_XPKT	1
.coproc 0 CPT_XPKT
.mem name segnum nbytes [init]

label:	add 
	jmpi, &label
	bzi, 3
	cpop 0, 0, z, w
	pkfxl 0:PPT_TCP:0
*/

struct clopt options[] = { 
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help and exit"), 
	CLOPT_INIT(CLOPT_NOARG, 'd', "--disassemble", "disassemble file"),
};
struct clopt_parser optparser = CLOPTPARSER_INIT(options, array_length(options));


struct nvmop {
	char *		iname;
	uint8_t		opcode;
	uchar 		nargs;
	ushort		argmask;
};


/* in argmask */
#define ARGX 1 
#define ARGY 2
#define ARGZ 4
#define ARGW 8
#define PDONLY 0x10
#define PDOPT  0x20
#define BRREL  0x40
#define MAXARGS 4
#define MAXTOKS (MAXARGS+1)
#define IDCHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" \
		"0123456789_"
#define LABELCHARS IDCHARS


struct nvmop Operations[] = {
	{ "pop",    NETVM_OC_POP,    1, ARGW },
	{ "popto",  NETVM_OC_POPTO,  1, ARGW },
	{ "push",   NETVM_OC_PUSH,   1, ARGW },
	{ "pushhi", NETVM_OC_PUSHHI, 1, ARGW },
	{ "zpush",  NETVM_OC_ZPUSH,  1, ARGW },
	{ "dup",    NETVM_OC_DUP,    1, ARGW },
	{ "swap",   NETVM_OC_SWAP,   1, ARGW },
	{ "ldbp",   NETVM_OC_LDBP,   0, 0 },
	{ "ldbpi",  NETVM_OC_LDBPI,  1, ARGW },
	{ "stbp",   NETVM_OC_STBP,   0, 0 },
	{ "stbpi",  NETVM_OC_STBPI,  1, ARGW },
	{ "pfe",    NETVM_OC_PFE,    0, 0 },
	{ "pfei",   NETVM_OC_PFEI,   4, ARGX|ARGY|ARGZ|ARGW|PDONLY },
	{ "ldpf",   NETVM_OC_LDPF,   0, 0 },
	{ "ldpfi",  NETVM_OC_LDPFI,  4, ARGX|ARGY|ARGZ|ARGW|PDONLY },
	{ "ld",     NETVM_OC_LD,     2, ARGX|ARGY },
	{ "ldi",    NETVM_OC_LDI,    4, ARGX|ARGY|ARGZ|ARGW|PDOPT },
	{ "cmp",    NETVM_OC_CMP,    0, 0 },
	{ "pcmp",   NETVM_OC_PCMP,   0, 0 },
	{ "mskcmp", NETVM_OC_MSKCMP, 0, 0 },
	{ "not",    NETVM_OC_NOT,    0, 0 },
	{ "invert", NETVM_OC_INVERT, 0, 0 },
	{ "tobool", NETVM_OC_TOBOOL, 0, 0 },
	{ "popl",   NETVM_OC_POPL,   0, 0 },
	{ "nlz",    NETVM_OC_NLZ,    0, 0 },
	{ "signx",  NETVM_OC_SIGNX,  1, ARGX },
	{ "add",    NETVM_OC_ADD,    0, 0 },
	{ "addi",   NETVM_OC_ADDI,   1, ARGW },
	{ "sub",    NETVM_OC_SUB,    0, 0 },
	{ "subi",   NETVM_OC_SUBI,   1, ARGW },
	{ "mul",    NETVM_OC_MUL,    0, 0 },
	{ "muli",   NETVM_OC_MULI,   1, ARGW },
	{ "div",    NETVM_OC_DIV,    0, 0 },
	{ "divi",   NETVM_OC_DIVI,   1, ARGW },
	{ "mod",    NETVM_OC_MOD,    0, 0 },
	{ "modi",   NETVM_OC_MODI,   1, ARGW },
	{ "shl",    NETVM_OC_SHL,    0, 0 },
	{ "shli",   NETVM_OC_SHLI,   1, ARGW },
	{ "shr",    NETVM_OC_SHR,    0, 0 },
	{ "shri",   NETVM_OC_SHRI,   1, ARGW },
	{ "shra",   NETVM_OC_SHRA,   0, 0 },
	{ "shrai",  NETVM_OC_SHRAI,  1, ARGW },
	{ "and",    NETVM_OC_AND,    0, 0 },
	{ "andi",   NETVM_OC_ANDI,   1, ARGW },
	{ "or",     NETVM_OC_OR,     0, 0 },
	{ "ori",    NETVM_OC_ORI,    1, ARGW },
	{ "xor",    NETVM_OC_XOR,    0, 0 },
	{ "xori",   NETVM_OC_XORI,   1, ARGW },
	{ "eq",     NETVM_OC_EQ,     0, 0 },
	{ "eqi",    NETVM_OC_EQI,    1, ARGW },
	{ "neq",    NETVM_OC_NEQ,    0, 0 },
	{ "neqi",   NETVM_OC_NEQI,   1, ARGW },
	{ "lt",     NETVM_OC_LT,     0, 0 },
	{ "lti",    NETVM_OC_LTI,    1, ARGW },
	{ "le",     NETVM_OC_LE,     0, 0 },
	{ "lei",    NETVM_OC_LEI,    1, ARGW },
	{ "gt",     NETVM_OC_GT,     0, 0 },
	{ "gti",    NETVM_OC_GTI,    1, ARGW },
	{ "ge",     NETVM_OC_GE,     0, 0 },
	{ "gei",    NETVM_OC_GEI,    1, ARGW },
	{ "ult",    NETVM_OC_ULT,    0, 0 },
	{ "ulti",   NETVM_OC_ULTI,   1, ARGW },
	{ "ule",    NETVM_OC_ULE,    0, 0 },
	{ "ulei",   NETVM_OC_ULEI,   1, ARGW },
	{ "ugt",    NETVM_OC_UGT,    0, 0 },
	{ "ugti",   NETVM_OC_UGTI,   1, ARGW },
	{ "uge",    NETVM_OC_UGE,    0, 0 },
	{ "ugei",   NETVM_OC_UGEI,   1, ARGW },
	{ "getcpt", NETVM_OC_GETCPT, 0, 0 },
	{ "cpopi",  NETVM_OC_CPOPI,  4, ARGX|ARGY|ARGZ|ARGW },
	{ "bri",    NETVM_OC_BRI,    1, ARGW|BRREL },
	{ "bnzi",   NETVM_OC_BNZI,   1, ARGW|BRREL },
	{ "bzi",    NETVM_OC_BZI,    1, ARGW|BRREL },
	{ "jmpi",   NETVM_OC_JMPI,   1, ARGW },
	{ "halt",   NETVM_OC_HALT,   1, ARGW },
	{ "cpop",   NETVM_OC_CPOP,   0, 0 },
	{ "br",     NETVM_OC_BR,     0, 0 },
	{ "bnz",    NETVM_OC_BNZ,    0, 0 },
	{ "bz",     NETVM_OC_BZ,     0, 0 },
	{ "pushpc", NETVM_OC_PUSHPC, 1, ARGW },
	{ "jmp",    NETVM_OC_JMP,    0, 0 },
	{ "call",   NETVM_OC_CALL,   1, ARGW },
	{ "ret",    NETVM_OC_RET,    1, ARGW },
	{ "popbp",  NETVM_OC_POPBP,  0, 0 },
	{ "st",     NETVM_OC_ST,     2, ARGX|ARGY },
	{ "sti",    NETVM_OC_STI,    4, ARGX|ARGY|ARGZ|ARGW|PDOPT },
	{ "move",   NETVM_OC_MOVE,   0, 0 },
	{ "pkswap", NETVM_OC_PKSWAP, 0, 0 },
	{ "pknew",  NETVM_OC_PKNEW,  0, 0 },
	{ "pkcopy", NETVM_OC_PKCOPY, 0, 0 },
	{ "pksla",  NETVM_OC_PKSLA,  1, ARGX },
	{ "pkcla",  NETVM_OC_PKCLA,  1, ARGX },
	{ "pkppsh", NETVM_OC_PKPPSH, 1, ARGX },
	{ "pkppop", NETVM_OC_PKPPOP, 1, ARGX },
	{ "pkdel",  NETVM_OC_PKDEL,  0, 0 },
	{ "pkdeli", NETVM_OC_PKDELI, 1, ARGX },
	{ "pkfxd",  NETVM_OC_PKFXD,  0, 0 },
	{ "pkfxdi", NETVM_OC_PKFXDI, 1, ARGX },
	{ "pkpup",  NETVM_OC_PKPUP,  0, 0 },
	{ "pkpupi", NETVM_OC_PKPUPI, 4, ARGX|ARGY|ARGZ|ARGW|PDONLY },
	{ "pkfxl",  NETVM_OC_PKFXL,  0, 0 },
	{ "pkfxli", NETVM_OC_PKFXLI, 4, ARGX|ARGY|ARGZ|ARGW|PDONLY },
	{ "pkfxc",  NETVM_OC_PKFXC,  0, 0 },
	{ "pkfxci", NETVM_OC_PKFXCI, 4, ARGX|ARGY|ARGZ|ARGW|PDONLY },
	{ "pkins",  NETVM_OC_PKINS,  1, ARGX },
	{ "pkcut",  NETVM_OC_PKCUT,  1, ARGX },
	{ "pkadj",  NETVM_OC_PKADJ,  0, 0 },

	{ NULL,  0,  0, 0 },
};


#define TABLESIZE	256
#define MAXINSTR	65536
#define MAXCONST	65536
#define MAXFILES	256
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
	char			files[MAXFILES][MAXSTR];
	uint			numf;
	char *			curfile;
	struct constant		consts[MAXCONST];
	uint			numc;
	struct hnode *		celem[TABLESIZE];
	struct htab 		ctab;
	struct hnode *		lelem[TABLESIZE];
	struct htab 		ltab;
	struct netvm_segdesc    sdescs[NETVM_MAXMSEGS];
	uint64_t                cpreqs[NETVM_MAXCOPROC];
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


int set_const(struct htab *t, const char *name, ulong v)
{
	struct hnode *hn;
	struct constant *c;
	if ((hn = ht_lkup(t, name, NULL)) == NULL)
		return 0;
	c = hn->data;
	c->val = v;
	return 1;
}


void add_const(struct htab *t, struct constant *c, const char *name, ulong v)
{
	c->val = v;
	ht_ninit(&c->hn, estrdup(name), &c);
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


static int tokenize(char *s, struct raw toks[], uint maxtoks)
{
	int na = 0;
	int first = 1;
	struct raw *r = toks;

	while (*s != '\0') {
		s = s + strspn(s, " \t\n");
		if (*s == '\0')
			return na;
		if (na == maxtoks)
			return -ERR_NARG;
		if (*s == '"') {
			r->data = s+1;
			s = parse_quoted_string(s+1, &r->len);
			if (s == NULL)
				return -ERR_BADTOK;
		} else {
			r->data = s;
			s = s + strcspn(s, " \t\n");
			r->len = (byte_t*)s - r->data;
			if (*s != '\0') {
				*s++ = '\0';
				s = s + strspn(s, " \t\n");
				if (!first && *s == ',')
					++s;
				else if (!first && *s != '\0')
					return -ERR_BADTOK;
			}
		}
		first = 0;
		++r;
		++na;
	}

	return na;
}


/* example: *0:tcp.0.0[3] */
/* example: *0:0x0103.0.0[4] */
static int read_pdesc(char *s, int multiseg, struct netvm_inst *ni,
		      struct htab *ct)
{
	char *cp;
	char pname[MAXSTR];
	uchar pktnum, index, field;
	uint ppt, offset;
	ulong v;

	pktnum = strtoul(s, &cp, 0);
	if ((cp == s) || (*cp != ':') || (pktnum >= NETVM_MAXPKTS))
		return -1;
	s = cp + 1;
	if (isalpha(*s)) {
		cp = s + strcspn(s, ".");
		if (*cp != '.')
			return -1;
		memcpy(pname, s, cp - s);
		pname[cp - s] = '\0';
		if (!find_const(ct, pname, &v))
			return -1;

		ppt = v & NETVM_PPD_PPT_MASK;
	} else {
		ppt = strtoul(s, &cp, 0) & NETVM_PPD_PPT_MASK;
		if ((cp == s) || (*cp != '.'))
			return -1;
	}

	s = cp + 1;

	index = strtoul(s, &cp, 0) & NETVM_PPD_IDX_MASK;
	if ((cp == s) || (*cp != '.'))
		return -1;
	s = cp + 1;

	field = strtoul(s, &cp, 0) & NETVM_PPD_FLD_MASK;
	if ((cp == s) || (*cp != '['))
		return -1;
	s = cp + 1;

	offset = strtoul(s, &cp, 0) & NETVM_PPD_OFF_MASK;
	if ((cp == s) || (*cp != ']'))
		return -1;

	ni->y = pktnum | (multiseg ? NETVM_SEG_ISPKT : 0);
	ni->z = (index << NETVM_PPD_IDX_OFF) | (field << NETVM_PPD_FLD_OFF);
	ni->w = (index << NETVM_PPD_PPT_OFF) | (field << NETVM_PPD_OFF_OFF);

	return 0;
}


static int intarg(const struct raw *r, struct htab *lt, struct htab *ct,
		  ulong *v)
{
	char *cp;

	if (r->data[0] == '&') {
		if (lt == NULL || !find_const(lt, r->data+1, v))
			return ERR_UNKLBL;
	} else if (isalpha(r->data[0])) {
		if (ct == NULL || !find_const(ct, r->data, v))
			return ERR_UNKSYM;
	} else {
		abort_unless(r->data[0] != '\0');
		*v = strtoul(r->data, &cp, 0);
		if (*cp != '\0')
			return ERR_BADNUM;
	}

	return 0;
}


int str2inst(const char *s, struct htab *lt, struct htab *ct,
	     uint inum, struct netvm_inst *ni)
{
	char ns[MAXSTR];
	struct raw toks[MAXTOKS], *r;
	int nt, rv;
	struct nvmop *op;
	ulong v;

	if (str_copy(ns, s, sizeof(ns)) > sizeof(ns))
		return ERR_TOOLONG;
	if ((nt = tokenize(ns, toks, array_length(toks))) <= 0)
		return nt == 0 ? ERR_NARG : -nt;
	if ((op = name2op(toks[0].data)) == NULL)
		return ERR_BADNAME;

	ni->x = ni->y = ni->z = ni->w = 0;
	ni->op = op->opcode;

	if (nt == 2 && toks[1].data[0] == '*') {
		rv = read_pdesc(toks[1].data + 1, op->argmask & PDOPT, ni, ct);
		if (rv < 0)
			return rv;
	} else if (nt - 1 == op->nargs) {
		r = toks + 1;
		if ((op->argmask & ARGX) != 0) {
			if ((rv = intarg(r++, lt, ct, &v)) != 0)
				return rv;
			ni->x = v;
		}
		if ((op->argmask & ARGY) != 0) {
			if ((rv = intarg(r++, lt, ct, &v)) != 0)
				return rv;
			ni->y = v;
		}
		if ((op->argmask & ARGZ) != 0) {
			if ((rv = intarg(r++, lt, ct, &v)) != 0)
				return rv;
			ni->z = v;
		}
		if ((op->argmask & ARGW) != 0) {
			if ((rv = intarg(r++, lt, ct, &v)) != 0)
				return rv;
			if ((op->argmask & BRREL) != 0) {
				abort_unless(v < UINT_MAX);
				ni->w = (uint32_t)(v - inum);
			} else {
				ni->w = v;
			}
		}
	} else {
		return ERR_NARG;
	}

	return 0;
}


static int pdesc2str(const struct netvm_inst *ni, char *s, size_t len)
{
	int r;
	uint ppt = (ni->w >> NETVM_PPD_PPT_OFF) & NETVM_PPD_PPT_MASK;

	/* example: *0:0x0103.0.0[3] */
	r = str_fmt(s, len, "*%u:0x%04x.%u.%u[%u]", ni->y, ppt, 
		    (ni->z >> NETVM_PPD_IDX_OFF) & NETVM_PPD_IDX_MASK,
		    (ni->z >> NETVM_PPD_FLD_OFF) & NETVM_PPD_FLD_MASK,
		    (ni->w >> NETVM_PPD_OFF_OFF) & NETVM_PPD_OFF_MASK);

	return 0;
}


int inst2str(const struct netvm_inst *ni, char *s, size_t len)
{
	struct nvmop *op;
	size_t nc;
	ulong args[MAXARGS], *ap = args;
	int fr;

	if ((op = oc2op(ni->op)) == NULL)
		return -1;

	if ((nc = str_copy(s, op->iname, len)) > len)
		return -1;
	s += nc;
	len -= nc;
	
	if (((op->argmask & PDONLY) != 0) ||
	    (((op->argmask & PDOPT) != 0) && ((ni->y & NETVM_SEG_ISPKT) != 0)))
		return pdesc2str(ni, s, len);

	if ((op->argmask & ARGX) != 0) *ap++ = ni->x;
	if ((op->argmask & ARGY) != 0) *ap++ = ni->y;
	if ((op->argmask & ARGZ) != 0) *ap++ = ni->z;
	if ((op->argmask & ARGW) != 0) *ap++ = ni->w;

	switch(op->nargs) {
	case 0: fr = 0;
		break;
	case 1: fr = str_fmt(s, len, "    %lu", args[0]);
		break;
	case 2: fr = str_fmt(s, len, "    %lu, %lu", args[0], args[1]);
		break;
	case 3: fr = str_fmt(s, len, "    %lu, %lu, %lu", args[0], args[1],
			     args[2]);
		break;
	case 4: fr = str_fmt(s, len, "    %lu, %lu, %lu, %lu", args[0], args[1],
			     args[2], args[3]);
		break;
	default: abort_unless(0);
	}
	if (fr < 0 || len > fr)
		return -1;

	return len + fr;
}


static void init_asmctx(struct asmctx *ctx)
{
	int i;
	ctx->matchonly = 0;
	memset(ctx->consts, 0, sizeof(ctx->consts));
	for (i = 0; i < array_length(ctx->celem); ++i)
		ctx->celem[i] = NULL;
	ht_init(&ctx->ctab, ctx->celem, TABLESIZE, cmp_str, ht_shash, NULL);
	for (i = 0; i < array_length(ctx->lelem); ++i)
		ctx->lelem[i] = NULL;
	ht_init(&ctx->ltab, ctx->lelem, TABLESIZE, cmp_str, ht_shash, NULL);
	for (i = 0; i < NETVM_MAXMSEGS; ++i)
		ctx->sdescs[i].perms = (uint)-1;
	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		ctx->cpreqs[i] = NETVM_CPT_NONE;
	ctx->numi = 0;
	ctx->numf = 0;
	ctx->numc = 0;
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
				 "in file %s on line %u; expected 2",
		       fn, lineno);
		return 1;
	}
	if ((fp = fopen(toks[1].data, "r")) == NULL) {
		logsys(1, "unable to open file %s "
			  "(included on line %s line %u)", 
		       toks[1].data, fn, lineno);
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
				 "in file %s on line %u; expected 3",
		       fn, lineno);
		return 1;
	}
	if (!isalnum(toks[1].data[0]) || 
	    strspn(toks[1].data, IDCHARS) != toks[1].len) {
		logrec(1, "invalid .define token "
				 "in file %s on line %u",
		       fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[2], &ctx->ltab, &ctx->ctab, &v)) != 0) {
		logrec(1, "invalid numeric value '%s' in .define "
				 "directive in file %s on line %u: %s",
		       toks[2].data, fn, lineno, estrs[rv]);
		return 1;
	}

	set_const(&ctx->ctab, toks[1].data, v);

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
			  "in file %s on line %u; expected 3",
		       fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[1], &ctx->ltab, &ctx->ctab, &segnum)) != 0) {
		logrec(1, "invalid segment number '%s' in .segment "
		          "directive in file %s on line %u: %s",
		       toks[1].data, fn, lineno, estrs[rv]);
		return 1;
	}
	if (segnum >= NETVM_MAXMSEGS) {
		logrec(1, "Invalid memory segment (%u) in file %s"
		          "on line %s", (uint)segnum, fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[2], &ctx->ltab, &ctx->ctab, &perms)) != 0) {
		logrec(1, "invalid permissions value '%s' in .segment "
		          "directive in file %s on line %u: %s",
		       toks[2].data, fn, lineno, estrs[rv]);
		return 1;
	}
	if ((perms & ~NETVM_SEG_PMASK) != 0) {
		logrec(1, "Invalid permissions for segment %u in file %s"
		          "on line %s", (uint)segnum, fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[3], &ctx->ltab, &ctx->ctab, &seglen)) != 0) {
		logrec(1, "invalid segment length '%s' in .segment "
		          "directive in file %s on line %u: %s",
		       toks[3].data, fn, lineno, estrs[rv]);
		return 1;
	}
	if (seglen > UINT_MAX) {
		logrec(1, "Invalid segment length (%lu) in file %s"
		          "on lien %s", seglen, fn, lineno);
		return 1;
	}

	sd = &ctx->sdescs[segnum];
	if (sd->perms != (uint)-1) {
		logrec(1, "redefinition of segment %u in file %s"
		          "on line %s", (uint)segnum, fn, lineno);
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
			  "directive in file %s on line %u",
		       fn, lineno);
		return 1;
	}
	ctx->matchonly = 1;
	return 0;
}


static int do_mem(struct asmctx *ctx, char *fn, uint lineno, 
		  struct raw toks[], uint nt)
{
	return 0;
}


static int do_coproc(struct asmctx *ctx, char *fn, uint lineno,
		     struct raw toks[], uint nt)
{
	int rv;
	ulong cpi, cpt;

	if (nt != 3) {
		logrec(1, "invalid number of args for .segment "
			  "in file %s on line %u; expected 2",
		       fn, lineno);
		return 1;
	}

	if ((rv = intarg(&toks[1], &ctx->ltab, &ctx->ctab, &cpi)) != 0) {
		logrec(1, "invalid coprocessor index '%s' in .coproc "
		          "directive in file %s on line %u: %s",
		       toks[1].data, fn, lineno, estrs[rv]);
		return 1;
	}

	if ((rv = intarg(&toks[2], &ctx->ltab, &ctx->ctab, &cpt)) != 0) {
		logrec(1, "invalid coprocessor type '%s' in .segment "
		          "directive in file %s on line %u: %s",
		       toks[2].data, fn, lineno, estrs[rv]);
		return 1;
	}

	if (cpi >= NETVM_MAXCOPROC) {
		logrec(1, "coprocessor index %lu out of range in .coproc "
		          "directive in file %s on line %u",
		       cpi, fn, lineno);
		return 1;
	}

	ctx->cpreqs[cpi] = cpt;

	return 0;
}


int parse_asm_directive(struct asmctx *ctx, char *s, char *fn, uint lineno)
{
	struct raw toks[MAXTOKS];
	uint nt;

	if ((nt = tokenize(s, toks, array_length(toks))) <= 0) {
		logrec(1, "invalid directive in file %s on line %u",
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
	} else {
		logrec(1, "unknown directive '%s' on file %s line %u",
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

	if (ctx->numf >= MAXFILES) {
		logrec(1, "Can't add file '%s' to the assembly "
		          "-- too many files", fn);
		return 1;
	}
	str_copy(ctx->files[ctx->numf], fn, MAXSTR);
	ctx->curfile = ctx->files[ctx->numf++];

	while (fgets(line, sizeof(line), input)) {
		lineno += 1;
		cp = line + strspn(line, " \t\n");
		if (*cp == '\0' && *cp == '#')
			continue;
		if (*cp == '.') {
			parse_asm_directive(ctx, cp+1, ctx->curfile, lineno);
			continue;
		}
		ep = cp + strspn(cp, LABELCHARS);
		if (*ep == ':') {
			memcpy(buf, cp, ep - cp);
			buf[ep - cp + 1] = '\0';
			if (find_const(&ctx->ltab, buf, NULL)) {
				logrec(1, "Duplicate label '%s' in %s:%u",
				       buf, ctx->curfile, lineno);
				ne += 1;
			} else if (ctx->numc == MAXCONST) {
				logrec(1, "Out of space for constants "
					  "adding label '%s'", buf);
				return ne + 1;
			} else {
				add_const(&ctx->ltab, &ctx->consts[ctx->numc++],
					  buf, ctx->numi);
			}
			cp = ep + 1;
			cp = cp + strspn(cp, " \t\n");
			if (*cp == '\0')
				continue;
		}

		if (ctx->numi == MAXINSTR) {
			logrec(1, "Out of space for instructions "
			          "on file '%s' line %u", ctx->curfile, lineno);
			return ne + 1;
		}

		in = ctx->instrs + ctx->numi;
		in->str = estrdup(cp);
		in->inum = ctx->numi;
		in->lineno = lineno;
		in->fname = ctx->curfile;
		ctx->numi++;
	}

	for (i = 0; i < ctx->numi; ++i) {
		in = &ctx->instrs[i];
		rv = str2inst(in->str, &ctx->ltab, &ctx->ctab, in->inum,
			      &in->instr);
		if (rv != 0) {
			logrec(1, "Error assembling file %s:%u -- %s",
			       in->fname, in->lineno, estrs[rv]);
			ne += 1;
		}
	}

	return ne;
}


void emit_program(struct asmctx *ctx, FILE *outfile)
{
	struct netvm_program prog;
	struct netvm_inst *istore;
	int i;

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
		err("unable to read input file: %d", i);

	fprintf(outfile, "# Declarations\n");

	if (prog.matchonly)
		fprintf(outfile, ".matchonly\n");

	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		sd = &prog.sdescs[i];
		if (sd->perms == 0)
			continue;
		fprintf(outfile, ".segment %u, %u, %u\n", i, sd->perms, 
			sd->len);
	}

	for (i = 0; i < NETVM_MAXCOPROC; ++i) {
		if (prog.cpreqs[i] != NETVM_CPT_NONE)
			fprintf(outfile, ".coproc %u %llu", i, 
			        (unsigned long long)prog.cpreqs[i]);
	}

	fprintf(outfile, "\n# Instructions (%u total)\n", prog.ninst);
	for (i = 0; i < prog.ninst; ++i) {
		if (inst2str(&prog.inst[i], line, sizeof(line)) < 0)
			err("error disassembling instruction %u\n", i);
		fprintf(outfile, "# %8u\n\t%s\n", i, line);
	}

	nvmp_clear(&prog);
}


void usage()
{
	char buf[4096];
	fprintf(stderr, "usage: nvmas [options]\n");
	optparse_print(&optparser, buf, sizeof(buf));
	str_cat(buf, "\n", sizeof(buf));
	fprintf(stderr, "%s\n", buf);
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
				errsys("Unable to open file '%s' for reading", 
				       ifn);
		}
	}

	if (rv < argc - 1) {
		if (strcmp(argv[rv+1], "-") == 0) {
			outfile = stdout;
		} else {
			outfile = fopen(argv[rv+1], "w");
			if (outfile == NULL)
				errsys("Unable to open file '%s' for writing",
				       argv[rv+1]);

		}
	}


	if (do_assemble) {
		init_asmctx(&ctx);
		if ((rv = assemble(&ctx, ifn, infile)) != 0)
			err("Exiting:  %d errors", rv);
		fclose(infile);
		emit_program(&ctx, outfile);
		free_asmctx(&ctx);
		fclose(outfile);
	} else {
		disassemble(infile, outfile);
	}

	return 0;
}
