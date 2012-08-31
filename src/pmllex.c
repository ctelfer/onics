#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#include <cat/cat.h>
#include <cat/str.h>
#include <cat/hash.h>
#include <cat/buffer.h>
#include <cat/inport.h>
#include <cat/stdclio.h>
#include <cat/list.h>

#include "pml.h"
#include "pmllex.h"


#define SIDCHARS "_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define IDCHARS \
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
#define WSCHARS " \t\r\n"
#define OPCHARS "=!<>~+-*/%&|^.@?{}[](),;$"
#define QUOTE		'"'
#define REXQUOTE	'`'

#define NEXTCNONE	-1
#define NEXTCEOF	-2
#define NEXTCERR	-3

enum {
	NTYPE, FTYPE, STYPE
};


struct inputs {
	struct list			ln;
	int				type;
	const char *			name;
	union {
		struct cstr_inport	csi;
		struct file_inport	fi;
	} inp_u;
	struct inport *			inp;
};

#define l_to_input(_n) (container((_n), struct inputs, ln))

#define PMLLEX_MAXESTR		256

struct pmllex {
	byte_t			s_sid[32];
	byte_t			s_id[32];
	byte_t			s_ws[32];
	byte_t			s_op[32];

	struct htab 		kwtab;
	struct hnode *		kwbk[32];
	struct hnode 		kwnodes[32];

	struct dynbuf		text;
	struct dynbuf		strbuf;

	int			unget;
	struct inputs		inputs;
	uint			curidx;

	struct pmll_val		tokx;

	ulong 			lineno;
	char			errbuf[PMLLEX_MAXESTR];
	ulong			svlineno;
	const char *		svname;
	
	void *			ctx;
	pmll_eoi_f		eoicb;
};

#define INLIST(_lex) (&(_lex)->inputs.ln)
#define CURINPUT(_lex) (l_to_input(l_head(INLIST(_lex))))


struct kwtok {
	const char *	name;
	int		tok;
} keywords[] = { 
	{ "BEGIN",	PMLTOK_BEGIN },
	{ "END",	PMLTOK_END },
	{ "int",	PMLTOK_INT },
	{ "inline",	PMLTOK_INLINE },
	{ "const",	PMLTOK_CONST },
	{ "not",	PMLTOK_NOT },
	{ "and",	PMLTOK_AND },
	{ "or",		PMLTOK_OR },
	{ "while",	PMLTOK_WHILE },
	{ "if",		PMLTOK_IF },
	{ "else",	PMLTOK_ELSE },
	{ "return",	PMLTOK_RETURN },
	{ "break",	PMLTOK_BREAK },
	{ "continue",	PMLTOK_CONTINUE },
	{ "nextrule",	PMLTOK_NEXTRULE },
	{ "sendpkt",	PMLTOK_SENDPKT },
	{ "drop",	PMLTOK_DROP },
	{ "blob",	PMLTOK_BLOB },
	{ "bref",	PMLTOK_BREF },
	{ "print",	PMLTOK_PRINT },
	{ NULL,		0 }
};


/* Value API */
STATIC_BUG_ON(PMLLV_SCALAR_not_zero, PMLLV_SCALAR != 0);
void pmllv_init(struct pmll_val *v)
{
	memset(v, 0, sizeof(*v));
}


void pmllv_clear(struct pmll_val *v)
{
	if (v->type == PMLLV_STRING) {
		free(v->u.raw.data);
		v->u.raw.data = 0;
	}
	memset(v, 0, sizeof(*v));
}


/* assumes that the next character is a ':' */
static int read_eth_or_ipv6(struct pmllex *lex, int cc);
static void pmll_err(struct pmllex *lex, int incf, const char *fmt, ...);
static void popinput(struct pmllex *lex);
static void pushback(struct pmllex *lex, int ch);


static void resetbuf(struct pmllex *lex)
{
	dyb_empty(&lex->text);
	abort_unless(lex->text.off == 0);
}


static const char *lexstr(struct pmllex *lex)
{
	return (const char *)lex->text.data;
}


static ulong lexslen(struct pmllex *lex)
{
	return lex->text.len;
}


struct pmllex *pmll_alloc(void)
{
	struct pmllex *lex;
	struct hnode *kwn;
	struct kwtok *kw;

	lex = malloc(sizeof(*lex));
	if (lex == NULL)
		return NULL;

	kwn = lex->kwnodes;
	kw = keywords;
	cset_init_accept(lex->s_sid, SIDCHARS);
	cset_init_accept(lex->s_id, IDCHARS);
	cset_init_accept(lex->s_ws, WSCHARS);
	cset_init_accept(lex->s_op, OPCHARS);

	ht_init(&lex->kwtab, lex->kwbk, array_length(lex->kwbk), cmp_str,
		ht_shash, NULL);

	while (kw->name != NULL) {
		ht_ninit(kwn, (char *)kw->name, kw);
		ht_ins_h(&lex->kwtab, kwn);
		++kwn;
		++kw;
	}

	dyb_init(&lex->text, &stdmm);
	dyb_init(&lex->strbuf, &stdmm);

	l_init(&lex->inputs.ln);
	lex->inputs.type = NTYPE;
	lex->inputs.name = "*END OF INPUT*";
	lex->inputs.inp = &null_inport;

	lex->unget = NEXTCNONE;
	lex->curidx = 0;
	lex->lineno = 1;
	pmllv_init(&lex->tokx);
	memset(&lex->errbuf, 0, sizeof(lex->errbuf));
	lex->ctx = NULL;

	return lex;
}


int pmll_add_instr(struct pmllex *lex, const char *s, int front, const char *sn)
{
	struct inputs *pi;

	abort_unless(lex && s);
	pi = malloc(sizeof(*pi));
	if (pi == NULL) {
		pmll_err(lex, 0, "pmll_add_input_string: out of memory");
		return -1;
	}
	pi->type = STYPE;
	pi->name = (char *)sn;
	csinp_init(&pi->inp_u.csi, s);
	pi->inp = &pi->inp_u.csi.in;
	if (front)
		l_push(INLIST(lex), &pi->ln);
	else
		l_enq(INLIST(lex), &pi->ln);

	return 0;
}


int pmll_add_infile(struct pmllex *lex, FILE *f, int front, const char *fn)
{
	struct inputs *pi;

	abort_unless(lex && f);
	pi = malloc(sizeof(*pi));
	if (pi == NULL) {
		pmll_err(lex, 0, "pmll_add_input_string: out of memory");
		return -1;
	}
	pi->type = FTYPE;
	pi->name = (char *)fn;
	finp_init(&pi->inp_u.fi, f);
	pi->inp = &pi->inp_u.fi.in;
	if (front)
		l_push(INLIST(lex), &pi->ln);
	else
		l_enq(INLIST(lex), &pi->ln);

	return 0;
}


void pmll_free(struct pmllex *lex)
{
	abort_unless(lex);

	while (!l_isempty(INLIST(lex)))
		popinput(lex);
	dyb_clear(&lex->text);
	dyb_clear(&lex->strbuf);
	pmllv_clear(&lex->tokx);
	memset(lex, 0, sizeof(&lex));

	free(lex);
}


static void pmll_err(struct pmllex *lex, int incf, const char *fmt, ...)
{
	struct inputs *pi;
	int len = 0;
	va_list ap;

	va_start(ap, fmt);
	pi = CURINPUT(lex);
	if (incf && pi->name != NULL)
		len = str_fmt(lex->errbuf, sizeof(lex->errbuf),
			      "file %s line %lu: ", pi->name, lex->lineno);
	if (len >= 0 && len < sizeof(lex->errbuf))
		str_vfmt(lex->errbuf + len, sizeof(lex->errbuf) - len, fmt, ap);
	va_end(ap);
}


static void popinput(struct pmllex *lex)
{
	struct inputs *pi = CURINPUT(lex);

	lex->svlineno = lex->lineno;
	lex->svname = pi->name;
	l_rem(&pi->ln);
	inp_close(pi->inp);
	free(pi);
	lex->lineno = 1;
}


static int addc(struct dynbuf *dyb, int ch)
{
	if (dyb->len >= dyb->size) { 
		if (dyb_resv(dyb, dyb->size + 32) < 0)
			return -1;
		abort_unless(dyb->off == 0);
	}
	((char *)dyb->data)[dyb->len++] = ch;
	return 0;
}


#define TEXT_APPEND(_lex, _ch) \
	do { 								\
		if (addc(&(_lex)->text, _ch) < 0) {			\
			pmll_err(lex, 1, "adding text: out of memory");	\
			return -1; 					\
		}							\
	} while (0)

#define SBUF_APPEND(_lex, _ch) \
	do { 								\
		if (addc(&(_lex)->strbuf, _ch) < 0) {			\
			pmll_err(lex, 1, "adding text: out of memory");	\
			return -1; 					\
		}							\
	} while (0)

#define TERMINATE(_lex) TEXT_APPEND(_lex, '\0')


static int nextc(struct pmllex *lex)
{
	int c;
	struct inputs *pi;

	if (lex->unget != NEXTCNONE) {
		c = lex->unget;
		lex->unget = NEXTCNONE;
		if (addc(&lex->text, c) < 0)
			return NEXTCERR;
		return c;
	}

	do {
		pi = CURINPUT(lex);
		c = inp_getc(pi->inp);
		if (c >= 0) {
			if (addc(&lex->text, c) < 0)
				return NEXTCERR;
			return c;
		}

		/* TODO: handle input error */
		if (pi == &lex->inputs) {
			if (lex->eoicb != NULL)
				(*lex->eoicb)(lex);
			pi = CURINPUT(lex);
			if (pi == &lex->inputs) {
				resetbuf(lex);
				return NEXTCEOF;
			}
		} else {
			popinput(lex);
		}

		/* treat a new file like a whitespace w.r.t separation */
		if (addc(&lex->text, ' ') < 0)
			return NEXTCERR;
		pushback(lex, ' ');
	} while (c < 0);

	/* UNREACHED */
	return 0;
}


static void pushback(struct pmllex *lex, int ch)
{
	abort_unless(lex && lex->unget == NEXTCNONE && lex->text.len > 0);
	lex->unget = ch;
	--lex->text.len;
}


/* NOTE: newlines can happen inside of strings or whitespace and */
/* nowhere else. */
static int skip_ws(struct pmllex *lex)
{
	struct inputs *pi;
	int nws = 512;
	int ch;

	ch = nextc(lex);
	while (ch >= 0 && (cset_contains(lex->s_ws, ch) || (ch == '#'))) {

		/* read until end of line or end of current input */
		if (ch == '#') {
			pi = CURINPUT(lex);
			do {
				ch = inp_getc(pi->inp);
			} while ((ch >= 0) && (ch != '\n'));
			if (ch == NEXTCEOF)
				popinput(lex);
			else if (ch == NEXTCERR)
				return -1;
			else
				++lex->lineno;
		} else if (ch == '\n') {
			++lex->lineno;
		}

		if (--nws <= 0) {
			resetbuf(lex);
			nws = 512;
		}

		ch = nextc(lex);
	}

	resetbuf(lex);
	if (ch >= 0)
		addc(&lex->text, ch);

	return ch;
}


static int ckhex(struct pmllex *lex)
{
	const char *s = lexstr(lex);
	ulong len = lexslen(lex);
	while (len > 0) {
		if (!isxdigit(*s++))
			return 0;
		--len;
	}
	return 1;
}


static int scanhex(struct pmllex *lex)
{
	int n = 0;
	int ch;

	ch = nextc(lex);
	while ((ch >= 0) && isxdigit(ch)) {
		++n;
		ch = nextc(lex);
	}
	pushback(lex, ch);

	return n;
}


/* must have been called after reading a ':' */
static int read_eth_or_ipv6(struct pmllex *lex, int cc)
{
	int i;
	int rv;
	int nc = 1 + cc;	/* # of colons */
	int has2oct = 0;	/* has 2-byte field */
	int ch;
        uint n[6];

	do {
		nc++;
		if ((rv = scanhex(lex)) < 0)
			goto err;
		if (rv == 0) {
			++cc;
		} else if (rv > 2) {
			has2oct = 1;
			if (rv > 4)
				goto err;
		}
		ch = nextc(lex);
	} while (ch == ':');

	pushback(lex, ch);
	TERMINATE(lex);

	if (nc == 5 && !cc && !has2oct) {
		/* ethernet address */
		sscanf(lexstr(lex), "%x:%x:%x:%x:%x:%x",
		       &n[0], &n[1], &n[2], &n[3], &n[4], &n[5]);
		for ( i = 0; i < 6; ++i )
			lex->tokx.u.ethaddr[i] = n[i];
		return PMLTOK_ETHADDR;
	} else {
		/* ipv6 address */
		if (nc > 7)
			goto errv6;
		if (str_parse_ip6a(&lex->tokx.u.v6addr, lexstr(lex)) < 0)
			goto errv6;
		return PMLTOK_IPV6ADDR;
	}


err:
	pmll_err(lex, 1, "invalid IPv6 or 802.11 address");
	return -1;
errv6:
	pmll_err(lex, 1, "invalid IPv6 address");
	return -1;
}


static int read_id(struct pmllex *lex, int ch)
{
	ulong off = 0;
	struct hnode *hn;
	struct kwtok *kw;
	size_t idlen;
	char *ns;

	do {
		ch = nextc(lex);
	} while (ch >= 0 && cset_contains(lex->s_id, ch));

	/* check for start of IPv6 or ethernet address */
	if (ch < 0) {
		return ch;
	} else if (ch == ':' && lexslen(lex) <= 4 && ckhex(lex)) {
		return read_eth_or_ipv6(lex, 0);
	} else {
		pushback(lex, ch);
		TERMINATE(lex);

		hn = ht_lkup(&lex->kwtab, lexstr(lex), NULL);
		if (hn != NULL) {
			kw = hn->data;
			return kw->tok;
		}

		/* copy string to token */
		lex->tokx.type = PMLLV_STRING;
		ns = malloc(lexslen(lex));
		if (ns == NULL) {
			pmll_err(lex, 1, "copying id: out of memory");
			return -1;
		}
		memcpy(ns, lexstr(lex), lexslen(lex));
		lex->tokx.u.raw.data = ns;
		lex->tokx.u.raw.len = lexslen(lex);

		return PMLTOK_ID;
	}
}


static int setsval(struct pmllex *lex, int countnull)
{
	struct dynbuf *sb = &lex->strbuf;

	if (addc(sb, '\0') < 0)
		return -1;
	lex->tokx.u.raw.len = sb->len;
	lex->tokx.u.raw.data = dyb_release(sb);
	if (!countnull)
		lex->tokx.u.raw.len -= 1;
	
	return 0;
}


int isodigit(int ch)
{
	return isdigit(ch) && (ch != '8') && (ch != '9');
}


static int read_str(struct pmllex *lex, int quote)
{
	struct inport *in;
	int ch;
	int d1, d2, d3;
	int tok;

	/* use inp_getc() because strings can't cross input boundaries */
	in = CURINPUT(lex)->inp;
	ch = inp_getc(in);

	while (ch != quote) {
		if (ch < 0) {
			pmll_err(lex, 1, "unterminated string");
			return -1;
		}
		TEXT_APPEND(lex, ch);

		if (ch == '\\') {
			ch = inp_getc(in);
			if (ch < 0) {
				pmll_err(lex, 1, "unterminated string");
				return -1;
			}
			TEXT_APPEND(lex, ch);

			switch (ch) {
			case '\\': ch = '\\'; break;
			case '0':  ch = '\0'; break;
			case 'a':  ch = '\a'; break;
			case 'b':  ch = '\b'; break;
			case 't':  ch = '\t'; break;
			case 'n':  ch = '\n'; break;
			case 'v':  ch = '\v'; break;
			case 'f':  ch = '\f'; break;
			case 'r':  ch = '\r'; break;
			case '\n': ++lex->lineno; break;
			case 'x': 
				if ((d1 = inp_getc(in)) < 0 || !isxdigit(d1) ||
				    (d2 = inp_getc(in)) < 0 || !isxdigit(d2)) {
					pmll_err(lex, 1, "short hex char");
					return -1;
				}
				ch = (chnval(d1) << 4) + chnval(d2);
				break;
			default:
				if ((d1 = inp_getc(in)) < 0 || !isodigit(d1) ||
				    (d2 = inp_getc(in)) < 0 || !isodigit(d2) ||
				    (d3 = inp_getc(in)) < 0 || !isodigit(d3)) {
					pmll_err(lex, 1, "short octal char");
					return -1;
				}
				ch = (chnval(d1) << 6) + (chnval(d2) << 3) +
				     chnval(d3);
				break;
			}
		}

		SBUF_APPEND(lex, ch);
		ch = inp_getc(in);
	}

	TEXT_APPEND(lex, ch);
	TERMINATE(lex);
	if (setsval(lex, 1) < 0)
		return -1;

	return (quote == '"') ? PMLTOK_STRING : PMLTOK_REGEX;
}


static int read_op(struct pmllex *lex, int ch)
{
	int ch2 = -1;
	int tok = -1;

	switch(ch) {
	case '+': tok = PMLTOK_PLUS; break;
	case '*': tok = PMLTOK_TIMES; break;
	case '/': tok = PMLTOK_DIV; break;
	case '%': tok = PMLTOK_MOD; break;
	case '&': tok = PMLTOK_AMP; break;
	case '|': tok = PMLTOK_BOR; break;
	case '^': tok = PMLTOK_BXOR; break;
	case '~': tok = PMLTOK_BINV; break;
	case '.': tok = PMLTOK_DOT; break;
	case '{': tok = PMLTOK_LBRACE; break;
	case '}': tok = PMLTOK_RBRACE; break;
	case '(': tok = PMLTOK_LPAREN; break;
	case ')': tok = PMLTOK_RPAREN; break;
	case '[': tok = PMLTOK_LBRACKET; break;
	case ']': tok = PMLTOK_RBRACKET; break;
	case ',': tok = PMLTOK_COMMA; break;
	case ';': tok = PMLTOK_SEMICOLON; break;
	case '$': tok = PMLTOK_DOLLAR; break;
	case '@': tok = PMLTOK_AT; break;

	case '?':
		ch2 = nextc(lex);
		if (ch2 == '-') { tok = PMLTOK_PPBEGIN; break; }
		goto err; /* no other tokens starting with '?' */

	case '=': 
		ch2 = nextc(lex);
		if (ch2 == '=') { tok = PMLTOK_EQ; break; }
		if (ch2 == '~') { tok = PMLTOK_MATCH; break; }
		pushback(lex, ch2);
		tok = PMLTOK_ASSIGN;
		break;

	case '!':
		ch2 = nextc(lex);
		if (ch2 == '=') { tok = PMLTOK_NEQ; break; }
		if (ch2 == '~') { tok = PMLTOK_NOMATCH; break; }
		goto err; /* no other tokens starting with '!' */

	case '<':
		ch2 = nextc(lex);
		if (ch2 == '=') { tok = PMLTOK_LEQ; break; } 
		if (ch2 == '<') { tok = PMLTOK_SHL; break; } 
		pushback(lex, ch2);
		tok = PMLTOK_LT;
		break;

	case '>':
		ch2 = nextc(lex);
		if (ch2 == '=') { tok = PMLTOK_GEQ; break; } 
		if (ch2 == '>') { tok = PMLTOK_SHR; break; } 
		pushback(lex, ch2);
		tok = PMLTOK_GT;
		break;

	case '-':
		ch2 = nextc(lex);
		if (ch2 == '?') { tok = PMLTOK_PPEND; break; }
		pushback(lex, ch2);
		tok = PMLTOK_MINUS;
		break;

	case ':':
		ch2 = nextc(lex);
		if (ch2 != ':')
			goto err;
		return read_eth_or_ipv6(lex, 1);

	default:
		abort_unless(0);
	}

	TERMINATE(lex);

	return tok;

err:
	pmll_err(lex, 1, "invalid token");
	return -1;
}


static int read_hexstr(struct pmllex *lex)
{
	struct inport *in;
	int ch = nextc(lex);
	int ch2;
	unsigned char v;
	ulong nx = 0;
	
	if (ch != 'x') {
		pmll_err(lex, 1, "invalid token");
		return -1;
	}

	ch = nextc(lex);
	while (ch >= 0 && (isxdigit(ch) || ch == '\\')) {
		if (ch == '\\') {
			ch2 = nextc(lex);
			if (ch != '\n') {
				pmll_err(lex, 1, "unterminated hexstring");
				return -1;
			}
			++lex->lineno;
			do {
				ch = nextc(lex);
			} while (ch == ' ' || ch == '\t' || ch == '\r');
		} else {
			if ((nx & 1) == 0)
				v = chnval(ch) << 4;
			else
				SBUF_APPEND(lex, v | chnval(ch));
			++nx;
		}
		ch = nextc(lex);
	}

	pushback(lex, ch);
	TERMINATE(lex);
	if (setsval(lex, 0) < 0)
		return -1;

	return PMLTOK_BYTESTR;
}


static int read_ipv4_after_one_octet(struct pmllex *lex)
{
	int i, ch;
	uint v[4];
	byte_t *p;
	
	pushback(lex, '.');
	for (i = 0 ; i < 3; ++i) {
		if ((ch = nextc(lex)) != '.')
			goto err;
		ch = nextc(lex);
		while ((ch >= 0) && isdigit(ch))
			ch = nextc(lex);
		pushback(lex, ch);
	}
	TERMINATE(lex);

	if (sscanf(lexstr(lex), "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]) < 4)
		goto err;

	for (i = 0, p = lex->tokx.u.v4addr; i < 4; ++i) {
		if (v[i] > 255)
			goto err;
		*p++ = v[i];
	}

	return PMLTOK_IPV4ADDR;

err:
	pmll_err(lex, 1, "invalid IP address format");
	return -1;
}


static int read_num(struct pmllex *lex, int ich)
{
	ullong v;
	char *cp;
	int ch;

	ch = nextc(lex);
	if (ich == '0') {
		if (ch == 'x') {
			ch = nextc(lex);
			if (ch < 0 || !isxdigit(ch)) {
				pmll_err(lex, 1, "invalid hex constant");
				return -1;
			}
		}
	} 

	while (ch >= 0 && isxdigit(ch))
		ch = nextc(lex);

	if (ch == '.') {
		return read_ipv4_after_one_octet(lex);
	} else if (ch == ':') {
		return read_eth_or_ipv6(lex, 0);
	}

	pushback(lex, ch);
	TERMINATE(lex);

	errno = 0;
	v = strtoull(lexstr(lex), &cp, 0);
	if (cp != lexstr(lex) + (lexslen(lex)-1) ||
	    (v == ULLONG_MAX && errno == ERANGE)) {
		pmll_err(lex, 1, "Invalid numeric constant");
		return -1;
	}

	lex->tokx.u.num = v;
	return PMLTOK_NUM;
}


int pmll_nexttok(struct pmllex *lex, struct pmll_val *v)
{
	int ch;
	int rv;
	
	pmllv_init(&lex->tokx);
	resetbuf(lex);

	ch = skip_ws(lex);
	if (ch == NEXTCEOF)
		return 0;
	else if (ch == NEXTCERR)
		return -1;

	if (cset_contains(lex->s_sid, ch)) {
		rv = read_id(lex, ch);
	} else if (cset_contains(lex->s_op, ch)) {
		rv = read_op(lex, ch);
	} else if (ch == QUOTE || ch == REXQUOTE) {
		rv = read_str(lex, ch);
	} else if (ch == '\\') {
		rv = read_hexstr(lex);
	} else if (isdigit(ch)) {
		rv = read_num(lex, ch);
	} else {
		pmll_err(lex, 1, "Unknown token character: '%c'", ch);
		return -1;
	}

	if (rv >= 0 && v != NULL) {
		*v = lex->tokx;
		pmllv_init(&lex->tokx);
	}
	
	return rv;
}


ulong pmll_get_lineno(struct pmllex *lex)
{
	struct inputs *pi = CURINPUT(lex);
	if (pi == &lex->inputs)
		return lex->svlineno;
	else
		return lex->lineno;
}


const char *pmll_get_iname(struct pmllex *lex)
{
	struct inputs *pi = CURINPUT(lex);
	if (pi == &lex->inputs)
		return lex->svname;
	else
		return pi->name;
}


const char *pmll_get_text(struct pmllex *lex)
{
	return lex->text.data;
}


const char *pmll_get_err(struct pmllex *lex)
{
	return lex->errbuf;
}


void pmll_set_ctx(struct pmllex *lex, void *ctx)
{
	lex->ctx = ctx;
}


void *pmll_get_ctx(struct pmllex *lex)
{
	return lex->ctx;
}


void pmll_set_eoicb(struct pmllex *lex, pmll_eoi_f eoicb)
{
	lex->eoicb = eoicb;
}
