%{
#include "pmllex.h"
#include "pml.h"
#include <cat/err.h>

#define YY_EXTRA_TYPE	struct pml_lex_val
#define YY_NO_INPUT
static void parse_eth_addr(yyscan_t scanner, const char *text);
static void parse_num(yyscan_t scanner, const char *text);
static void parse_ipv4_addr(yyscan_t scanner, const char *text);
static int parse_ipv6_addr(yyscan_t scanner, const char *text);
static int copy_string(yyscan_t scanner, const char *text, int tok);
%}

%option reentrant
%option prefix="pml"
%option noyywrap
%option yylineno
%option nounput

xd		[0-9a-fA-F]
xb		{xd}{xd}
xq		{xd}{1,4}
ws		[ \t\r\n]
ipb		(2((5[0-5])|[0-4][0-9]))|(1[0-9][0-9])|([1-9]?[0-9])
sch		([^"]|\\\\|\\\"|\r|\n)
xnum		0x{xb}+
onum		0[0-7]+
dnum		0|[1-9][0-9]*

%%

#.*\n

\"{sch}*\"		{return copy_string(yyscanner, yytext, PMLTOK_STRING);}

{xnum}	|
{onum}	|
{dnum}  {
	parse_num(yyscanner, yytext);
	return PMLTOK_NUM; 
}

\\x{xb}+		{return copy_string(yyscanner, yytext, PMLTOK_BYTESTR);}

{ipb}\.{ipb}\.{ipb}\.{ipb} { 
	parse_ipv4_addr(yyscanner, yytext);
	return PMLTOK_IPV4ADDR; 
}

{xb}:{xb}:{xb}:{xb}:{xb}:{xb}	{ 
	parse_eth_addr(yyscanner, yytext);
	return PMLTOK_ETHADDR; 
}

::({xq}(:{xq})*)?		|
({xq}:)+(((:{xq})+)|{xq}|:)	{ 
	return parse_ipv6_addr(yyscanner, yytext); 
}

"not"		{ return PMLTOK_NOT; }
"and"		{ return PMLTOK_AND; }
"or"		{ return PMLTOK_OR; }
"nlz"		{ return PMLTOK_NLZ; }
"pop"		{ return PMLTOK_POP; }
"while"		{ return PMLTOK_WHILE; }
"if"		{ return PMLTOK_IF; }
"else"		{ return PMLTOK_ELSE; }
"return"	{ return PMLTOK_RETURN; }
"drop"		{ return PMLTOK_DROP; }
"insert"	{ return PMLTOK_INSERT; }
"cut"		{ return PMLTOK_CUT; }
"dup"		{ return PMLTOK_DUP; }
"fixlen"	{ return PMLTOK_FIXLEN; }
"fixcsum"	{ return PMLTOK_FIXCSUM; }
"fixdlt"	{ return PMLTOK_FIXDLT; }
"enqueue"	{ return PMLTOK_ENQUEUE; }
"print"		{ return PMLTOK_PRINT; }

"=="		{ return PMLTOK_EQ; }
"!="		{ return PMLTOK_NEQ; }
"<"		{ return PMLTOK_LT; }
">"		{ return PMLTOK_GT; }
"<="		{ return PMLTOK_LEQ; }
">="		{ return PMLTOK_GEQ; }
"=/"		{ return PMLTOK_MASKEQ; }
"!/"		{ return PMLTOK_MASKNE; }
"=~"		{ return PMLTOK_REX; }
"!~"		{ return PMLTOK_NOTREX; }

"+"		{ return PMLTOK_PLUS; }
"-"		{ return PMLTOK_MINUS; }
"*"		{ return PMLTOK_TIMES; }
"/"		{ return PMLTOK_DIV; }
"%"		{ return PMLTOK_MOD; }
"&"		{ return PMLTOK_BAND; }
"|"		{ return PMLTOK_BOR; }
"~"		{ return PMLTOK_BINV; }
"<<"		{ return PMLTOK_SHL; }
">>"		{ return PMLTOK_SHR; }
">>a"		{ return PMLTOK_SHRA; }
"."		{ return PMLTOK_DOT; }
":"		{ return PMLTOK_COLON; }
"="		{ return PMLTOK_ASSIGN; }

"{"		{ return PMLTOK_LBRACE; }
"}"		{ return PMLTOK_RBRACE; }
"("		{ return PMLTOK_LPAREN; }
")"		{ return PMLTOK_RPAREN; }
"["		{ return PMLTOK_LBRACKET; }
"]"		{ return PMLTOK_RBRACKET; }
"?-"		{ return PMLTOK_PPBEGIN; }
"-?"		{ return PMLTOK_PPEND; }
","		{ return PMLTOK_COMMA; }

[a-zA-Z_][a-zA-Z0-9_]*	{ return PMLTOK_ID; }

{ws}		/* skip ws */

.		{ return -1; }

%%


void parse_eth_addr(yyscan_t scanner, const char *text)
{
	struct pml_lex_val v;
	unsigned n[6];
	int i;
	v.type  = PMLLV_SCALAR;
	sscanf(text, "%x:%x:%x:%x:%x:%x", &n[0], &n[1], &n[2], &n[3], &n[4], 
               &n[5]);
	for ( i = 0; i < 6; ++i )
		v.u.ethaddr[i] = n[i];
	pmlset_extra(v, scanner);
}


void parse_num(yyscan_t scanner, const char *text)
{
	struct pml_lex_val v;
	v.type  = PMLLV_SCALAR;
	v.u.num = strtoul(text, NULL, 0);
	pmlset_extra(v, scanner);
}


void parse_ipv4_addr(yyscan_t scanner, const char *text)
{
	struct pml_lex_val v;
	unsigned n[4];
	int i;
	v.type  = PMLLV_SCALAR;
	sscanf(text, "%u.%u.%u.%u", &n[0], &n[1], &n[2], &n[3]);
	for ( i = 0; i < 4; ++i )
		v.u.v4addr[i] = n[i];
	pmlset_extra(v, scanner);
}


int parse_ipv6_addr(yyscan_t scanner, const char *text)
{
	struct pml_lex_val v;
	const char *p = text, *nxt;
	byte_t prefix[16];
	byte_t suffix[16];
	char xdigits[5];
	int plen = 0, slen = 0, zcomp = 0, n;
	ushort xpair;

	v.type  = PMLLV_SCALAR;
	while ( (nxt = strchr(p, ':')) && (nxt != p) ) {
		if ( plen >= 8 )
			return -1;
		memcpy(xdigits, p, nxt - p);
		xdigits[nxt-p] = '\0';
		xpair = strtoul(xdigits, 0, 16);
		prefix[plen*2] = (xpair >> 8) & 0xff;
		prefix[plen*2+1] = xpair & 0xff;
		plen += 1;
		p = nxt + 1;
	}

	if ( *p != '\0' ) {
		if ( p == text )
			p += 2;
		else 
			p += 1;
		zcomp = 1;
	}

	while ( (nxt = strchr(p, ':')) && (nxt != p) ) {
		if ( plen + zcomp + slen >= 8 )
			return -1;
		memcpy(xdigits, p, nxt - p);
		xdigits[nxt-p] = '\0';
		xpair = strtoul(xdigits, 0, 16);
		suffix[slen*2] = (xpair >> 8) & 0xff;
		suffix[slen*2+1] = xpair & 0xff;
		slen += 1;
		p = nxt + 1;
	}

	n = plen * 2;
	memcpy(&v.u.v6addr[0], prefix, n);
	memset(&v.u.v6addr[n], 0, 16 - (n + slen * 2));
	n = 16 - slen * 2;
	memcpy(&v.u.v6addr[n], suffix, slen * 2);

	pmlset_extra(v, scanner);
	return PMLTOK_IPV6ADDR;
}


static int copy_string(yyscan_t scanner, const char *text, int tok)
{
	size_t len;
	struct pml_lex_val v;

	v.type  = PMLLV_STRING;
	len = strlen(text) + 1;
	if ( (v.u.raw.data = malloc(len)) == NULL )
		return -1;
	memcpy(v.u.raw.data, text, len);
	v.u.raw.len = len;
	pmlset_extra(v, scanner);

	return tok;
}


const char *strs[] = { 
  "EOF",
  "ID",
  "STRING",
  "NUM",
  "BYTESTR",
  "IPV4ADDR",
  "IPV6ADDR",
  "ETHADDR",
  
  "NOT",
  "AND",
  "OR",
  "NLZ",
  "POP",
  "WHILE",
  "IF",

  "EQ",
  "NEQ",
  "LT",
  "GT",
  "LEQ",
  "GEQ",
  "MEQ",
  "SLT",
  "SGT",
  "SLEQ",
  "SGEQ",
  "REX",
  
  "PLUS",
  "MINUS",
  "TIMES",
  "DIV",
  "MOD",
  "BAND",
  "BOR",
  "BINV",
  "SHL",
  "SHR",
  "SHRA",
  "DOT",
  "COLON",
  "ASSIGN",
  
  "LBRACE",
  "RBRACE",
  "LPAREN",
  "RPAREN",
  "LBRACKET",
  "RBRACKET",
  "PPBEGIN",
  "PPEND",
  "COMMA",
};


int testpmllex()
{
	int x;
	yyscan_t scanner;
	if ( pmllex_init(&scanner) )
		errsys("pmllex_init:");
	pmlset_in(stdin, scanner);
	while ( (x = pmllex(scanner)) > 0 )
		printf("%-15s'%s'\n", strs[x], pmlget_text(scanner));
	if ( x < 0 ) {
		printf("unknown char on line: %d\n", pmlget_lineno(scanner));
	} else {
		printf("End of file\n");
	}
	pmllex_destroy(scanner);
	return 0;
}
