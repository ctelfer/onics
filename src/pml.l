%{
#include "pmltok.h"
#include <cat/err.h>

union pmllex_u {
	byte_t v6addr[16];
	byte_t ethaddr[6];
	unsigned long num;
	byte_t v4addr[4];
};

#define YY_EXTRA_TYPE	union pmllex_u
static void parse_eth_addr(yyscan_t scanner, const char *text);
static void parse_num(yyscan_t scanner, const char *text);
static void parse_ipv4_addr(yyscan_t scanner, const char *text);
static int parse_ipv6_addr(yyscan_t scanner, const char *text);
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

\"{sch}*\"		{ return NMLTOK_STRING; }

{xnum}	|
{onum}	|
{dnum}  {
	parse_num(yyscanner, yytext);
	return NMLTOK_NUM; 
}

\\x{xb}+		{ return NMLTOK_BYTESTR; }

{ipb}\.{ipb}\.{ipb}\.{ipb} { 
	parse_ipv4_addr(yyscanner, yytext);
	return NMLTOK_IPV4ADDR; 
}

{xb}:{xb}:{xb}:{xb}:{xb}:{xb}	{ 
	parse_eth_addr(yyscanner, yytext);
	return NMLTOK_ETHADDR; 
}

::({xq}(:{xq})*)?		|
({xq}:)+(((:{xq})+)|{xq}|:)	{ 
	return parse_ipv6_addr(yyscanner, yytext); 
}

"not"		{ return NMLTOK_NOT; }
"and"		{ return NMLTOK_AND; }
"or"		{ return NMLTOK_OR; }
"nlz"		{ return NMLTOK_NLZ; }
"pop"		{ return NMLTOK_POP; }
"while"		{ return NMLTOK_WHILE; }
"if"		{ return NMLTOK_IF; }

"=="		{ return NMLTOK_EQ; }
"!="		{ return NMLTOK_NEQ; }
"<"		{ return NMLTOK_LT; }
">"		{ return NMLTOK_GT; }
"<="		{ return NMLTOK_LEQ; }
">="		{ return NMLTOK_GEQ; }
"=/"		{ return NMLTOK_MASKEQ; }
"!/"		{ return NMLTOK_MASKNE; }
"=~"		{ return NMLTOK_REX; }
"!~"		{ return NMLTOK_NOTREX; }

"+"		{ return NMLTOK_PLUS; }
"-"		{ return NMLTOK_MINUS; }
"*"		{ return NMLTOK_TIMES; }
"/"		{ return NMLTOK_DIV; }
"%"		{ return NMLTOK_MOD; }
"&"		{ return NMLTOK_BAND; }
"|"		{ return NMLTOK_BOR; }
"~"		{ return NMLTOK_BINV; }
"<<"		{ return NMLTOK_SHL; }
">>"		{ return NMLTOK_SHR; }
">>a"		{ return NMLTOK_SHRA; }
"."		{ return NMLTOK_DOT; }
":"		{ return NMLTOK_COLON; }
"="		{ return NMLTOK_ASSIGN; }

"{"		{ return NMLTOK_LBRACE; }
"}"		{ return NMLTOK_RBRACE; }
"("		{ return NMLTOK_LPAREN; }
")"		{ return NMLTOK_RPAREN; }
"["		{ return NMLTOK_LBRACKET; }
"]"		{ return NMLTOK_RBRACKET; }
"?-"		{ return NMLTOK_PPBEGIN; }
"-?"		{ return NMLTOK_PPEND; }
","		{ return NMLTOK_COMMA; }

[a-zA-Z_][a-zA-Z0-9_]*	{ return NMLTOK_ID; }

{ws}		/* skip ws */

.		{ return -1; }

%%


void parse_eth_addr(yyscan_t scanner, const char *text)
{
	union pmllex_u lu;
	unsigned n[6];
	int i;
	sscanf(text, "%x:%x:%x:%x:%x:%x", &n[0], &n[1], &n[2], &n[3], &n[4], 
               &n[5]);
	for ( i = 0; i < 6; ++i )
		lu.ethaddr[i] = n[i];
	pmlset_extra(lu, scanner);
}


void parse_num(yyscan_t scanner, const char *text)
{
	union pmllex_u lu;
	lu.num = strtoul(text, NULL, 0);
	pmlset_extra(lu, scanner);
}


void parse_ipv4_addr(yyscan_t scanner, const char *text)
{
	union pmllex_u lu;
	unsigned n[4];
	int i;
	sscanf(text, "%u.%u.%u.%u", &n[0], &n[1], &n[2], &n[3]);
	for ( i = 0; i < 4; ++i )
		lu.v4addr[i] = n[i];
	pmlset_extra(lu, scanner);
}


int parse_ipv6_addr(yyscan_t scanner, const char *text)
{
	const char *p = text, *nxt;
	union pmllex_u lu;
	byte_t prefix[16];
	byte_t suffix[16];
	char xdigits[5];
	int plen = 0, slen = 0, zcomp = 0, n;
	ushort xpair;

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
	memcpy(&lu.v6addr[0], prefix, n);
	memset(&lu.v6addr[n], 0, 16 - (n + slen * 2));
	n = 16 - slen * 2;
	memcpy(&lu.v6addr[n], suffix, slen * 2);

	pmlset_extra(lu, scanner);
	return NMLTOK_IPV6ADDR;
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
