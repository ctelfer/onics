%{
#include "pml.h"
#include "pmltree.h"
#include <cat/err.h>
#include <cat/str.h>

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

\"{sch}*\"		{
	return copy_string(yyscanner, yytext, PMLTOK_STRING);
}

`{sch}*`		{
	return copy_string(yyscanner, yytext, PMLTOK_REGEX);
}

{xnum}	|
{onum}	|
{dnum}  {
	parse_num(yyscanner, yytext);
	return PMLTOK_NUM; 
}

\\x{xb}+		{
	return copy_string(yyscanner, yytext, PMLTOK_BYTESTR);
}

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
"while"		{ return PMLTOK_WHILE; }
"if"		{ return PMLTOK_IF; }
"else"		{ return PMLTOK_ELSE; }
"return"	{ return PMLTOK_RETURN; }
"var"		{ return PMLTOK_VAR; }

"=="		{ return PMLTOK_EQ; }
"!="		{ return PMLTOK_NEQ; }
"<"		{ return PMLTOK_LT; }
">"		{ return PMLTOK_GT; }
"<="		{ return PMLTOK_LEQ; }
">="		{ return PMLTOK_GEQ; }
"<-"		{ return PMLTOK_SLT; }
">-"		{ return PMLTOK_SGT; }
"<=-"		{ return PMLTOK_SLEQ; }
">=-"		{ return PMLTOK_SGEQ; }

"=~"		{ return PMLTOK_MATCH; }
"!~"		{ return PMLTOK_NOMATCH; }

"+"		{ return PMLTOK_PLUS; }
"-"		{ return PMLTOK_MINUS; }
"*"		{ return PMLTOK_TIMES; }
"/"		{ return PMLTOK_DIV; }
"%"		{ return PMLTOK_MOD; }
"&"		{ return PMLTOK_AMP; }
"|"		{ return PMLTOK_BOR; }
"^"		{ return PMLTOK_BXOR; }
"~"		{ return PMLTOK_BINV; }
"<<"		{ return PMLTOK_SHL; }
">>"		{ return PMLTOK_SHR; }
">>-"		{ return PMLTOK_SHRA; }
"."		{ return PMLTOK_DOT; }
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

[a-zA-Z_][a-zA-Z0-9_]*	{ 
	return copy_string(yyscanner, yytext, PMLTOK_ID);
}

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

	v.type  = PMLLV_SCALAR;
	if ( str_parse_ip6a(&v.u.v6addr, text) < 0 )
		return -1;
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


static const char *strs[] = { 
  "EOF",
  "PRED",
  "ID",
  "LPAREN",
  "RPAREN",
  "FUNC",
  "LBRACE",
  "RBRACE",
  "COMMA",
  "VAR",
  "SEMICOLON",
  "LBRACKET",
  "NUM",
  "RBRACKET",
  "ASSIGN",
  "WHILE",
  "IF",
  "ELSE",
  "RETURN",
  "PRINT",
  "STRING",
  "PPBEGIN",
  "PPEND",
  "OR",
  "AND",
  "BYTESTR",
  "DIV",
  "IPV4ADDR",
  "IPV6ADDR",
  "ETHADDR",
  "REGEX",
  "MATCH",
  "NOMATCH",
  "EQ",
  "NEQ",
  "LT",
  "GT",
  "LEQ",
  "GEQ",
  "SLT",
  "SGT",
  "SLEQ",
  "SGEQ",
  "BOR",
  "BXOR",
  "AMP",
  "PLUS",
  "MINUS",
  "TIMES",
  "MOD",
  "SHL",
  "SHR",
  "SHRA",
  "NOT",
  "BINV",
  "IPADDR",
  "DOT",
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
