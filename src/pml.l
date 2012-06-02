%{
/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * pml.l -- PML lexical analyzer in the flex format.
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

#include <string.h>
#include <ctype.h>
#include <cat/err.h>
#include <cat/str.h>
#include "pml.h"
#include "pmltree.h"

#define YY_EXTRA_TYPE	struct pml_lex_val
#define YY_NO_INPUT
static void parse_eth_addr(yyscan_t scanner, const char *text);
static void parse_num(yyscan_t scanner, const char *text);
static void parse_ipv4_addr(yyscan_t scanner, const char *text);
static int parse_ipv6_addr(yyscan_t scanner, const char *text);
static int copy_string(yyscan_t scanner, const char *text, int tok, int quoted);
static int copy_bytestr(yyscan_t scanner, const char *hex, int tok);
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
xnum		0x{xd}+
onum		0[0-7]+
dnum		0|[1-9][0-9]*

%%

#.*\n

\"{sch}*\" {
	return copy_string(yyscanner, yytext, PMLTOK_STRING, 1);
}

`{sch}*` {
	return copy_string(yyscanner, yytext, PMLTOK_REGEX, 1);
}

{xnum}	|
{onum}	|
{dnum}  {
	parse_num(yyscanner, yytext);
	return PMLTOK_NUM; 
}

\\x({xb}{xb})+ {
	return copy_bytestr(yyscanner, yytext, PMLTOK_BYTESTR);
}

{ipb}\.{ipb}\.{ipb}\.{ipb} { 
	parse_ipv4_addr(yyscanner, yytext);
	return PMLTOK_IPV4ADDR; 
}

{xb}:{xb}:{xb}:{xb}:{xb}:{xb} { 
	parse_eth_addr(yyscanner, yytext);
	return PMLTOK_ETHADDR; 
}

::({xq}(:{xq})*)?	    |
({xq}:)+(((:{xq})+)|{xq}|:) { 
	return parse_ipv6_addr(yyscanner, yytext); 
}

"BEGIN"		{ return PMLTOK_BEGIN; }
"END"		{ return PMLTOK_END; }
"int"		{ return PMLTOK_INT; }
"void"		{ return PMLTOK_VOID; }
"inline"	{ return PMLTOK_INLINE; }
"const"		{ return PMLTOK_CONST; }
"not"		{ return PMLTOK_NOT; }
"and"		{ return PMLTOK_AND; }
"or"		{ return PMLTOK_OR; }
"while"		{ return PMLTOK_WHILE; }
"if"		{ return PMLTOK_IF; }
"else"		{ return PMLTOK_ELSE; }
"return"	{ return PMLTOK_RETURN; }
"break"		{ return PMLTOK_BREAK; }
"continue"	{ return PMLTOK_CONTINUE; }
"nextrule"	{ return PMLTOK_NEXTRULE; }
"sendpkt"	{ return PMLTOK_SENDPKT; }
"drop"		{ return PMLTOK_DROP; }
"var"		{ return PMLTOK_VAR; }
"print"		{ return PMLTOK_PRINT; }

"=="		{ return PMLTOK_EQ; }
"!="		{ return PMLTOK_NEQ; }
"<"		{ return PMLTOK_LT; }
">"		{ return PMLTOK_GT; }
"<="		{ return PMLTOK_LEQ; }
">="		{ return PMLTOK_GEQ; }

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
"."		{ return PMLTOK_DOT; }
"="		{ return PMLTOK_ASSIGN; }
"@@"		{ return PMLTOK_ATAT; }
"@"		{ return PMLTOK_AT; }

"{"		{ return PMLTOK_LBRACE; }
"}"		{ return PMLTOK_RBRACE; }
"("		{ return PMLTOK_LPAREN; }
")"		{ return PMLTOK_RPAREN; }
"["		{ return PMLTOK_LBRACKET; }
"]"		{ return PMLTOK_RBRACKET; }
"?-"		{ return PMLTOK_PPBEGIN; }
"-?"		{ return PMLTOK_PPEND; }
","		{ return PMLTOK_COMMA; }
";"		{ return PMLTOK_SEMICOLON; }
":"		{ return PMLTOK_COLON; }

[a-zA-Z_][a-zA-Z0-9_]* { 
	return copy_string(yyscanner, yytext, PMLTOK_ID, 0);
}

{ws}		/* skip ws */

.		{ return -1; }

%%


void parse_eth_addr(yyscan_t scanner, const char *text)
{
	struct pml_lex_val v;
	uint n[6];
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
	v.u.num = strtoull(text, NULL, 0);
	pmlset_extra(v, scanner);
}


void parse_ipv4_addr(yyscan_t scanner, const char *text)
{
	struct pml_lex_val v;
	uint n[4];
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


static int isodigit(char c)
{
	return (c >= '0' && c <= '7');
}

static void c_translate(struct raw *r, const char *s, size_t len)
{
	char *d = r->data;
	r->len = 0;
	while (len > 0) {
		if (*s != '\\' && len > 1) {
			*d++ = *s++;
			len -= 1;
		} else {
			switch (s[1]) {
			case '\\': *d++ = '\\'; s += 2; len -= 2; break;
			case '0':  *d++ = '\0'; s += 2; len -= 2; break;
			case 'a':  *d++ = '\a'; s += 2; len -= 2; break;
			case 'b':  *d++ = '\b'; s += 2; len -= 2; break;
			case 't':  *d++ = '\t'; s += 2; len -= 2; break;
			case 'n':  *d++ = '\n'; s += 2; len -= 2; break;
			case 'v':  *d++ = '\v'; s += 2; len -= 2; break;
			case 'f':  *d++ = '\f'; s += 2; len -= 2; break;
			case 'r':  *d++ = '\r'; s += 2; len -= 2; break;
			case 'x':
				if (len < 4 && isxdigit(s[2]) && 
				    isxdigit(s[3])) {
					*d++ = *s++;
					len -= 1;
				} else {
					*d++ = (chnval(s[2]) << 4) + 
					       (chnval(s[3]) << 0);
					s += 4;
					len -= 4;
				}
				break;
			default:
				if (len >= 4 && isodigit(s[1]) && 
				    isodigit(s[2]) && isodigit(s[3])) {
					*d++ = ((chnval(s[1]) << 6) +
						(chnval(s[2]) << 3) +
						(chnval(s[3]) << 0)) % 0xFF;
					s += 4;
					len -= 4;
				} else {
					*d++ = *s++;
					len -= 1;
				}
			}
		}
		++r->len;
	}
	*d = '\0';
	++r->len;
}


static int copy_string(yyscan_t scanner, const char *text, int tok, int quoted)
{
	size_t len;
	struct pml_lex_val v;

	v.type = PMLLV_STRING;
	len = strlen(text) + 1;
	if ( quoted ) {
		abort_unless(len >= 3);
		len -= 3;
		text += 1;
	}
	if ( (v.u.raw.data = malloc(len)) == NULL )
		return -1;
	if ( quoted ) {
		c_translate(&v.u.raw, text, len);
	} else {
		memcpy(v.u.raw.data, text, len);
		v.u.raw.len = len;
	}
	pmlset_extra(v, scanner);

	return tok;
}


static int copy_bytestr(yyscan_t scanner, const char *hex, int tok)
{
	size_t len = 0;
	struct pml_lex_val v;
	uint8_t *bp;

	v.type  = PMLLV_STRING;
	len = strlen(hex);
	abort_unless(len >= 4 && (len % 2 == 0));
	len -= 2;
	hex += 2;
	bp = malloc(len + 1);
	if ( bp == NULL )
		return -1;
	len /= 2;
	v.u.raw.len = len;
	v.u.raw.data = bp;
	while ( len > 0 ) {
		*bp++ = chnval(hex[0]) * 16 + chnval(hex[1]);
		hex += 2;
		--len;
	}
	*bp = '\0'; /* paranoid/defensive */
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
