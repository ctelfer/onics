%{
#include "nmltok.h"
%}

%option reentrant
%option prefix="nml"
%option noyywrap

xd		[0-9a-fA-F]
xbyte		{xd}{xd}
xq		{xd}{xd}{xd}{xd}
ws		[ \t\r\n]
ipb		(2((5[0-5])|[0-4][0-9]))|(1[0-9][0-9])|([1-9]?[0-9])
sch		([^"]|\\\\|\\\"|\r|\n)

%%

#.*\n

\"{sch}*\"		{ return NMLTOK_STRING; }

(0x)?{xbyte}+		{ return NMLTOK_NUM; }

\\x{xbyte}+		{ return NMLTOK_BYTESTR; }

{ipb}\.{ipb}\.{ipb}\.{ipb} { return NMLTOK_IPADDR; }

{xd}:{xd}:{xd}:{xd}:{xd}:{xd}	{ return NMLTOK_ETHADDR; }

({xq}:)+:?({xq}:*){xq}	{ return NMLTOK_IPV6ADDR; }

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
"/="		{ return NMLTOK_MEQ; }
"*<"		{ return NMLTOK_SLT; }
"*>"		{ return NMLTOK_SGT; }
"*<="		{ return NMLTOK_SLEQ; }
"*>="		{ return NMLTOK_SGEQ; }
"~="		{ return NMLTOK_REX; }

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
">>*"		{ return NMLTOK_SHRA; }
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

.		{ /* error: unknown token */ }

%%


