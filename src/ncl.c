#include "ncltok.h"
#include <cat/stduse.h>

#define ADDOP(s, n) \
  if ( tkz_addop(tkz, (s), (n)) ) \
    goto err;
#define ADDKW(s, n) \
  if ( tkz_addkw(tkz, (s), (n)) ) \
    goto err;
struct tokenizer *ncl_tkz_new()
{
  struct tokenizer *tkz = tkz_new(&stdmem);
  if ( !tkz )
    return NULL;

  ADDKW("not", NCLTOK_NOT);
  ADDKW("and", NCLTOK_AND);
  ADDKW("or", NCLTOK_OR);

  ADDOP("==", NCLTOK_EQ);
  ADDOP("!=", NCLTOK_NEQ);
  ADDOP("<", NCLTOK_LT);
  ADDOP(">", NCLTOK_GT);
  ADDOP("<=", NCLTOK_LEQ);
  ADDOP(">=", NCLTOK_GEQ);
  ADDOP("/=", NCLTOK_MEQ);
  ADDOP("*<", NCLTOK_SLT);
  ADDOP("*>", NCLTOK_SGT);
  ADDOP("*<=", NCLTOK_SLEQ);
  ADDOP("*>=", NCLTOK_SGEQ);
  ADDOP("~=", NCLTOK_REX);

  ADDOP("+", NCLTOK_PLUS);
  ADDOP("-", NCLTOK_MINUS);
  ADDOP("*", NCLTOK_TIMES);
  ADDOP("/", NCLTOK_DIV);
  ADDOP("%", NCLTOK_MOD);
  ADDOP("&", NCLTOK_BAND);
  ADDOP("|", NCLTOK_BOR);
  ADDOP("~", NCLTOK_BINV);
  ADDOP("<<", NCLTOK_SHL);
  ADDOP(">>", NCLTOK_SHR);
  ADDOP(">>*", NCLTOK_SHRA);
  ADDOP(".", NCLTOK_DOT);
  ADDOP(":", NCLTOK_COLON);

  ADDOP("{", NCLTOK_LBRACE);
  ADDOP("}", NCLTOK_RBRACE);
  ADDOP("(", NCLTOK_LPAREN);
  ADDOP(")", NCLTOK_RPAREN);
  ADDOP("[", NCLTOK_LBRACKET);
  ADDOP("]", NCLTOK_RBRACKET);
  ADDOP("?-", NCLTOK_PPBEGIN);
  ADDOP("-?", NCLTOK_PPEND);
  ADDOP(",", NCLTOK_COMMA);
  
  return tkz;

err:
  tkz_free(tkz);
  return NULL;
}
#undef ADDOP
#undef ADDKW

