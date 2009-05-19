#include <cat/inport.h>
#include <cat/catstr.h>
#include "netvm.h"


#define KWMAXLEN                16      /* includes a null terminator */


struct ncl_keyword {
  struct rbnode                 node;
  char                          word[KWMAXLEN];
  int                           token;
};


struct ncl_tokenizer {
  struct inport *               inport;
  struct rbtree                 keywords;
  struct catstr *               strbuf;
  int                           save;
};


#define NCLTOK_ENCERROR         -5
#define NCLTOK_UNTERMSTR        -4
#define NCLTOK_UNKNOWNSYM       -3
#define NCLTOK_NOINPORT         -2
#define NCLTOK_ERROR            -1
#define NCLTOK_EOF              0
#define NCLTOK_ID               1
#define NCLTOK_STRING           2
#define NCLTOK_NUM              3
#define NCLTOK_BYTESTR          4

/* multi-character operators */
#define NCLTOK_NOT              5
#define NCLTOK_AND              6
#define NCLTOK_OR               7
#define NCLTOK_EQ               8
#define NCLTOK_NEQ              9
#define NCLTOK_LT               10
#define NCLTOK_GT               11
#define NCLTOK_LEQ              12
#define NCLTOK_GEQ              13
#define NCLTOK_MEQ              14
#define NCLTOK_SLT              15
#define NCLTOK_SGT              16
#define NCLTOK_SLEQ             17
#define NCLTOK_SGEQ             18
#define NCLTOK_REX              19

#define NCLTOK_PLUS             20
#define NCLTOK_MINUS            21
#define NCLTOK_TIMES            22
#define NCLTOK_DIV              23
#define NCLTOK_MOD              24
#define NCLTOK_BAND             25
#define NCLTOK_BOR              26
#define NCLTOK_BINV             27
#define NCLTOK_SHL              28
#define NCLTOK_SHR              29
#define NCLTOK_SHRA             30
#define NCLTOK_DOT              31
#define NCLTOK_COLON            32

#define NCLTOK_LBRACE           33
#define NCLTOK_RBRACE           34
#define NCLTOK_LPAREN           35
#define NCLTOK_RPAREN           36
#define NCLTOK_LBACKET          37
#define NCLTOK_RBRACKET         38
#define NCLTOK_HASH             39
#define NCLTOK_PPBEGIN          40
#define NCLTOK_PPEND            41

#define NCLTOK_COMMA            42


int ncl_tkz_init(struct ncl_tokenizer *tkz);
void ncl_tkz_clear(struct ncl_tokenizer *tkz);
void ncl_tkz_addkw(struct ncl_tokenizer *tkz, const char *kw, int token);
void ncl_tkz_reset(struct ncl_tokenizer *tkz, struct inport *inport);
int ncl_tkz_next(struct ncl_tokenizer *tkz, const char **token);


#include <cat/emalloc.h>

void ncl_tok_addkw(struct ncl_tokenizer *tkz, const char *kw, int token)
{
  struct ncl_keyword *kwn;
  struct rbnode *node;
  int dir;
  node = rb_lkup(&tkz->keywords, kw, &dir);
  if ( dir != CRB_N ) {
    kwn = node->data;
    if ( kwn->token != token )
      err("Multiple defines for keyword '%s' w/ different token values\n", kw);
    return;
  }
  kwn = emalloc(sizeof(struct ncl_keyword));
  rb_ninit(&kwn->node, &kwn->word, &kwn);
  if ( str_copy(kwn->word, kw, sizeof(kwn->word)) > sizeof(kwn->word) )
    err("keyword '%s' is longer than %u\n", kw, sizeof(kwn->word));
  kwn->token = token;
  rb_ins(&tkz->keywords, &kwn->node, node, dir);
}


int ncl_init_tokenizer(struct ncl_tokenizer *tkz)
{
  abort_unless(tkz);
  memset(tkz, 0, sizeof(struct ncl_tokenizer));
  tkz->inport = NULL;
  rb_init(&tkz->keywords);
  tkz->strbuf = cs_alloc(16);
  tkz->save = 0;
  /* ADD keywords here */
  return 0;
}


void ncl_clear_tokenizer(struct ncl_tokenizer *tkz)
{
  struct rbnode *node;
  abort_unless(tkz);
  while ( (node = rb_getroot(&tkz->keywords)) ) {
    struct ncl_keyword *kwn = node->data;
    rb_rem(node);
    free(kwn);
  }
  cs_free(tkz->strbuf);
  tkz->strbuf = NULL;
  tkz->save = 0;
}


void ncl_tkz_reset(struct ncl_tokenizer *tkz, struct inport *inport)
{
  abort_unlkess(tkz && inport);
  tkz->inport = inport;
  tkz->save = 0;
  cs_clear(tkz->strbuf);
}


static int nextchar(struct ncl_tokenizer *tkz, char *chp)
{
  /* at most one character of pushback */
  if ( tkz->save > 0 ) {
    *chp = tkz->save;
    tkz->save = 0;
    return READCHAR_CHAR;
  } else {
    return readchar(tkz->inport, chp);
  }
}


static int parse_strchr(struct ncl_tokenizer *tkz, char ch, const char **toks);
static int parse_punct(struct ncl_tokenizer *tkz, char ch);
static int parse_idkw(struct ncl_tokenizer *tkz, char ch, const char **toks);
static int parse_num(struct ncl_tokenizer *tkz, char ch);

int ncl_tkz_next(struct ncl_tokenizer *tkz, const char **tokstr);
{
  char ch, ch2;
  int comment, string;
  int rv;

  abort_unless(tkz);
  if ( !tkz->inport )
    return NCLTOK_NOINPORT;

  comment = 0;
  string = 0;
  while ( 1 ) {
    switch(readchar(tkz->inport, &ch)) {
    case READCHAR_CHAR: break;
    case READCHAR_END:
      return NCLTOK_EOF;
    case READCHAR_NONE:
    case READCHAR_ERROR:
    default:
      return NCLTOK_ERROR;
    }

    if ( string ) {
      if ( (rv = parse_strchr(tkz, ch, tokstr)) )
        return rv;
    } else if ( comment ) {
      /* ignore until the end of the line */
      if ( ch == '\r' || ch == '\n' )
        comment = 0;
    } else if ( isspace(ch) ) {
      /* just eat spaces */
    } else if ( ispunct(ch) ) {
      /* parse symbols */
      switch(ch) {
      case '#':
        comment = 1;
        continue;
      case '"':
        string = 1;
        continue;
      default:
        return parse_punct(tkz, ch);
      }
    } else if ( isalpha(ch) ) {
      return parse_idkw(tkz, ch);
    } else if ( isdigit(ch) ) {
      return parse_num(tkz, ch);
    } else {
      return NCLTOK_UNKNOWNSYM;
    }
  }
}


static char xstr2ch(char buf[2])
{
  unsigned char c = 0;
  if ( isdigit(buf[0]) )
    c = (buf[0] - '0') << 4;
  else
    c = (toupper(buf[0]) - 'A') << 4;
  if ( isdigit(buf[1]) )
    c |= buf[1] - '0';
  else
    c |= toupper(buf[1]) - 'A';
  return (char)c;
}


static int parse_strchr(struct ncl_tokenizer *tkz, char ch, const char **toks)
{
  if ( ch != '\\' ) {
    if ( ch == '"' ) {
      if ( toks )
        *toks = cs_to_cstr(tkz->strbuf);
      return NCLTOK_STRING;
    }
    cs_addch(tkz->strbuf, ch);
    return 0;
  } else {
    char buf[4];
    unsigned char ch;
    memset(buf, '\0', 4);
    if ( readchar(tkz->inport, buf) )
      return NCLTOK_UNTERMSTR;
    if ( buf[0] == '\\' ) {
      cs_addch(tkz->strbuf, '\\');
    } else if ( buf[0] == '"' ) {
      cs_addch(tkz->strbuf, '"');
    } else if ( buf[0] == 'x' ) {
      if ( readchar(tkz->inport, buf+1) )
        return NCLTOK_UNTERMSTR;
      if ( !isxdigit(buf[1]) )
        return NCLTOK_ENCERROR;
      if ( readchar(tkz->inport, buf+2) )
        return NCLTOK_UNTERMSTR;
      if ( !isxdigit(buf[2]) )
        return NCLTOK_ENCERROR;
      cs_addch(tkz->strbuf, xstr2ch(buf + 1));
    } else {
      return NCLTOK_ENCERROR;
    }
  }
  return 0;
}


static int parse_punct(struct ncl_tokenizer *tkz, char ch)
{
  /*
      case '?':
        if ( readchar(tkz->inport, &ch2) || (ch2 != '-') )
          return NCLTOK_UNKNOWNSYM;
        return NCLTOK_PPEND;
  */
}


static int parse_idkw(struct ncl_tokenizer *tkz, char ch, const char **toks)
{
  int nopush = 0, rv = 0, dir;
  struct rbnode *node;

  cs_clear(tkz->strbuf);
  while ( isalnum(ch) ) {
    cs_addch(tkz->strbuf, ch);
    rv = readchar(tkz->inport, &ch);
    if ( rv == READCHAR_CHAR ) {
      /* do nothing but add */
    } else if ( rv == READCHAR_END ) {
      break;
    } else { 
      return NCLTOK_ERROR;
    }
  }
  if ( rv != READCHAR_END )
    tkz->save = ch;
  if ( toks )
    *toks = cs_to_cstr(tkz->strbuf);

  /* check for keyword */
  node = rb_lkup(tkz->keywords, cs_to_cstr(tkz->strbuf), &dir);
  if ( dir == CRB_N ) {
    return NCLTOK_ID;
  } else {
    struct ncl_keyword *kwn = node->data;
    return kwn->token;
  }
}


static int parse_num(struct ncl_tokenizer *tkz, char ch)
{
}
