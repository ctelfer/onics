#include <cat/inport.h>
#include <cat/catstr.h>
#include <cat/mem.h>
#include "netvm.h"


#define KWMAXLEN                16      /* includes a null terminator */


struct ncl_token {
  int                           id;
  union {
    const char *                sval;
    struct raw                  rawval;
    unsigned long               uival;
    long                        ival;
  } u;
};


struct ncl_reserved {
  struct rbnode                 node;
  char                          word[KWMAXLEN];
  int                           token;
};


struct ncl_tokenizer {
  struct inport *               inport;
  struct rbtree                 keywords;
  struct rbtree                 operators;
  struct catstr *               strbuf;
  int                           save;
  struct memmgr                 mm;
};


#define NCLTOK_NUMBASEERR       -7
#define NCLTOK_NOMEM            -6
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

#define NCLTOK_MAXPUNCTLEN      2


int ncl_tkz_init(struct ncl_tokenizer *tkz, struct memmgr *mm);
void ncl_tkz_destroy(struct ncl_tokenizer *tkz);
int ncl_tkz_addkw(struct ncl_tokenizer *tkz, const char *kw, int token);
int ncl_tkz_reset(struct ncl_tokenizer *tkz, struct inport *inport);
int ncl_tkz_next(struct ncl_tokenizer *tkz, struct ncl_token *tok);


static int ncl_tkz_add_rb(struct ncl_tokenizer *tkz, const char *str, 
                          int token, int iskw)
{
  struct ncl_reserved *rn;
  struct rbnode *node;
  int dir;
  struct rbtree  *rbt;
  abort_unless(tkz && str && token > 0);

  rbt = iskw ? &tkz->keywords : tkz->operators;
  node = rb_lkup(rbt, str, &dir);
  if ( dir != CRB_N ) {
    rn = node->data;
    if ( rn->token != token )
      return -1;
    return 0;
  }
  if ( (rn = mem_get(&tkz->mm, sizeof(struct ncl_reserved))) == NULL )
    return -1;
  rb_ninit(&rn->node, &rn->word, &rn);
  if ( str_copy(rn->word, str, sizeof(rn->word)) > sizeof(rn->word) )
    err("'%s' is longer than %u\n", str, sizeof(rn->word));
  rn->token = token;
  rb_ins(rbt, &rn->node, node, dir);

  return 0;
}



int ncl_tkz_addkw(struct ncl_tokenizer *tkz, const char *str, int token)
{
  const char *s = str;
  abort_unless(tkz && str && token > 0);
  if ( !isalpha(*str) )
    return -1;
  return ncl_tkz_add_rb(tkz, str, token, 1);
}


int ncl_tkz_addop(struct ncl_tokenizer *tkz, const char *str, int token)
{
  abort_unless(tkz && str && token > 0);
  if ( !ispunct(*str) )
    return -1;
  return ncl_tkz_add_rb(tkz, str, token, 0);
}


int ncl_tkz_init(struct ncl_tokenizer *tkz, struct memmgr *mm)
{
  abort_unless(tkz);
  memset(tkz, 0, sizeof(struct ncl_tokenizer));
  tkz->inport = NULL;
  rb_init(&tkz->keywords);
  rb_init(&tkz->operators);
  if ( !(tkz->strbuf = cs_alloc(16)) )
    return -1;
  tkz->save = 0;
  if ( mm )
    tkz->mm = *mm;
  else
    tkz->mm = estdmem;
  return 0;
}


void ncl_tkz_destroy(struct ncl_tokenizer *tkz)
{
  struct rbnode *node;
  abort_unless(tkz);
  while ( (node = rb_getroot(&tkz->keywords)) ) {
    struct ncl_reserved *kwn = node->data;
    rb_rem(node);
    free(kwn);
  }
  while ( (node = rb_getroot(&tkz->operators)) ) {
    struct ncl_reserved *opn = node->data;
    rb_rem(node);
    free(opn);
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
  if ( tkz->save == EOF ) {
    return READCHAR_END;
  } else if ( tkz->save > 0 ) {
    *chp = tkz->save;
    tkz->save = 0;
    return READCHAR_CHAR;
  } else {
    return readchar(tkz->inport, chp);
  }
}


static int parse_strchr(struct ncl_tokenizer *tkz, char ch,
                        struct ncl_token *tok);
static int parse_punct(struct ncl_tokenizer *tkz, char ch,
                       struct ncl_token *tok);
static int parse_bytestr(struct ncl_tokenizer *tkz, struct ncl_token *tok);
static int parse_idkw(struct ncl_tokenizer *tkz, char ch, 
                      struct ncl_token *tok);
static int parse_num(struct ncl_tokenizer *tkz, char ch,
                     struct ncl_token *tok);

int ncl_tkz_next(struct ncl_tokenizer *tkz, struct ncl_token *tok);
{
  char ch, ch2;
  int comment, string;
  int rv;

  abort_unless(tkz);
  if ( !tkz->inport )
    return NCLTOK_NOINPORT;

  cs_clear(tkz->strbuf);
  comment = 0;
  string = 0;
  while ( 1 ) {
    switch(nextchar(tkz, &ch)) {
    case READCHAR_CHAR: break;
    case READCHAR_END:
      return NCLTOK_EOF;
    case READCHAR_NONE:
    case READCHAR_ERROR:
    default:
      return NCLTOK_ERROR;
    }

    if ( string ) {
      if ( (rv = parse_strchr(tkz, ch, tok)) )
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
        return parse_punct(tkz, ch, tok);
      }
    } else if ( isalpha(ch) ) {
      return parse_idkw(tkz, ch, tok);
    } else if ( isdigit(ch) ) {
      return parse_num(tkz, ch, tok);
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


static int parse_strchr(struct ncl_tokenizer *tkz, char ch,
                        struct ncl_token *tok)
{
  if ( ch != '\\' ) {
    if ( ch == '"' ) {
      tok->id = NCLTOK_STRING;
      tok->u.sval = cs_to_cstr(tkz->strbuf);
      return tok->id;
    }
    if ( !cs_addch(tkz->strbuf, ch) )
      return NCLTOK_NOMEM;
    return 0;
  } else {
    char buf[4];
    unsigned char ch;
    memset(buf, '\0', 4);
    if ( readchar(tkz->inport, buf) )
      return NCLTOK_UNTERMSTR;
    if ( buf[0] == '\\' ) {
      if ( !cs_addch(tkz->strbuf, '\\') )
        return NCLTOK_NOMEM;
    } else if ( buf[0] == '"' ) {
      if ( !cs_addch(tkz->strbuf, '"') )
        return NCLTOK_NOMEM;
    } else if ( buf[0] == 'x' ) {
      if ( readchar(tkz->inport, buf+1) )
        return NCLTOK_UNTERMSTR;
      if ( !isxdigit(buf[1]) )
        return NCLTOK_ENCERROR;
      if ( readchar(tkz->inport, buf+2) )
        return NCLTOK_UNTERMSTR;
      if ( !isxdigit(buf[2]) )
        return NCLTOK_ENCERROR;
      if ( !cs_addch(tkz->strbuf, xstr2ch(buf + 1)) )
        return NCLTOK_NOMEM;
    } else {
      return NCLTOK_ENCERROR;
    }
  }
  return 0;
}


static int parse_punct(struct ncl_tokenizer *tkz, char ch,
                       struct ncl_token *tok)
{
  char buf[NCLTOK_MAXPUNCTLEN+1] = { ch , '\0' };
  struct rbnode *node;
  int np = 1, rv, dir;
  struct ncl_reserved *op;

  while ( np < NCLTOK_MAXPUNCTLEN+1 ) {
    rv = readchar(tkz->inport, &ch);
    if ( rv == READCHAR_CHAR ) {
      if ( ispunct(ch) ) {
        if ( np == NCLTOK_NUMPUNCTLEN )
          return NCLTOK_UNKNOWNSYM;
        buf[np] = ch;
        ++np;
      } else {
        if ( (np == 1) && (buf[0] == '\\') && (ch == 'x') )
          return parse_bytestr(tkz, tok);
        tkz->save = ch;
        break;
      }
    } else if ( rv == READCHAR_END ) {
      tkz->save = EOF;
      break;
    } else { 
      return NCLTOK_ERROR;
    }
  }

  buf[np] = '\0';
  node = rb_lkup(tkz->operators, cs_to_cstr(buf), &dir);
  if ( dir == CRB_N )
    return NCLTOK_UNKNOWNSYM;
  op = node->data;
  tok->id = op->token;
  return tok->id;
}

#define xval(c) (isdigit(c) ? (c) - '0' : (tolower(c) - 'a' + 10))
static int parse_bytestr(struct ncl_tokenizer *tkz, struct ncl_token *tok)
{
  char digits[2];
  unsigned int i = 0, rv;

  while ( !(rv = readchar(tkz->inport, &digits[i&1])) && isxdigit(ch) ) {
    if ( ++i & 1 == 0 )
      if ( !cs_addch(tkz->strbuf, xval(digits[0]) << 4 | xval(digits[1])) )
        return NCLTOK_NOMEM;
  }
  if ( rv == READCHAR_CHAR )
    tkz->save = ch;
  else if ( rv == READCHAR_END )
    tkz->save = EOF;
  else
    return NCLTOK_ERROR;

  if ( i & 1 )
    if ( !cs_addch(tkz->strbuf, xval(digits[0]) << 4) )
        return NCLTOK_NOMEM;

  tok->u.rawval.data = (byte_t)tkz->strbuf->cs_data;
  tok->u.rawval.len = tkz->strbuf->cs_dlen;
  tok->id = NCLTOK_BYTESTR;
  return tok->id;
}


static int parse_idkw(struct ncl_tokenizer *tkz, char ch, 
                      struct ncl_token *tok)
{
  int nopush = 0, rv = 0, dir;
  struct rbnode *node;

  while ( isalnum(ch) || (ch == '_') ) {
    if ( !cs_addch(tkz->strbuf, ch) )
      return NCLTOK_NOMEM;
    rv = readchar(tkz->inport, &ch);
    if ( rv == READCHAR_CHAR ) {
      /* do nothing but add */
    } else if ( rv == READCHAR_END ) {
      tkz->save = EOF;
      break;
    } else { 
      return NCLTOK_ERROR;
    }
  }
  if ( rv != READCHAR_END )
    tkz->save = ch;
  tok->u.sval = cs_to_cstr(tkz->strbuf);

  /* check for keyword */
  node = rb_lkup(tkz->keywords, cs_to_cstr(tkz->strbuf), &dir);
  if ( dir == CRB_N ) {
    tok->id = NCLTOK_ID;
  } else {
    struct ncl_reserved *kwn = node->data;
    tok->id = kwn->token;
  }
  return tok->id;
}


static int parse_num(struct ncl_tokenizer *tkz, char ch,
                     struct ncl_token *tok)
{
  int base = 10, rv;
  char cp;

  if ( !cs_addch(tkz->strbuf, ch) )
    return NCLTOK_NOMEM;

  tkz->save = 0;
  rv = readchar(tkz->inport, &ch);
  if ( rv == READCHAR_END ) {
    tkz->save = EOF;
  } else if ( !isdigit(ch) ) {
    if ( (tkz->strbuf->cs_data[0] != '0') || (ch != 'x') )
      tkz->save = ch;
  } else {
    if ( !cs_addch(tkz->strbuf, ch) )
      return NCLTOK_NOMEM;
    if ( tkz->strbuf->cs_data[0] == '0' )
      base = 8;
  }

  while ( !(rv = readchar(tkz->inport, &ch)) ) {
    /* will catch 8's and 9's in base-8 below */
    if ( !isdigit(ch) && ((base != 16) || !isxdigit(ch)) ) {
      tkz->save = ch;
      break;
    }
    if ( !cs_addch(tkz->strbuf, ch) )
      return NCLTOK_NOMEM;
  }
  if ( rv == READCHAR_END )
    tkz->save = EOF;
  else if ( rv != READCHAR_CHAR )
    return NCLTOK_ERROR;

  tok->id = NCLTOK_NUM;
  tok->u.uival = strtoul(cs_to_cstr(tkz->strbuf), &cp, base);
  if ( cp != cs_to_cstr(tkz->strbuf) + tkz->strbuf->cs_dlen )
    return NCLTOK_NUMBASEERR;
  return tok->id;
}
