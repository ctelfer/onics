#include "tokenizer.h"
#include <cat/stduse.h>

#define TKZ_MAXPUNCTLEN         3


struct tokenizer *tkz_new(struct memmgr *mm)
{
  struct tokenizer *tkz;
  if ( !mm )
    mm = &estdmem;
  if ( (tkz = mem_get(mm, sizeof(struct tokenizer))) ) {
    memset(tkz, 0, sizeof(struct tokenizer));
    tkz->inport = NULL;
    rb_init(&tkz->keywords);
    rb_init(&tkz->operators);
    if ( !(tkz->strbuf = cs_alloc(16)) )
      return -1;
    tkz->save = 0;
    tkz->mm = mm;
  }
  return tkz;
}


void tkz_free(struct tokenizer *tkz)
{
  struct rbnode *node;
  struct memmgr *mm;
  abort_unless(tkz);
  mm = tkz->mm;
  while ( (node = rb_getroot(&tkz->keywords)) ) {
    struct tkz_reserved *kwn = node->data;
    rb_rem(node);
    free(kwn);
  }
  while ( (node = rb_getroot(&tkz->operators)) ) {
    struct tkz_reserved *opn = node->data;
    rb_rem(node);
    free(opn);
  }
  cs_free(tkz->strbuf);
  tkz->strbuf = NULL;
  tkz->save = 0;
  mem_free(mm, tkz);
}


static int tkz_add_rb(struct tokenizer *tkz, const char *str, int token, 
                      int iskw)
{
  struct tkz_reserved *rn;
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
  if ( (rn = mem_get(tkz->mm, sizeof(struct tkz_reserved))) == NULL )
    return -1;
  rb_ninit(&rn->node, &rn->word, &rn);
  if ( str_copy(rn->word, str, sizeof(rn->word)) > sizeof(rn->word) )
    err("'%s' is longer than %u\n", str, sizeof(rn->word));
  rn->token = token;
  rb_ins(rbt, &rn->node, node, dir);

  return 0;
}


int tkz_addkw(struct tokenizer *tkz, const char *str, int token)
{
  const char *s = str;
  abort_unless(tkz && str && token > 0);
  if ( !isalpha(*str) )
    return -1;
  return tkz_add_rb(tkz, str, token, 1);
}


int tkz_addop(struct tokenizer *tkz, const char *str, int token)
{
  abort_unless(tkz && str && token > 0);
  if ( !ispunct(*str) )
    return -1;
  return tkz_add_rb(tkz, str, token, 0);
}


void tkz_reset(struct tokenizer *tkz, struct inport *inport)
{
  abort_unlkess(tkz && inport);
  tkz->inport = inport;
  tkz->save = 0;
  cs_clear(tkz->strbuf);
}


static int nextchar(struct tokenizer *tkz, char *chp);
static int parse_strchr(struct tokenizer *tkz, char ch, struct tkz_token *tok);
static int parse_punct(struct tokenizer *tkz, char ch, struct tkz_token *tok);
static int parse_bytestr(struct tokenizer *tkz, struct tkz_token *tok);
static int parse_idkw(struct tokenizer *tkz, char ch, struct tkz_token *tok);
static int parse_num(struct tokenizer *tkz, char ch, struct tkz_token *tok);


int tkz_next(struct tokenizer *tkz, struct tkz_token *tok);
{
  char ch, ch2;
  int comment, string;
  int rv;

  abort_unless(tkz);
  if ( !tkz->inport )
    return TKZ_NOINPORT;

  cs_clear(tkz->strbuf);
  comment = 0;
  string = 0;
  while ( 1 ) {
    switch(nextchar(tkz, &ch)) {
    case READCHAR_CHAR: break;
    case READCHAR_END:
      return TKZ_EOF;
    case READCHAR_NONE:
    case READCHAR_ERROR:
    default:
      return TKZ_ERROR;
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
      return TKZ_UNKNOWNSYM;
    }
  }
}


static int nextchar(struct tokenizer *tkz, char *chp)
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


static int parse_strchr(struct tokenizer *tkz, char ch, struct tkz_token *tok)
{
  if ( ch != '\\' ) {
    if ( ch == '"' ) {
      tok->id = TKZ_STRING;
      tok->u.sval = cs_to_cstr(tkz->strbuf);
      return tok->id;
    }
    if ( !cs_addch(tkz->strbuf, ch) )
      return TKZ_NOMEM;
    return 0;
  } else {
    char buf[4];
    unsigned char ch;
    memset(buf, '\0', 4);
    if ( readchar(tkz->inport, buf) )
      return TKZ_UNTERMSTR;
    if ( buf[0] == '\\' ) {
      if ( !cs_addch(tkz->strbuf, '\\') )
        return TKZ_NOMEM;
    } else if ( buf[0] == '"' ) {
      if ( !cs_addch(tkz->strbuf, '"') )
        return TKZ_NOMEM;
    } else if ( buf[0] == 'x' ) {
      if ( readchar(tkz->inport, buf+1) )
        return TKZ_UNTERMSTR;
      if ( !isxdigit(buf[1]) )
        return TKZ_ENCERROR;
      if ( readchar(tkz->inport, buf+2) )
        return TKZ_UNTERMSTR;
      if ( !isxdigit(buf[2]) )
        return TKZ_ENCERROR;
      if ( !cs_addch(tkz->strbuf, xstr2ch(buf + 1)) )
        return TKZ_NOMEM;
    } else {
      return TKZ_ENCERROR;
    }
  }
  return 0;
}


static int parse_punct(struct tokenizer *tkz, char ch, struct tkz_token *tok)
{
  char buf[TKZ_MAXPUNCTLEN+1] = { ch , '\0' };
  struct rbnode *node;
  int np = 1, rv, dir;
  struct tkz_reserved *op;

  while ( np < TKZ_MAXPUNCTLEN+1 ) {
    rv = readchar(tkz->inport, &ch);
    if ( rv == READCHAR_CHAR ) {
      if ( ispunct(ch) ) {
        if ( np == TKZ_NUMPUNCTLEN )
          return TKZ_UNKNOWNSYM;
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
      return TKZ_ERROR;
    }
  }

  buf[np] = '\0';
  node = rb_lkup(tkz->operators, cs_to_cstr(buf), &dir);
  if ( dir == CRB_N )
    return TKZ_UNKNOWNSYM;
  op = node->data;
  tok->id = op->token;
  return tok->id;
}


#define xval(c) (isdigit(c) ? (c) - '0' : (tolower(c) - 'a' + 10))
static int parse_bytestr(struct tokenizer *tkz, struct tkz_token *tok)
{
  char digits[2];
  unsigned int i = 0, rv;

  while ( !(rv = readchar(tkz->inport, &digits[i&1])) && isxdigit(ch) ) {
    if ( ++i & 1 == 0 )
      if ( !cs_addch(tkz->strbuf, xval(digits[0]) << 4 | xval(digits[1])) )
        return TKZ_NOMEM;
  }
  if ( rv == READCHAR_CHAR )
    tkz->save = ch;
  else if ( rv == READCHAR_END )
    tkz->save = EOF;
  else
    return TKZ_ERROR;

  if ( i & 1 )
    if ( !cs_addch(tkz->strbuf, xval(digits[0]) << 4) )
        return TKZ_NOMEM;

  tok->u.rawval.data = (byte_t)tkz->strbuf->cs_data;
  tok->u.rawval.len = tkz->strbuf->cs_dlen;
  tok->id = TKZ_BYTESTR;
  return tok->id;
}


static int parse_idkw(struct tokenizer *tkz, char ch, struct tkz_token *tok)
{
  int nopush = 0, rv = 0, dir;
  struct rbnode *node;

  while ( isalnum(ch) || (ch == '_') ) {
    if ( !cs_addch(tkz->strbuf, ch) )
      return TKZ_NOMEM;
    rv = readchar(tkz->inport, &ch);
    if ( rv == READCHAR_CHAR ) {
      /* do nothing but add */
    } else if ( rv == READCHAR_END ) {
      tkz->save = EOF;
      break;
    } else { 
      return TKZ_ERROR;
    }
  }
  if ( rv != READCHAR_END )
    tkz->save = ch;
  tok->u.sval = cs_to_cstr(tkz->strbuf);

  /* check for keyword */
  node = rb_lkup(tkz->keywords, cs_to_cstr(tkz->strbuf), &dir);
  if ( dir == CRB_N ) {
    tok->id = TKZ_ID;
  } else {
    struct tkz_reserved *kwn = node->data;
    tok->id = kwn->token;
  }
  return tok->id;
}


static int parse_num(struct tokenizer *tkz, char ch, struct tkz_token *tok)
{
  int base = 10, rv;
  char cp;

  if ( !cs_addch(tkz->strbuf, ch) )
    return TKZ_NOMEM;

  tkz->save = 0;
  rv = readchar(tkz->inport, &ch);
  if ( rv == READCHAR_END ) {
    tkz->save = EOF;
  } else if ( !isdigit(ch) ) {
    if ( (tkz->strbuf->cs_data[0] != '0') || (ch != 'x') )
      tkz->save = ch;
  } else {
    if ( !cs_addch(tkz->strbuf, ch) )
      return TKZ_NOMEM;
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
      return TKZ_NOMEM;
  }
  if ( rv == READCHAR_END )
    tkz->save = EOF;
  else if ( rv != READCHAR_CHAR )
    return TKZ_ERROR;

  tok->id = TKZ_NUM;
  tok->u.uival = strtoul(cs_to_cstr(tkz->strbuf), &cp, base);
  if ( cp != cs_to_cstr(tkz->strbuf) + tkz->strbuf->cs_dlen )
    return TKZ_NUMBASEERR;
  return tok->id;
}
