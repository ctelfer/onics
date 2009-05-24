#ifndef __tokenizer_h
#define __tokenizer_h
#include <cat/inport.h>
#include <cat/catstr.h>
#include <cat/mem.h>
#include <cat/rbtree.h>


#define KWMAXLEN                16      /* includes a null terminator */


struct tkz_token {
  int                           id;
  union {
    const char *                sval;
    struct raw                  rawval;
    unsigned long               uival;
    long                        ival;
  } u;
};


struct tkz_reserved {
  struct rbnode                 node;
  char                          word[KWMAXLEN];
  int                           token;
};


struct tokenizer {
  struct inport *               inport;
  struct rbtree                 keywords;
  struct rbtree                 operators;
  struct catstr *               strbuf;
  int                           save;
  struct memmgr *               mm;
};


#define TKZ_NUMBASEERR       -7
#define TKZ_NOMEM            -6
#define TKZ_ENCERROR         -5
#define TKZ_UNTERMSTR        -4
#define TKZ_UNKNOWNSYM       -3
#define TKZ_NOINPORT         -2
#define TKZ_ERROR            -1
#define TKZ_EOF              0
#define TKZ_ID               1
#define TKZ_STRING           2
#define TKZ_NUM              3
#define TKZ_BYTESTR          4


struct tokenizer *tkz_new(struct memmgr *mm);
void tkz_free(struct tokenizer *tkz);
int tkz_addkw(struct tokenizer *tkz, const char *kw, int token);
int tkz_addop(struct tokenizer *tkz, const char *op, int token);
void tkz_reset(struct tokenizer *tkz, struct inport *inport);
int tkz_next(struct tokenizer *tkz, struct tkz_token *tok);


#endif /* __tokenizer_h */
