#ifndef __netvm_rt_h
#define __netvm_rt_h

#include "netvm.h"
#include <cat/list.h>
#include <cat/hash.h>
#include <cat/mem.h>


#define NETVM_IPTYPE_LABEL      1
#define NETVM_IPTYPE_VAR        2

struct netvm_ipatch {
  uint32_t              iaddr;
  uint32_t              delta;
  char *                symname;
  int                   type;
};


struct netvm_label {
  char *                name;
  uint32_t              addr;
};


#define NETVM_ITYPE_NONE        0
#define NETVM_ITYPE_FILL        1
#define NETVM_ITYPE_DATA        2
#define NETVM_ITYPE_LABEL       4
#define NETVM_ITYPE_VADDR       5


struct netvm_var {
  char *                name;
  uint32_t              addr;
  uint32_t              len;
  int                   inittype;
  int                   isrdonly;
  uint32_t              datalen;
  union {
    char *              symname;
    void *              data;
    uint32_t            fill;
  } init_type_u;
};


struct netvm_program {
  int                   matchonly;
  int                   linked;
  struct netvm_inst *   inst;
  size_t                ninst;
  size_t                isiz;
  struct arraymm        rwmm;           /* fake allocator to assign vars */
  struct arraymm        romm;           /* fake allocator to assign RO vars */
  struct htab *         labels;
  struct list *         ipatches;
  struct htab *         vars;
  struct list *         varlist;        /* used for initialization after link */
};


void nprg_init(struct netvm_program *prog, int matchonly);

/* instructions and instruction symbols */
int nprg_add_code(struct netvm_program *prog, struct netvm_inst *inst,
                  uint32_t ninst, uint32_t *iaddr);
int nprg_add_label(struct netvm_program *prog, const char *name, uint32_t iadd);
/* creates a patch for the instruction at iaddr */
int nprg_add_ipatch(struct netvm_program *prog, uint32_t iaddr, uint32_t delta,
                    const char *symname, int type);

/* variables and variable symbols */
struct netvm_var *nprg_add_var(struct netvm_program *prog, const char *name,
                               uint32_t len, int isrdonly);
int nprg_vinit_data(struct netvm_var *var, void *data, uint32_t len);
int nprt_vinit_label(struct netvm_var *var, const char *label, uint32_t delta);
int nprt_vinit_vaddr(struct netvm_var *var, const char *varnam, uint32_t delta);
int nprg_vinit_fill(struct netvm_var *var, uint32_t val, int width);

/* get the amount of memory required by the program */
size_t mem_required(struct netvm_program *prog);

/* resolve all instruction patches in the system */
int nprg_link(struct netvm_program *prog);

/* load a program onto a VM */
int nprg_load(struct netvm *vm, struct netvm_program *prog);

/* release all auxilliary data */
void nprg_release(struct netvm_program *prog);



/* ----------  Functions for running the netvm ------------ */


struct netvm_matchedprog {
  struct netvm_program *        match;
  struct netvm_program *        action;
};

typedef struct pktbuf *(*netvm_pktin_f)(void *ctx);
typedef int (*netvm_pktout_f)(void *ctx, struct pktbuf *pb);

struct netvm_mrt {
  struct netvm *                vm;
  netvm_pktin_f                 pktin;
  void *                        inctx;
  netvm_pktout_f                pktout;
  void *                        outctx;
  struct netvm_program *        begin;
  struct netvm_program *        end;
  struct list *                 pktprogs;
};

void nvmmrt_init(struct netvm_mrt *mrt, struct netvm *vm, netvm_pktin_f inf, 
                 void *inctx, netvm_pktout_f outf, void *outctx);
int nvmmrt_set_begin(struct netvm_mrt *rt, struct netvm_program *prog);
int nvmmrt_set_end(struct netvm_mrt *rt, struct netvm_program *prog);
int nvmmrt_add_pktprog(struct netvm_mrt *rt, struct netvm_program *match,
                       struct netvm_program *action);
int nvmmrt_execute(struct netvm_mrt *rt);
void nvmmrt_release(struct netvm_mrt *rt, void (*progfree)(void *));


/* "Default registers" in memory local to functions (save between calls) */
#define NETVM_LOC_0     0
#define NETVM_LOC_1     8
#define NETVM_LOC_2     16
#define NETVM_LOC_3     24
#define NETVM_LOC_4     32
#define NETVM_LOC_5     40
#define NETVM_LOC_6     48
#define NETVM_LOC_7     56
#define NETVM_LOC_8     64
#define NETVM_LOC_9     72
#define NETVM_LOC_10    80
#define NETVM_LOC_11    88
#define NETVM_LOC_12    96
#define NETVM_LOC_13    104
#define NETVM_LOC_14    112
#define NETVM_LOC_15    120
#define NETVM_ARG_0     128
#define NETVM_ARG_1     136
#define NETVM_ARG_2     144
#define NETVM_ARG_3     152
#define NETVM_ARG_4     160
#define NETVM_ARG_5     168
#define NETVM_ARG_6     176
#define NETVM_ARG_7     184
#define NETVM_ARG_8     192
#define NETVM_ARG_9     200
#define NETVM_ARG_10    208
#define NETVM_ARG_11    216
#define NETVM_ARG_12    224
#define NETVM_ARG_13    232
#define NETVM_ARG_14    240
#define NETVM_ARG_15    248

#define NETVM_RW_BASE   256

#endif /* __netvm_rt_h */
