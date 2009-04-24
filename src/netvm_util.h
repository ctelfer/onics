#ifndef __netvm_util_h
#define __netvm_util_h

#include "netvm.h"

struct netvm_ipatch {
  const char *          symbase;
  uint32_t              offset;
  uint64_t              delta;
};


struct netvm_iloc {
  const char *          name;
  struct list *         patches;
  uint32_t              addr;
  uint32_t              len;
};


#define NETVM_ITYPE_FILL        1
#define NETVM_ITYPE_DATA        2


struct netvm_var {
  const char *          name;
  struct list *         patches;
  uint32_t              addr;
  uint32_t              len;
  int                   inittype;
  uint32_t              datalen;
  union {
    void *              data;
    uint64_t            fill;
  } init_type_u;
};


struct netvm_program {
  int                   matchonly;
  struct netvm_inst *   inst;
  uint32_t              ninst;
  struct arraymsys      rwsys;          /* fake allocator to assign vars */
  struct arraymsys      rosys;          /* fake allocator to assign RO vars */
  struct htab *         isymtab;
  struct htab *         msymtab;
};


void nprg_init(struct netvm_program *prog, int matchonly);

/* instructions and instruction symbols */
struct netvm_iloc *nprg_add_code(struct netvm_program *prog, 
                                 struct netvm_inst *inst uint32_t ninst, 
                                 const char *name);
int nprg_iloc_patch(const char *symbase, uint32_t off, uint64_t delta);
uint32_t nprg_get_iaddr(struct netvm_program *prog, const char *name);


/* variables and variable symbols */
struct netvm_var *nprg_add_var(struct netvm_program *prog, const char *name,
                               uint32_t len);
int nprg_vinit_data(struct netvm_var *var, void *data, uint32_t len);
void nprg_vinit_fill(struct netvm_var *var, uint64_t val, int width);
int nprg_var_patch(const char *symbase, uint32_t off, uint64_t delta);

/* resolve all instruction patches in the system */
int nprg_link(struct netvm *vm);

/* load a program onto a VM */
int nprg_load(struct netvm *vm, struct netvm_program *prog);

/* release all auxilliary data */
void nprg_release(struct netvm_program *prog);



/* ----------  Functions for running the netvm ------------ */
#define BEGIN_SYMBOL    "__BEGIN__"
#define END_SYMBOL      "__END__"
#define PACKET_SYMBOL   "__PACKET__"

typedef struct pktbuf *(*netvm_util_pktin_f)(void *ctx);
typedef int (*netvm_util_pktout_f)(void *ctx, struct pktbuf *pb);

struct netvm_runtime {
  struct netvm *                netvm;
  netvm_util_pktin_f            pktin;
  void *                        inctx;
  netvm_util_pktout_f           pktout;
  void *                        outctx;
};

int nvmrt_execute(struct netvm_runtime *rt, struct netvm_program *prog);


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

#define NETVM_RW_BASE   128

#endif /* __netvm_util_h */
