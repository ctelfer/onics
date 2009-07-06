/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#ifndef __pmltree_h
#define __pmltree_h
#include <cat/list.h>
#include <cat/hash.h>
#include <cat/stduse.h>

enum {
  PMLTT_SCALAR  = 1,
  PMLTT_BYTESTR = 2,
  PMLTT_MASKVAL = 3,
  PMLTT_BINOP   = 4,
  PMLTT_UNOP    = 5,
};


struct pml_maskval {
  struct raw            pmlm_val;
  struct raw            pmlm_mask;
};


struct pml_scalar {
  unsigned long         pmls_val;
  int                   pmls_width;
};


struct pml_value {
  int                   pmlv_type;
  union {
    struct pml_scalar   u_scalar;
    struct raw          u_bytestr;
    struct pml_maskval  u_maskval;
  } pmlv_u;
};

#define pmlv_scalar     pmlv_u.u_scalar
#define pmlv_sval       pmlv_u.u_scalar.pmls_val
#define pmlv_swidth     pmlv_u.u_scalar.pmls_width
#define pmlv_byteval    pmlv_u.u_bytestr
#define pmlv_maskval    pmlv_u.u_maskval
#define pmlv_mval       pmlv_u.u_maskval.pmlm_val
#define pmlv_mmask      pmlv_u.u_maskval.pmlm_mask

struct pml_binop {
  int                   pmlb_type;
  int                   pmlb_op;
  union pml_expr *      pmlb_left;
  union pml_expr *      pmlb_right;
};


struct pml_unop {
  int                   pmlu_type;
  int                   pmlu_op;
  union pml_expr *      pmlb_expr;
};


union pml_expr {
  struct pml_value      pmln_value;
  struct pml_binop      pmln_binop;
  struct pml_unop       pmln_unop;
};


struct pml_exprlist {
  int                   pmlel_type;
  struct list *         pmlel_exprs;
};


struct pml_function {
  int                   pmlfc_type;
  struct pml_func *     pmlfc_func;
  struct pml_exprlist * pmlfc_params;
};


struct pml_stmtlist {
  int                   pmlsl_type;
  struct list *         pmlsl_stmts;
};


struct pml_if {
  int                   pmlif_type;
  union pml_expr *      pmlif_test;
  struct pml_stmtlist * pmlif_tbody;
  struct pml_stmtlist * pmlif_fbody;
};


struct pml_while {
  int                   pmlw_type;
  union pml_expr *      pmlw_test;
  struct pml_stmtlist * pmlw_body;
};


struct pml_variable {
  int                   pmlvar_type;
  char *                pmlvar_name;
  int                   pmlvar_width;
  int                   pmlvar_num;
  int                   pmlvar_signed;
};


struct pml_ns {
  int                   pmlns_type;
  struct pml_ns *       pmlns_parent;
  struct htab *         pmlns_vars;
  struct htab *         pmlns_funcs;
};


struct pml_function {
  int                   pmlf_type;
  char *                pmlf_name;
  struct list *         pmlf_pnames;
  struct pml_ns         pmlf_ns;
  struct pml_stmtlist * pmlf_body;
};



#endif /* __pmtree_h */
