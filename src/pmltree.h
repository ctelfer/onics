/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#ifndef __pmltree_h
#define __pmltree_h
#include <cat/list.h>
#include <cat/hash.h>

enum {
  PMLTT_SCALAR,
  PMLTT_BYTESTR,
  PMLTT_MASKVAL,
  PMLTT_VARREF,
  PMLTT_BINOP,
  PMLTT_UNOP,
  PMLTT_EXPRLIST,
  PMLTT_FUNCALL,
  PMLTT_IF,
  PMLTT_WHILE,
  PMLTT_PKTACT,
  PMLTT_SETACT,
  PMLTT_PRINT,
  PMLTT_STMTLIST,
  PMLTT_FUNCTION,
  PMLTT_RULE,
};


struct pml_prog {
  struct list           pmlp_decls;
  struct htab           pmlp_gvars;
  struct htab           pmlp_funcs;
  struct pml_function * pmlp_inside;
};


struct pml_expr {
  int                   pmle_type;
  struct list           pmle_ln;
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
  struct list		pmlv_ln;
  union {
    struct pml_scalar   u_scalar;
    struct raw          u_bytestr;
    struct pml_maskval  u_maskval;
    struct pml_variable *u_varref;
  } pmlv_u;
};

#define pmlv_scalar     pmlv_u.u_scalar
#define pmlv_sval       pmlv_u.u_scalar.pmls_val
#define pmlv_swidth     pmlv_u.u_scalar.pmls_width
#define pmlv_byteval    pmlv_u.u_bytestr
#define pmlv_maskval    pmlv_u.u_maskval
#define pmlv_mval       pmlv_u.u_maskval.pmlm_val
#define pmlv_mmask      pmlv_u.u_maskval.pmlm_mask
#define pmlv_varref	pmlv_u.u_varref

struct pml_binop {
  int                   pmlb_type;
  struct list		pmlb_ln;
  int                   pmlb_op;
  union pml_expr_u *    pmlb_left;
  union pml_expr_u *    pmlb_right;
};


struct pml_unop {
  int                   pmlu_type;
  struct list		pmlu_ln;
  int                   pmlu_op;
  union pml_expr_u *    pmlu_expr;
};


union pml_expr_u {
  struct pml_expr       expr;
  struct pml_value      value;
  struct pml_binop      binop;
  struct pml_unop       unop;
};


struct pml_exprlist {
  int                   pmlel_type;
  struct list           pmlel_exprs;
};


struct pml_stmt {
  int                   pmls_type;
  struct list           pmls_ln;
};


struct pml_funcall {
  int                   pmlfc_type;
  struct list           pmlfc_ln;
  struct pml_func *     pmlfc_func;
  struct pml_exprlist * pmlfc_args;
};


struct pml_if {
  int                   pmlif_type;
  struct list           pmlif_ln;
  union pml_expr_u *    pmlif_test;
  struct pml_stmtlist * pmlif_tbody;
  struct pml_stmtlist * pmlif_fbody;
};


struct pml_while {
  int                   pmlw_type;
  struct list           pmlw_ln;
  union pml_expr_u *    pmlw_test;
  struct pml_stmtlist * pmlw_body;
};


enum {
  PMLPA_DROP = 1,
  PMLPA_INSERT = 2,
  PMLPA_CUT = 3,
  PMLPA_DUP = 4,
  PMLPA_HDRPUSH = 5,
  PMLPA_FIXLEN = 6,
  PMLPA_FIXCSUM = 7,
  PMLPA_DLT = 8,
  PMLPA_ENQUEUE = 9,
};


struct pml_pkt_action {
  int                   pmlpa_type;
  struct list           pmlpa_ln;
  int                   pmlpa_action;
  union pml_expr_u *    pmlpa_pkt;
  char *                pmlpa_name;
  union pml_expr_u *    pmlpa_off;
  union pml_expr_u *    pmlpa_amount;   /* for insert or cut */
};


struct pml_set_action {
  int                   pmlsa_type;
  struct list           pmlsa_ln;
  int                   pmlsa_conv;             /* byte order conversion */
  char *                pmlsa_vname;
  union pml_expr_u *    pmlsa_off;
  union pml_expr_u *    pmlsa_len;
  union pml_expr_u *    pmlsa_newval;
};


struct pml_print {
  int                   pmlp_type;
  struct list           pmlp_ln;
  char *                pmlp_fmt;
  struct pml_exprlist * pmlp_args;
};


struct pml_stmtlist {
  int                   pmlsl_type;
  struct list           pmlsl_stmts;
};


struct pml_variable {
  struct hnode          pmlvar_hn;
  char *                pmlvar_name;
  int                   pmlvar_width;
  int                   pmlvar_num;
  int                   pmlvar_signed;
};


struct pml_function {
  int                   pmlf_type;
  struct list		pmlf_ln;
  char *                pmlf_name;
  char **               pmlf_pnames;
  uint                  pmlf_nparams;
  struct htab           pmlf_vars;
  struct pml_stmtlist * pmlf_body;
};


struct pml_rule {
  int                   pmlr_type;
  struct list		pmlr_ln;
  union pml_expr_u *    pmlr_pattern;
  struct pml_stmtlist * pmlr_stmts;
};


union pml_tree {
  struct pml_expr       expr;
  struct pml_value      value;
  struct pml_binop      binop;
  struct pml_unop       unop;
  union pml_expr_u      expr_u;
  struct pml_exprlist   exprlist;
  struct pml_stmt       stmt;
  struct pml_funcall    funcall;
  struct pml_if         ifstmt;
  struct pml_while      whilestmt;
  struct pml_pkt_action pktact;
  struct pml_set_action setact;
  struct pml_print      print;
  struct pml_stmtlist   stmtlist;
  struct pml_function   function;
  struct pml_rule       rule;
};


union pml_tree *pmlt_alloc(int pmltt);
void pmlt_free(union pml_tree *tree);


#endif /* __pmtree_h */
