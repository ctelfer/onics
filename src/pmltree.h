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
  PMLTT_EXPRLIST = 6,
  PMLTT_FUNCALL = 7,
  PMLTT_STMTLIST = 8,
  PMLTT_IF      = 9,
  PMLTT_WHILE   = 10,
  PMLTT_PKTACT  = 11,
  PMLTT_SETACT  = 12,
  PMLTT_FUNCTION = 13,
  PMLTT_PRINT = 14,
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


struct pml_funcall {
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
  int                   pmlpa_action;
  union pml_expr *      pmlpa_pkt;
  char *                pmlpa_name;
  union pml_expr *      pmlpa_off;
  union pml_expr *      pmlpa_amount;   /* for insert or cut */
};


struct pml_set_action {
  int                   pmlsa_type;
  int                   pmlsa_conv;             /* byte order conversion */
  char *                pmlsa_vname;
  union pml_expr *      pmlsa_off;
  union pml_expr *      pmlsa_len;
  union pml_expr *      pmlsa_newval;
};


struct pml_variable {
  char *                pmlvar_name;
  int                   pmlvar_width;
  int                   pmlvar_num;
  int                   pmlvar_signed;
};


struct pml_ns {
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


struct pml_print {
  int                   pmlp_type;
  char *                pmlp_fmt;
  struct pml_exprlist * pmlp_params;
};


union pml_tree {
  struct pml_value      value;
  struct pml_binop      binop;
  struct pml_unop       unop;
  struct pml_exprlist   exprlist;
  struct pml_funcall    funcall;
  struct pml_stmtlist   stmtlist;
  struct pml_if         ifstmt;
  struct pml_while      whilestmt;
  struct pml_pkt_action pktact;
  struct pml_set_action setact;
  struct pml_function   function;
  struct pml_print      print;
};



#endif /* __pmtree_h */
