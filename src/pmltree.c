/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#include "pmltree.h"
#include <stdlib.h>

union pml_tree *pmlt_alloc(int pmltt)
{
  switch(pmltt) {
  case PMLTT_SCALAR:
  case PMLTT_BYTESTR:
  case PMLTT_MASKVAL: {
    struct pml_value *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlv_type = pmltt;
    if ( pmltt == PMLTT_SCALAR ) {
      p->pmlv_sval = 0;
      p->pmlv_swidth = 4;
    } else if ( pmltt == PMLTT_BYTESTR ) {
      p->pmlv_byteval.data = NULL;
      p->pmlv_byteval.len = 0;
    } else {
      p->pmlv_mval.data = NULL;
      p->pmlv_mval.len = 0;
      p->pmlv_mmask.data = NULL;
      p->pmlv_mmask.len = 0;
    }
    l_init(&p->pmlv_ln);
    return (union pml_tree *)p;
  } break;

  case PMLTT_BINOP: {
    struct pml_binop *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlb_type = pmltt;
    p->pmlb_op = 0;
    p->pmlb_left = NULL;
    p->pmlb_right = NULL;
    return (union pml_tree *)p;
  } break;

  case PMLTT_UNOP: {
    struct pml_unop *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlu_type = pmltt;
    p->pmlu_op = 0;
    p->pmlb_expr = NULL;
    return (union pml_tree *)p;
  } break;

  case PMLTT_EXPRLIST: {
    struct pml_exprlist *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlel_type = pmltt;
    l_init(&p->pmlel_exprs);
    return (union pml_tree *)p;
  }  break;

  case PMLTT_FUNCALL: {
    struct pml_funcall *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlfc_type = pmltt;
    p->pmlfc_func = NULL;
    p->pmlfc_params = NULL;
    return (union pml_tree *)p;
  } break;

  case PMLTT_STMTLIST: {
    struct pml_stmtlist *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlsl_type = pmltt;
    l_init(&p->pmlsl_stmts);
    return (union pml_tree *)p;
  } break;

  case PMLTT_IF: {
    struct pml_if *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlif_type = pmltt;
    p->pmlif_test = NULL;
    p->pmlif_tbody = NULL;
    p->pmlif_fbody = NULL;
    return (union pml_tree *)p;
  } break;

  case PMLTT_WHILE: {
    struct pml_while *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlw_type = pmltt;
    p->pmlw_test = NULL;
    p->pmlw_body = NULL;
    return (union pml_tree *)p;
  } break;

  case PMLTT_PKTACT: {
    struct pml_pkt_action *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlpa_type = pmltt;
    p->pmlpa_action = 0;
    p->pmlpa_pkt = NULL;
    p->pmlpa_name = NULL;
    p->pmlpa_off = NULL;
    p->pmlpa_amount = NULL;
    return (union pml_tree *)p;
  } break;

  case PMLTT_SETACT: {
    struct pml_set_action *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlsa_type = pmltt;
    p->pmlsa_conv = 0;
    p->pmlsa_vname = NULL;
    p->pmlsa_off = NULL;
    p->pmlsa_len = NULL;
    p->pmlsa_newval = NULL;
    return (union pml_tree *)p;
  } break;

  case PMLTT_FUNCTION: {
    struct pml_function *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlf_type = pmltt;
    p->pmlf_name = NULL;
    l_init(&p->pmlf_pnames);
    p->pmlf_ns.pmlns_parent = NULL;
    p->pmlf_ns.pmlns_vars = NULL;   /* TODO */
    p->pmlf_ns.pmlns_funcs = NULL;  /* TODO */
    return (union pml_tree *)p;
  } break;

  case PMLTT_PRINT: {
    struct pml_print *p;
    if ( (p = calloc(1, sizeof(*p))) == NULL )
      return NULL;
    p->pmlp_type = pmltt;
    p->pmlp_fmt = NULL;
    p->pmlp_params = NULL;
    return (union pml_tree *)p;
  } break;

  default:
    return NULL;
  }
}


void pmlt_free(union pml_tree *tree)
{
}
