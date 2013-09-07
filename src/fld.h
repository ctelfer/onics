/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * fld.h -- convenience get/set operations on packet fields referenced
 *	    by name or namespace element and protocol parse.
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __fld_h
#define __fld_h

#include <stdlib.h>
#include "protoparse.h"
#include "ns.h"


/* 
 * Return the offset of a given field in bits from the start of the packet
 * or PRP_OFF_INVALID of the offset is invalid.
 */
ulong fld_get_off(struct prparse *prp, struct ns_elem *nse);

/* 
 * Return the length of a given field in bits from the start of the packet 
 * or -1 if invalid.
 */
long fld_get_len(struct prparse *prp, struct ns_elem *nse);


/* returns 1 if the 'idx'th 'pf' field exists in plist and 0 otherwise */
int fld_exists(struct prparse *plist, struct ns_pktfld *pf, uint idx);


/* return the 'idx'th 'ns' parse in 'plist' */
struct prparse *fld_get_prpi(struct prparse *plist, struct ns_namespace *ns,
			     uint idx);

/* as per fld_get_prpi() but look up the protocol by name */
struct prparse *fld_get_prpni(struct prparse *plist, const char *s, uint idx);

/* as per fld_get_prpi() but idx = 0 */
struct prparse *fld_get_prp(struct prparse *plist, struct ns_namespace *ns);

/* as per fld_get_prpni() but idx = 0 */
struct prparse *fld_get_prpn(struct prparse *plist, const char *s);

/*
 * return a pointer to the header of the 'idx'th 'pf' parse 
 * in buffer 'p' with parse 'plist'.  Return NULL if one doesn't exist.
 * If one does exist, return the header length in 'len'
 */
void *fld_get_hdri(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		   uint idx, ulong *len);

/*
 * return a pointer to the payload of the 'idx'th 'pf' parse 
 * in buffer 'p' with parse 'plist'.  Return NULL if one doesn't exist.
 * If one does exist, return the header length in 'len'
 */
void *fld_get_pldi(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		   uint idx, ulong *len);

/*
 * return a pointer to the trailer of the 'idx'th 'pf' parse 
 * in buffer 'p' with parse 'plist'.  Return NULL if one doesn't exist.
 * If one does exist, return the header length in 'len'
 */
void *fld_get_trli(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		   uint idx, ulong *len);


/* as fld_get_hdri() but look up protocol by name */
void *fld_get_hdrni(byte_t *p, struct prparse *plist, const char *s,
		    uint idx, ulong *len);

/* as fld_get_pldi() but look up protocol by name */
void *fld_get_pldni(byte_t *p, struct prparse *plist, const char *s,
		    uint idx, ulong *len);

/* as fld_get_trli() but look up protocol by name */
void *fld_get_trlni(byte_t *p, struct prparse *plist, const char *s,
		    uint idx, ulong *len);

/* as fld_get_hdri() but with idx = 0 */
void *fld_get_hdr(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		  ulong *len);

/* as fld_getpldi() but with idx = 0 */
void *fld_get_pld(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		  ulong *len);

/* as fld_get_trli() but with idx = 0 */
void *fld_get_trl(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		  ulong *len);


/* as fld_get_hdrni() but with idx = 0 */
void *fld_get_hdrn(byte_t *p, struct prparse *plist, const char *s,
		   ulong *len);

/* as fld_get_pldni() but with idx = 0 */
void *fld_get_pldn(byte_t *p, struct prparse *plist, const char *s,
		   ulong *len);

/* as fld_get_trlni() but with idx = 0 */
void *fld_get_trln(byte_t *p, struct prparse *plist, const char *s,
		   ulong *len);


/*
 * returns a pointer to the 'idx'th 'pf' field in 'p' parsed by 'plist' 
 * and the length if not NULL.  If there is an error or the field
 * does not exist, then it returns NULL.
 */
void *fld_get_pi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
		 uint idx, ulong *len);

/* as fld_get_pi() but with idx == 0) */
void *fld_get_p(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
		ulong *len);


/*
 * read the value of the 'idx'th 'pf' field in a packet with
 * data at 'p' and a parse of 'plist' into a ulong ('v')
 * returns 0 on success and -1 on failure
 */
int fld_get_vi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	       uint idx, ulong *v);
/*
 * read the value of the 'idx'th 'pf' field in a packet with
 * data at 'p' and a parse of 'plist' into a byte array 'dp' of length 'len.
 * returns 0 on success and -1 on failure
 */
int fld_get_bi(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	       uint idx, void *dp, size_t len);

/*
 * set the value of the 'idx'th 'pf' field in a packet with
 * data at 'dp' and a parse of 'plist' to the value 'v'.
 * returns 0 on success and -1 on failure
 */
int fld_set_vi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	       uint idx, ulong v);

/*
 * set the value of the 'idx'th 'pf' field in a packet with
 * data at 'dp' and a parse of 'plist' to the 'len' bytes in 'sp'.
 * returns 0 on success and -1 on failure
 */
int fld_set_bi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	       uint idx, void *sp, size_t len);


/* as fld_get_vi(), but the field is looked up by name */
int fld_get_vni(byte_t *p, struct prparse *plist, const char *s, uint idx,
	        ulong *v);

/* as fld_get_bi(), but the field is looked up by name */
int fld_get_bni(byte_t *sp, struct prparse *plist, const char *s, uint idx,
	        void *dp, size_t len);

/* as fld_set_vi(), but the field is looked up by name */
int fld_set_vni(byte_t *p, struct prparse *plist, const char *s, uint idx,
	        ulong v);

/* as fld_set_bi(), but the field is looked up by name */
int fld_set_bni(byte_t *dp, struct prparse *plist, const char *s, uint idx,
	        void *sp, size_t len);


/* as fld_get_vi(), but index is implicitly 0 */
int fld_get_v(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	      ulong *v);

/* as fld_get_bi(), but index is implicitly 0 */
int fld_get_b(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	      void *dp, size_t len);

/* as fld_set_vi(), but index is implicitly 0 */
int fld_set_v(byte_t *p, struct prparse *list, struct ns_pktfld *pf,
	      ulong v);

/* as fld_set_bi(), but index is implicitly 0 */
int fld_set_b(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	      void *sp, size_t len);


/* as fld_getnvi, but index is implicitly 0 */
int fld_get_vn(byte_t *p, struct prparse *plist, const char *s, ulong *v);

/* as fld_getnbi, but index is implicitly 0 */
int fld_get_bn(byte_t *sp, struct prparse *plist, const char *s,
	       void *dp, size_t len);

/* as fld_set_nvi, but index is implicitly 0 */
int fld_set_vn(byte_t *p, struct prparse *plist, const char *s, ulong v);

/* as fld_setn_bi, but index is implicitly 0 */
int fld_set_bn(byte_t *dp, struct prparse *plist, const char *s,
	       void *sp, size_t len);


/* Structure for named protocol fields. */
struct npfield {
	struct list		le;
	struct prparse *	prp;
	byte_t *		buf;
	struct ns_elem *	nse;
	uint			pidx;
	ulong 			off;	/* in bits */
	ulong			len;	/* in bits */
};


struct npf_list {
	struct npfield 		list;	/* prp == NULL, nse == NULL */
	struct prparse *	plist;
	byte_t *		buf;
	uint			nfields;
	uint			ngaps;
};


#define l_to_npf(_lep)		container((_lep), struct npfield, le)
#define npf_next(npf)		l_to_npf(l_next(&(npf)->le))
#define npf_prev(npf)		l_to_npf(l_prev(&(npf)->le))
#define npfl_first(npfl)	l_to_npf(l_head(&(npfl)->list.le))
#define npfl_last(npfl)		l_to_npf(l_tail(&(npfl)->list.le))
#define npfl_isempty(npfl)	l_isempty(&(npfl)->list.le)
#define npfl_get_len(npfl)	((npfl)->nfields)
#define npf_is_end(npf)		((npf)->len == (ulong)-1l)
#define npf_is_nonfld(npf)	((npf)->nse == NULL)
#define npf_is_gap(npf)		((npf)->nse == NULL && (npf)->buf != NULL)
#define npf_is_prp(npf)		((npf)->nse == NULL && (npf)->buf == NULL)
#define npf_type_eq(n1, n2)	(((n1)->nse == (n2)->nse) && \
				 (n1)->prp->prid == (n2)->prp->prid)

/* returns 1 if the field should be filtered out and 0 otherwise */
typedef int (*npfl_filter_f)(struct ns_elem *e);

/* initialize a named protocol field list for a given parse and buffer */
void npfl_init(struct npf_list *npfl, struct prparse *plist, byte_t *buf);

/* Initialize a named protocol field list from a parse */
int npfl_load(struct npf_list *npfl, struct prparse *prp, int fill,
	      npfl_filter_f filter);

/* free the elements of a named protcol field list */
void npfl_clear(struct npf_list *npfl);

/* cache the elements of a named protcol field list */
void npfl_cache(struct npf_list *npfl);

/* release the elements in the field list cache */
void npfl_clear_cache(struct npf_list *npfl);

/* return 1 if the two fields are essentially equal and 0 otherwise */
int npf_eq(struct npfield *npf1, struct npfield *npf2);

#endif /* __fld_h */
