/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * fld.h -- convenience get/set operations on packet fields
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

/* returns 1 if the 'idx'th 'pf' field exists in plist and 0 otherwise */
int fld_exists(struct prparse *plist, struct ns_pktfld *pf, uint idx);


/* return the 'idx'th 'ns' parse in 'plist' */
struct prparse *fld_getprpi(struct prparse *plist, struct ns_namespace *ns,
			    uint idx);

/* as per fld_getprpi() but look up the protocol by name */
struct prparse *fld_getprpni(struct prparse *plist, const char *s, uint idx);

/* as per fld_getprpi() but idx = 0 */
struct prparse *fld_getprp(struct prparse *plist, struct ns_namespace *ns);

/* as per fld_getprpni() but idx = 0 */
struct prparse *fld_getprpn(struct prparse *plist, const char *s);

/*
 * return a pointer to the header of the 'idx'th 'pf' parse 
 * in buffer 'p' with parse 'plist'.  Return NULL if one doesn't exist.
 * If one does exist, return the header length in 'len'
 */
void *fld_gethdri(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		  uint idx, ulong *len);

/*
 * return a pointer to the payload of the 'idx'th 'pf' parse 
 * in buffer 'p' with parse 'plist'.  Return NULL if one doesn't exist.
 * If one does exist, return the header length in 'len'
 */
void *fld_getpldi(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		  uint idx, ulong *len);

/*
 * return a pointer to the trailer of the 'idx'th 'pf' parse 
 * in buffer 'p' with parse 'plist'.  Return NULL if one doesn't exist.
 * If one does exist, return the header length in 'len'
 */
void *fld_gettrli(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		  uint idx, ulong *len);


/* as fld_gethdri() but look up protocol by name */
void *fld_gethdrni(byte_t *p, struct prparse *plist, const char *s,
		   uint idx, ulong *len);

/* as fld_getpldi() but look up protocol by name */
void *fld_getpldni(byte_t *p, struct prparse *plist, const char *s,
		   uint idx, ulong *len);

/* as fld_gettrli() but look up protocol by name */
void *fld_gettrlni(byte_t *p, struct prparse *plist, const char *s,
		   uint idx, ulong *len);

/* as fld_gethdri() but with idx = 0 */
void *fld_gethdr(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		 ulong *len);

/* as fld_getpldi() but with idx = 0 */
void *fld_getpld(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		 ulong *len);

/* as fld_gettrli() but with idx = 0 */
void *fld_gettrl(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		 ulong *len);


/* as fld_gethdrni() but with idx = 0 */
void *fld_gethdrn(byte_t *p, struct prparse *plist, const char *s,
		  ulong *len);

/* as fld_getpldni() but with idx = 0 */
void *fld_getpldn(byte_t *p, struct prparse *plist, const char *s,
		   ulong *len);

/* as fld_gettrlni() but with idx = 0 */
void *fld_gettrln(byte_t *p, struct prparse *plist, const char *s,
		  ulong *len);


/*
 * returns a pointer to the 'idx'th 'pf' field in 'p' parsed by 'plist' 
 * and the length if not NULL.  If there is an error or the field
 * does not exist, then it returns NULL.
 */
void *fld_getpi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
		uint idx, ulong *len);


/*
 * read the value of the 'idx'th 'pf' field in a packet with
 * data at 'p' and a parse of 'plist' into a ulong ('v')
 * returns 0 on success and -1 on failure
 */
int fld_getvi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	      uint idx, ulong *v);
/*
 * read the value of the 'idx'th 'pf' field in a packet with
 * data at 'p' and a parse of 'plist' into a byte array 'dp' of length 'len.
 * returns 0 on success and -1 on failure
 */
int fld_getbi(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	      uint idx, void *dp, size_t len);

/*
 * set the value of the 'idx'th 'pf' field in a packet with
 * data at 'dp' and a parse of 'plist' to the value 'v'.
 * returns 0 on success and -1 on failure
 */
int fld_setvi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	      uint idx, ulong v);

/*
 * set the value of the 'idx'th 'pf' field in a packet with
 * data at 'dp' and a parse of 'plist' to the 'len' bytes in 'sp'.
 * returns 0 on success and -1 on failure
 */
int fld_setbi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	      uint idx, void *sp, size_t len);


/* as fld_getvi(), but the field is looked up by name */
int fld_getvni(byte_t *p, struct prparse *plist, const char *s, uint idx,
	       ulong *v);

/* as fld_getbi(), but the field is looked up by name */
int fld_getbni(byte_t *sp, struct prparse *plist, const char *s, uint idx,
	       void *dp, size_t len);

/* as fld_setvi(), but the field is looked up by name */
int fld_setvni(byte_t *p, struct prparse *plist, const char *s, uint idx,
	       ulong v);

/* as fld_setbi(), but the field is looked up by name */
int fld_setbni(byte_t *dp, struct prparse *plist, const char *s, uint idx,
	       void *sp, size_t len);


/* as fld_getvi(), but index is implicitly 0 */
int fld_getv(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	     ulong *v);

/* as fld_getbi(), but index is implicitly 0 */
int fld_getb(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	     void *dp, size_t len);

/* as fld_setvi(), but index is implicitly 0 */
int fld_setv(byte_t *p, struct prparse *list, struct ns_pktfld *pf,
	     ulong v);

/* as fld_setbi(), but index is implicitly 0 */
int fld_setb(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	     void *sp, size_t len);


/* as fld_getnvi, but index is implicitly 0 */
int fld_getvn(byte_t *p, struct prparse *plist, const char *s, ulong *v);

/* as fld_getnbi, but index is implicitly 0 */
int fld_getbn(byte_t *sp, struct prparse *plist, const char *s,
	      void *dp, size_t len);

/* as fld_setnvi, but index is implicitly 0 */
int fld_setvn(byte_t *p, struct prparse *plist, const char *s, ulong v);

/* as fld_setnbi, but index is implicitly 0 */
int fld_setbn(byte_t *dp, struct prparse *plist, const char *s,
	      void *sp, size_t len);

#endif /* __fld_h */
