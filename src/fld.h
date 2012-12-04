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

/*
 * read the value of the 'idx'th 'pf' field in a packet with
 * data at 'p' and a parse of 'plist' into a uint64_t ('v')
 * returns 0 on success and -1 on failure
 */
int fld_getvi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	      uint idx, uint64_t *v);
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
	      uint idx, uint64_t v);

/*
 * set the value of the 'idx'th 'pf' field in a packet with
 * data at 'dp' and a parse of 'plist' to the 'len' bytes in 'sp'.
 * returns 0 on success and -1 on failure
 */
int fld_setbi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	      uint idx, void *sp, size_t len);


/* as fld_getvi(), but the field is looked up by name */
int fld_getnvi(byte_t *p, struct prparse *plist, const char *s, uint idx,
	       uint64_t *v);

/* as fld_getbi(), but the field is looked up by name */
int fld_getnbi(byte_t *sp, struct prparse *plist, const char *s, uint idx,
	       void *dp, size_t len);

/* as fld_setvi(), but the field is looked up by name */
int fld_setnvi(byte_t *p, struct prparse *plist, const char *s, uint idx,
	        uint64_t v);

/* as fld_setbi(), but the field is looked up by name */
int fld_setnbi(byte_t *dp, struct prparse *plist, const char *s, uint idx,
	        void *sp, size_t len);


/* as fld_getvi(), but index is implicitly 0 */
int fld_getv(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	     uint64_t *v);

/* as fld_getbi(), but index is implicitly 0 */
int fld_getb(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	     void *dp, size_t len);

/* as fld_setvi(), but index is implicitly 0 */
int fld_setv(byte_t *p, struct prparse *list, struct ns_pktfld *pf,
	     uint64_t v);

/* as fld_setbi(), but index is implicitly 0 */
int fld_setb(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	     void *sp, size_t len);


/* as fld_getnvi, but index is implicitly 0 */
int fld_getnv(byte_t *p, struct prparse *plist, const char *s, uint64_t *v);

/* as fld_getnbi, but index is implicitly 0 */
int fld_getnb(byte_t *sp, struct prparse *plist, const char *s,
	      void *dp, size_t len);

/* as fld_setnvi, but index is implicitly 0 */
int fld_setnv(byte_t *p, struct prparse *plist, const char *s, uint64_t v);

/* as fld_setnbi, but index is implicitly 0 */
int fld_setnb(byte_t *dp, struct prparse *plist, const char *s,
	      void *sp, size_t len);

#endif /* __fld_h */
