/*
 * ONICS
 * Copyright 2013 
 * Christopher Adam Telfer
 *
 * pdiff.c -- Compute the difference between two packet streams.
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

#include <pktbuf.h>
#include <stdlib.h>
#include <cat/err.h>
#include <cat/emalloc.h>


/* 
   lets start with the simple version first

   We're going to use damerau-levenshtein distance because packet reordering
   is definitely cheaper than packet modifications in a network.  For now, lets
   use the full NxM matrix to do the computation.  I can use a more memory
   efficient data structure when I've fully internalized the algorithm and
   its implications.
   
   The cost of a substitution is going to be proportional to the amount of 
   change in the packet.  We might differentiate in reporting the difference
   between virtually complete substitution and simple editing.

   Comparison of two packets is nuanced and we need to treat it so.  We may
   want to not treat certain packet headers (e.g. L2) or fields (e.g. ttl)
   as significant when comparing packets depending on what we are trying
   to accomplish.  How fine a granularity is appropriate?  Bit?  Byte?
   Field?  Header?
 */


struct pktarr { 
	struct pktbuf **	pkts;
	ulong			npkts;
	ulong			pasz;
};


struct dpath {
	int			action;
	ulong			cost;
};


#define dpm_elem(dpm, nc, r, c) ((dpm)[((r) * (nc) + nc)])



struct pktarr *read_pktfile(FILE *f, const char *fn)
{
	struct pktarr *pa;
	struct pktbuf *p;
	int rv;

	pa = emalloc(sizeof(*pa));
	pa->pasz = 16;
	pa->pkts = emalloc(sizeof(struct pktbuf *) * pa->pasz);

	while ((rv = pkt_file_read(&pa->pkts[pa->npkts], fp)) > 0) {
		++pa->npkts;
		if (pa->npkst == pa->pasz) {
			if (pa->pasz * 2 < pa->pasz)
				err("Size overflow\n");
			pa->pasz *= 2;
			pa->pkts = erealloc(pa->pkts, 
					    pa->pasz * sizeof(struct pktbuf *));

		}
	}

	if (rv < 0)
		errsys("Error reading packet for file %s", fn);

	return pa;
}
