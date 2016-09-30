/*
 * ONICS
 * Copyright 2013-2015
 * Christopher Adam Telfer
 *
 * ipfrag.c -- Fragment packets according to a given MTU.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cat/optparse.h>
#include <cat/pack.h>
#include <cat/err.h>
#include "pktbuf.h"
#include "ns.h"
#include "stdproto.h"
#include "prload.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"

#define MIN_IPV4_MTU	68
#define MIN_IPV6_MTU	1280

enum {
	PASS = 0,
	FRAG = 1,
	DROP = 2,
};

struct clopt options[] = {
	CLOPT_I_STRING('a', NULL, "DFACTION",
		       "Action to take when frag not allowed."),
	CLOPT_I_NOARG('d', NULL, "Set the DF bit on new fragments."),
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_UINT('i', NULL, "ID",
		     "Assign IP IDs to new fragments starting with ID"),
	CLOPT_I_UINT('m', NULL, "MTU", "Set the max IP/IPv6 MTU."),
	CLOPT_I_NOARG('4', NULL, "Fragment IPv4 packets (default)"),
	CLOPT_I_NOARG('6', NULL, "Fragment IPv6 packets"),
};
struct clopt_parser oparse =
CLOPTPARSER_INIT(options, array_length(options));

const char *progname;
FILE *infile;
FILE *outfile;
int frag4 = 0;
int frag6 = 0;
int dfact = DROP;
uint dfbit = 0;
ulong mtu = 1500;
ulong nextid = 1;
int setid = 0;


void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] [INFILE [OUTFILE]]\n", progname);
	fprintf(stderr, "Options:\n%s\n", str);
	fprintf(stderr, "\tIf neither '-4' nor '-6' are specified, then\n");
	fprintf(stderr, "\tthe program defaults to '-4'.  The arguments\n");
	fprintf(stderr, "\tcan specify both '-4' and '-6'\n\n");
	fprintf(stderr, "\tDFACT is the action taken when:\n");
	fprintf(stderr, "\t\t- an IPv4 datagram must be fragmented "
			"but the DF bit is set\n");
	fprintf(stderr, "\t\t- an IPv6 datagram must be fragmented "
			"but it already has a fragmentation header\n");
	fprintf(stderr, "\tDFACT must be one of 'pass', 'frag' or 'drop'\n");
	fprintf(stderr, "\tIf DFACT is 'frag' is treated as 'drop' when\n");
	fprintf(stderr, "\tthe packet is an IPv6 fragment requiring further");
	fprintf(stderr, "\tfragmentation.\n");
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;
	const char *fn;

	infile = stdin;
	outfile = stdout;
	progname = argv[0];

	optparse_reset(&oparse, argc, argv);
	while (!(rv = optparse_next(&oparse, &opt))) {
		switch (opt->ch) {
		case 'a':
			if (strcmp(opt->val.str_val, "pass"))
				dfact = PASS;
			else if (strcmp(opt->val.str_val, "frag"))
				dfact = FRAG;
			else if (strcmp(opt->val.str_val, "drop"))
				dfact = DROP;
			else
				usage("Invalid DF action");
			break;
		case 'd':
			dfbit = IPH_DFMASK;
			break;
		case 'h':
			usage(NULL);
			break;
		case 'i':
			setid = 1;
			nextid = opt->val.uint_val;
			break;
		case 'm':
			mtu = opt->val.uint_val;
			break;
		case '4':
			frag4 = 1;
			break;
		case '6':
			frag6 = 1;
			break;
		}
	}
	if (rv < 0)
		usage(oparse.errbuf);

	if (frag4 == 0 && frag6 == 0)
		frag4 = 1;

	if (frag4 && mtu < MIN_IPV4_MTU)
		err("MTU %lu too small for IPv4 fragmentation.\n", mtu);
	if (frag6 && mtu < MIN_IPV6_MTU)
		err("MTU %lu too small for IPv6 fragmentation.\n", mtu);

	if (rv < argc) {
		fn = argv[rv++];
		infile = fopen(fn, "r");
		if (infile == NULL)
			errsys("Error opening file %s: ", fn);
	}

	if (rv < argc) {
		fn = argv[rv++];
		outfile = fopen(fn, "w");
		if (outfile == NULL)
			errsys("Error opening file %s: ", fn);
	}
}


static int frag_action(struct pktbuf *p)
{
	struct prparse *prp;
	struct ipv4h *ip;

	prp = p->layers[PKB_LAYER_NET];
	if (prp == NULL) {
		return PASS;
	} else if (prp->prid == PRID_IPV4 && frag4) {
		if (prp->error != 0 || prp_totlen(prp) <= mtu)
			return PASS;
		ip = prp_header(prp, p->buf, struct ipv4h);
		if (ntoh16(ip->fragoff) & IPH_DFMASK)
			return dfact;
		else
			return FRAG;
	} else if (prp->prid == PRID_IPV6 && frag6) {
		/* IPv6 always has a "Don't fragment" bit implied. */
		/* so if frag6 is non-zero we assume we should fragment. */
		if (prp->error != 0 || prp_totlen(prp) <= mtu)
			return PASS;
		else if (prp_off_valid(prp, PRP_IPV6FLD_FRAGH) || 
			 prp_off_valid(prp, PRP_IPV6FLD_AHH))
			return DROP;
		else
			return FRAG;
	} else {
		return 0;
	}
}


static void copy_send_firstn(struct pktbuf *p, ulong plen)
{
	struct pktbuf *p2;
	p2 = pkb_create(plen);
	if (p2 == NULL)
		errsys("error allocating packet buffer: ");
	pkb_set_dltype(p2, pkb_get_dltype(p));
	pkb_set_len(p2, plen);
	memcpy(pkb_data(p2), pkb_data(p), plen);
	pkb_pack(p2);
	if (pkb_file_write(p2, outfile) < 0)
		errsys("pkb_file_write(): ");
}


static int copy_v4_options(byte_t *in, byte_t *out, uint len)
{
	byte_t *op = out;
	int c;
	int l;

	abort_unless(len <= 40);
	while (len > 0) {
		c = IPOPT_CODE(in);
		if (c == IPOPT_EOP) {
			break;
		} else if (c == IPOPT_NOP) {
			l = 1;
		} else {
			if (len < 2)
				return -1;
			l = in[1];
		}
		if (l > len)
			return -1;

		if (IPOPT_COPY(in)) {
			memcpy(op, in, l);
			op += l;
		}
		in += l;
		len -= l;
	}

	return op - out;
}


static int fragment_v4(struct pktbuf *p)
{
	struct prparse *prp = p->layers[PKB_LAYER_NET];
	struct ipv4h *ip = prp_header(prp, p->buf, struct ipv4h);
	byte_t newhdr[60];
	int ohlen = prp_hlen(prp);
	int nhlen;
	ulong nb;		/* number of 8-byte blocks */
	ulong plen;		/* packet length */
	uint16_t foff;		/* next fragment offset */

	abort_unless(ohlen <= 60);
	abort_unless(prp_totlen(prp) > mtu);

	foff = ntoh16(ip->fragoff);

	/* First, assign the IP ID to assign to the packet if needed */
	if (setid && (foff & (IPH_MFMASK | IPH_FRAGOFFMASK)) == 0) {
		ip->id = hton16(nextid);
		++nextid;
	}

	/* 
	 * Next we need to generate the new header copying the
	 * necessary options from the old header.  It may be shorter.
	 */
	memcpy(newhdr, ip, 20);
	nhlen = copy_v4_options((byte_t *)ip, newhdr, ohlen - 20);
	if (nhlen < 0)
		return -1;
	nhlen += 20;
	
	/* 
	 * Next generate first fragment:  original header plus 
	 * (MTU - old_hdr_len) / 8 bytes of data.
	 */
	/* Check that fragment won't overflow. */
	if (IPH_FRAGOFF(foff) + prp_totlen(prp) > 65535)
		return -1;

	nb = (mtu - ohlen) / 8;
	ip->fragoff = hton16(foff | IPH_MFMASK | dfbit);
	ip->len = hton16(nb * 8 + ohlen);
	prp_fix_cksum(prp, p->buf);

	/* now copy out the old header plus the data to a new packet and send */
	plen = nb * 8 + ohlen + prp_soff(prp) - pkb_get_off(p);
	copy_send_firstn(p, plen);

	/*
	 * Prepare the main packet buffer by copying in the new header and then
	 * stripping the payload data we just sent.  Cut nb * 8 + the
	 * difference in header sizes starting just past the new header.  Shift
	 * up since the L2 headers are likely to be shorter than the payload.
	 */
	memcpy(prp_header(prp, p->buf, void), newhdr, nhlen);
	prp_cut(prp, p->buf, nhlen, ohlen - nhlen + nb * 8, 1);
	foff += nb;

	/* 
	 * Now enter a loop to generate the middle fragments.  This is
	 * simpler because the IP header mostly stays the same.  Only
	 * the fragment offset will change. 
	 */
	ip = prp_header(prp, p->buf, struct ipv4h);
	nb = (mtu - nhlen) / 8;
	ip->len = hton16(nhlen + nb * 8);
	while (prp_totlen(prp) > mtu) {
		ip->fragoff = hton16(foff | IPH_MFMASK | dfbit);
		prp_fix_cksum(prp, p->buf);
		plen = nb * 8 + nhlen + prp_soff(prp) - pkb_get_off(p);
		copy_send_firstn(p, plen);
		prp_cut(prp, p->buf, nhlen, nb * 8, 1);
		foff += nb;
		ip = prp_header(prp, p->buf, struct ipv4h);
	}

	/* now what is left is just the last fragment */
	ip->fragoff = hton16(foff | dfbit);
	ip->len = hton16(nhlen + prp_plen(prp));
	prp_fix_cksum(prp, p->buf);
	pkb_pack(p);
	if (pkb_file_write(p, outfile) < 0)
		errsys("pkb_file_write(): ");

	return 0;
}


static ulong find_v6_fragoff(struct pktbuf *p, uint8_t *nxth, uint8_t **fhp)
{
	struct prparse *prp = p->layers[PKB_LAYER_NET];
	struct ipv6h *ip6;
	byte_t *o;
	/* 
	 * see RFC2460. If route header is present, fragment after it.
	 * Else if hop-by-hop options present, fragment after it.  Else
	 * fragment after the base header.
	 */
	if (prp_off_valid(prp, PRP_IPV6FLD_RTOPT)) {
		o = p->buf + prp->offs[PRP_IPV6FLD_RTOPT];
		*nxth = o[0];
		*fhp = o;
		return o[1] * 8 + 8 + 
		       prp->offs[PRP_IPV6FLD_FRAGH] - prp_soff(prp);
	} else if (prp_off_valid(prp, PRP_IPV6FLD_HOPOPT)) {
		o = p->buf + prp->offs[PRP_IPV6FLD_HOPOPT];
		*nxth = o[0];
		*fhp = o;
		return o[1] * 8 + 8 +
		       prp->offs[PRP_IPV6FLD_HOPOPT] - prp_soff(prp);
	} else {
		ip6 = prp_header(prp, p->buf, struct ipv6h);
		*nxth = ip6->nxthdr;
		*fhp = &ip6->nxthdr;
		return 40;
	}
}


static int fragment_v6(struct pktbuf *p)
{
	struct prparse *prp = p->layers[PKB_LAYER_NET];
	struct ipv6h *ip6;
	struct ipv6_fragh *fh;
	ulong id;	/* the fragment ID */
	ulong nb;	/* number of bytes in this frag: not 8-byte blocks */
	ulong fho;	/* packet offset to start of frag header */
	ulong hl;	/* length from start of l2 header to end of frag hdr */
	ulong xhl;	/* length of the v6 ext hdrs through the frag hdr */
	uint8_t nxth;	/* ID of the hdr that will follow the frag hdr */
	uint8_t *fhp;	/* ptr to nxthdr byte to redirect to the frag hdr */
	uint16_t foff = 0;	/* current fragment offset */

	id = nextid++;

	/* 
	 * Start by finding where the fragment header will go.  We need
	 * the packet offset, the length of data from l2 through the
	 * end of said header and the length of the extension headers
	 * through said fragment header. 
	 */
	fho = find_v6_fragoff(p, &nxth, &fhp);
	hl = fho + 8 + prp_soff(prp)- pkb_get_off(p);
	xhl =  fho - 32; /* fho + 8 - 40 */

	/* make sure the MTU is big enough for the various headers */
	/* it really ought to be */
	if (mtu < xhl + 40)
		return -1;

	/* insert 8 bytes for the fragment header */
	*fhp = IPPROT_V6_FRAG_HDR;
	prp_insert(prp, p->buf, fho, 8, 0); 
	prp->offs[PRP_IPV6FLD_FRAGH] = prp_soff(prp) + fho;

	/* build the fragment header for the first fragment */
	fh = (struct ipv6_fragh *)(p->buf + prp->offs[PRP_IPV6FLD_FRAGH]);
	nb = (mtu - xhl - 40) / 8 * 8;
	fh->nxthdr = nxth;
	fh->resv = 0;
	fh->fragoff = hton16(IPV6_FRAGH_MFMASK);
	fh->id = hton32(id);

	/* now we set the payload length correctly in the IPv6 header */
	ip6 = prp_header(prp, p->buf, struct ipv6h);
	ip6->len = hton16(nb + xhl);

	/* we are now set up to copy in the first frag a new buffer and send */
	copy_send_firstn(p, nb + hl);

	/* now cut out the payload bytes we just sent and adjust offsets */
	prp_cut(prp, p->buf, xhl + 40, nb, 1);
	foff += nb;

	/*
	 * Now enter a loop and generate the middle fragments.
	 * Length will remain the same throughout.
	 */
	ip6 = prp_header(prp, p->buf, struct ipv6h);
	fh = (struct ipv6_fragh *)(p->buf + prp->offs[PRP_IPV6FLD_FRAGH]);
	nb = (mtu - xhl - 40) / 8 * 8;
	ip6->len = hton16(nb + xhl);
	while (prp_totlen(prp) > mtu) {
		fh->fragoff = hton16(foff | IPV6_FRAGH_MFMASK);
		copy_send_firstn(p, nb + hl);
		prp_cut(prp, p->buf, xhl + 40, nb, 1);
		foff += nb;
		fh = (struct ipv6_fragh *)(p->buf + prp->offs[PRP_IPV6FLD_FRAGH]);
	}

	/* Finally we just send what is left as the last fragment */
	ip6 = prp_header(prp, p->buf, struct ipv6h);
	ip6->len = hton16(prp_totlen(prp) - 40);
	fh->fragoff = hton16(foff);
	pkb_pack(p);
	if (pkb_file_write(p, outfile) < 0)
		errsys("pkb_file_write(): ");

	return 0;
}


static int fragment(struct pktbuf *p)
{
	if (p->layers[PKB_LAYER_NET]->prid == PRID_IPV4) {
		return fragment_v4(p);
	} else {
		abort_unless(p->layers[PKB_LAYER_NET]->prid == PRID_IPV6);
		return fragment_v6(p);
	}
}


int main(int argc, char *argv[])
{
	int rv;
	int action;
	struct pktbuf *p;
	ulong pn = 0;

	pkb_init_pools(32);
	register_std_proto();
	load_external_protocols();
	parse_args(argc, argv);

	while ((rv = pkb_file_read_a(&p, infile, NULL, NULL)) > 0) {
		++pn;
		if (pkb_parse(p) < 0)
			err("Error parsing packet %lu\n", pn);

		action = frag_action(p);
		if (action == PASS) {
			pkb_pack(p);
			if (pkb_file_write(p, outfile) < 0)
				errsys("pkb_file_write(): ");
		} else if (action == FRAG) {
			if (fragment(p) < 0)
				pkb_free(p);
		} else {
			abort_unless(action == DROP);
			pkb_free(p);
		}
	}
	if (rv < 0)
		errsys("pkb_file_read_a(): ");

	return 0;
}
