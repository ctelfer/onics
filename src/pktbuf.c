/*
 * ONICS
 * Copyright 2012-2022
 * Christopher Adam Telfer
 *
 * pktbuf.c -- Library for managing ONICS packet buffers.
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
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <cat/pcache.h>
#include <cat/io.h>
#include "prid.h"
#include "pktbuf.h"
#include "ns.h"

const size_t pkb_xpkt_pool_size = 1024 - sizeof(cat_pcpad_t);
#define PKB_MAX_DATA_LEN  (65536 + 2048 - sizeof(cat_pcpad_t))
const size_t pkb_data_pool_sizes[] = {
	2048 - sizeof(cat_pcpad_t),
	16384 - sizeof(cat_pcpad_t),
	PKB_MAX_DATA_LEN,
};
const uint pkb_num_data_pools = array_length(pkb_data_pool_sizes);


struct pcache pkb_buf_pool;
struct pcache pkb_xpkt_pool;
struct pcache pkb_data_pools[array_length(pkb_data_pool_sizes)];

#define SET_LAYER_AUTO		-1
#define SET_LAYER_FORCE		-2

#define DLT_NONE_PAD		0
#define DLT_ETHERNET2_PAD	2

int dloffs[PRID_PROTO(PRID_DLT_MAX)+1] = {
	DLT_NONE_PAD,
	DLT_ETHERNET2_PAD,
};

/* Returns the pad offset for this DL type -- usually 0-3 */
/* ONLY call with a valid dltype or it will abort. */
static int dlt_offset(uint16_t prid)
{
	if ((PRID_FAMILY(prid) == PRID_PF_DLT) && (prid >= PRID_DLT_MIN) &&
	    (prid <= PRID_DLT_MAX))
		return dloffs[PRID_PROTO(prid)];
	return 0;
}


void pkb_init_pools(uint num_buf_expected)
{
	int i;
	pc_init(&pkb_buf_pool, sizeof(struct pktbuf), 65536,
		num_buf_expected, 0, &stdmm);
	pc_init(&pkb_xpkt_pool, pkb_xpkt_pool_size, pkb_xpkt_pool_size * 32,
		num_buf_expected, 0, &stdmm);
	for (i = 0; i < pkb_num_data_pools; ++i) {
		pc_init(&pkb_data_pools[i], pkb_data_pool_sizes[i],
			pkb_data_pool_sizes[i] * 32,
			num_buf_expected, 0, &stdmm);
	}
}


void pkb_free_pools(void)
{
	int i;
	pc_freeall(&pkb_buf_pool);
	pc_freeall(&pkb_xpkt_pool);
	for (i = 0; i < pkb_num_data_pools; ++i)
		pc_freeall(&pkb_data_pools[i]);
}


void pkb_init(struct pktbuf *pkb, void *buf, ulong bsize, void *xbuf,
	      ulong xbsize)
{
	abort_unless(pkb != NULL);
	abort_unless(buf != NULL);
	abort_unless(xbuf != NULL);
	abort_unless(xbsize >= XPKT_HLEN);

	pkb->free = NULL;
	pkb->buf = buf;
	pkb->bufsize = bsize;
	pkb->xpkt = xbuf;
	pkb->xsize = xbsize;
	pkb->flags = 0;
	pkb_reset(pkb);
}


static void pkb_free_buf(void *ctx, struct pktbuf *pkb)
{
	(void)ctx;	/* unused */
	pdu_clear(&pkb->pdus);
	pc_free(pkb->xpkt);
	pc_free(pkb->buf);
	pc_free(pkb);
}


struct pktbuf *pkb_create(ulong bufsize)
{
	struct pktbuf *pkb;
	void *xmp, *dp;
	int pl;

	for (pl = 0; pl < pkb_num_data_pools; ++pl)
		if (bufsize <= pkb_data_pool_sizes[pl])
			break;
	if (pl >= pkb_num_data_pools) {
		errno = ENOMEM;
		return NULL;
	}

	if (!(pkb = pc_alloc(&pkb_buf_pool))) {
		errno = ENOMEM;
		return NULL;
	}
	if (!(xmp = pc_alloc(&pkb_xpkt_pool))) {
		pc_free(pkb);
		errno = ENOMEM;
		return NULL;
	}
	if (!(dp = pc_alloc(&pkb_data_pools[pl]))) {
		pc_free(pkb);
		pc_free(xmp);
		errno = ENOMEM;
		return NULL;
	}

	l_init(&pkb->entry);
	pkb->free = &pkb_free_buf;
	pkb->fctx = NULL;
	pkb->buf = dp;
	pkb->bufsize = bufsize;
	pkb->xpkt = xmp;
	pkb->xsize = pkb_xpkt_pool_size;
	pkb_reset(pkb);

	return pkb;
}


static struct pktbuf *pkb_alloc_default(void *ctx, size_t xlen, size_t plen)
{
	if (xlen > pkb_xpkt_pool_size) {
		errno = ENOMEM;
		return NULL;
	}
	return pkb_create(plen);
}


static void reset_layers(struct pktbuf *pkb)
{
	int i;
	for (i = 0; i < PKB_LAYER_NUM; ++i)
		pkb->layers[i] = NULL;
}


void pkb_reset(struct pktbuf *pkb)
{
	struct xpkthdr *xh;

	abort_unless(pkb);

	pkb->xhlen = 0;
	pkb->flags &= PKB_F_RESET_MASK;

	pdu_init_root(&pkb->pdus, pkb->bufsize);
	reset_layers(pkb);

	xh = &pkb->xpkt->hdr;
	xh->len = XPKT_HLEN;
	xh->dltype = PRID_INVALID;
	xh->tlen = 0;
}


struct pktbuf *pkb_copy(struct pktbuf *opkb)
{
	struct pktbuf *npkb;
	int errval;
	struct pdu *nt, *ot, *layer;
	int i;

	if (!(npkb = pkb_create(opkb->bufsize)))
		return NULL;
	if (pdu_copy(&npkb->pdus, &opkb->pdus) < 0) {
		errval = errno;
		pkb_free(npkb);
		errno = errval;
		return NULL;
	}

	/* from here on we are safe */
	memcpy(npkb->buf + pdu_poff(&npkb->pdus),
	       opkb->buf + pdu_poff(&opkb->pdus), pdu_plen(&opkb->pdus));

	if ((opkb->flags & PKB_F_PACKED)) {
		memcpy(npkb->xpkt, opkb->xpkt, opkb->xhlen);
	} else {
		memcpy(npkb->xpkt, opkb->xpkt, xpkt_doff(opkb->xpkt));
	}

	/* Set the layers in the new packet buffer */
	for (i = 0; i < PKB_LAYER_NUM; ++i) {
		if (!(layer = opkb->layers[i]))
			continue;
		ot = pdu_next(&opkb->pdus);
		nt = pdu_next(&npkb->pdus);
		while (!pdu_list_end(ot) && (ot != layer)) {
			ot = pdu_next(ot);
			nt = pdu_next(nt);
		}
		abort_unless(!pdu_list_end(ot));
		npkb->layers[i] = nt;
	}

	npkb->flags = opkb->flags;

	return npkb;
}


void pkb_free(struct pktbuf *pkb)
{
	if (pkb != NULL && pkb->free != NULL)
		(*pkb->free)(pkb->fctx, pkb);
}


ulong pkb_get_off(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return pdu_poff(&pkb->pdus);
}


ulong pkb_get_len(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return pdu_plen(&pkb->pdus);
}


ulong pkb_get_bufsize(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return pdu_eoff(&pkb->pdus);
}


uint16_t pkb_get_dltype(struct pktbuf *pkb)
{
	abort_unless(pkb && pkb->xpkt);
	abort_unless((pkb->flags & PKB_F_PACKED) == 0);
	return pkb->xpkt->hdr.dltype;
}


void pkb_set_off(struct pktbuf *pkb, ulong off)
{
	ulong len;

	abort_unless(!pkb_is_parsed(pkb));

	len = pdu_plen(&pkb->pdus);

	/* check for overflow/underflow:  integer then buffer */
	abort_unless(len + off >= off);
	abort_unless(len + off <= pdu_totlen(&pkb->pdus));

	pdu_poff(&pkb->pdus) = off;
	pdu_toff(&pkb->pdus) = off + len;
}


void pkb_set_len(struct pktbuf *pkb, ulong len)
{
	ulong off;

	abort_unless(!pkb_is_parsed(pkb));

	off = pdu_poff(&pkb->pdus);

	/* check for overflow/underflow:  integer then buffer */
	abort_unless(off + len >= len);
	abort_unless(off + len <= pdu_totlen(&pkb->pdus));

	pdu_toff(&pkb->pdus) = off + len;
}


void pkb_set_dltype(struct pktbuf *pkb, uint16_t dltype)
{
	abort_unless(pkb && pkb->xpkt);
	abort_unless((pkb->flags & PKB_F_PACKED) == 0);
	pkb->xpkt->hdr.dltype = dltype;
}


void *pkb_data(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return pkb->buf + pdu_poff(&pkb->pdus);
}


#define HPADMIN		192
#define TPADMIN		192

static int pkb_read_finish(struct pktbuf *pkb, size_t doff, size_t dlen)
{
	struct xpkt *x;

	abort_unless(pkb);

	x = pkb->xpkt;
	if (xpkt_unpack_tags(x->tags, x->hdr.tlen) < 0) {
		errno = EIO;
		return -1;
	}
	if (xpkt_validate_tags(x->tags, x->hdr.tlen) < 0) {
		errno = EIO;
		return -1;
	}

	pdu_poff(&pkb->pdus) = doff;
	pdu_toff(&pkb->pdus) = doff + dlen;

	/* In unpacked state, the hdr.len says there is no data: only tags */
	x->hdr.len = xpkt_doff(x);

	return 1;
}


int pkb_file_read(struct pktbuf *pkb, FILE *fp)
{
	struct xpkthdr *xh;
	size_t tlen;
	size_t xhlen;
	size_t doff;
	size_t dlen;
	size_t nr;

	abort_unless(fp && pkb && pkb->buf);
	abort_unless(pkb->xpkt && pkb->xsize >= XPKT_HLEN);

	xh = &pkb->xpkt->hdr;
	if ((nr = fread(xh, 1, XPKT_HLEN, fp)) < XPKT_HLEN)
		return (nr == 0) ? 0 : -1;
	xpkt_unpack_hdr(xh);
	if (xpkt_validate_hdr(xh) < 0) {
		errno = EIO;
		return -1;
	}

	tlen = xh->tlen * 4;
	xhlen = tlen + XPKT_HLEN;
	doff = dlt_offset(xh->dltype) + HPADMIN;
	dlen = xh->len - xhlen;

	if (xhlen > pkb->xsize || dlen > PKB_MAX_PKTLEN ||
	    doff + dlen + TPADMIN < dlen || /* overflow check */
	    doff + dlen + TPADMIN > pkb->bufsize) {
		errno = ENOMEM;
		return -1;
	}

	nr = fread(pkb->xpkt->tags, 1, tlen, fp);
	if (nr < tlen)
		return -1;

	nr = fread(pkb->buf + doff, 1, dlen, fp);
	if (nr < dlen)
		return -1;

	return pkb_read_finish(pkb, doff, dlen);
}


int pkb_file_read_a(struct pktbuf **pkbp, FILE *fp, pkb_alloc_f alloc,
		    void *ctx)
{
	struct xpkthdr xh;
	int errval;
	struct pktbuf *pkb;
	size_t tlen;
	size_t xhlen;
	size_t doff;
	size_t dlen;
	ssize_t nr;
	int rv = 0;

	abort_unless(fp && pkbp);

	if (alloc == NULL) {
		alloc = &pkb_alloc_default;
		ctx = NULL;
	}

	if ((nr = fread(&xh, 1, XPKT_HLEN, fp)) < XPKT_HLEN)
		return (nr == 0) ? 0 : -1;
	xpkt_unpack_hdr(&xh);
	if (xpkt_validate_hdr(&xh) < 0) {
		errno = EIO;
		return -1;
	}

	tlen = xh.tlen * 4;
	xhlen = tlen + XPKT_HLEN;
	doff = dlt_offset(xh.dltype) + HPADMIN;
	dlen = xh.len - xhlen;

	/* overflow check */
	if (dlen > PKB_MAX_PKTLEN || doff + dlen + TPADMIN < dlen) {
		errno = ENOMEM;
		return -1;
	}

	pkb = (*alloc)(ctx, xhlen, doff + dlen + TPADMIN);
	if (pkb == NULL)
		return -1;

	pkb->xpkt->hdr = xh;
	nr = fread(pkb->xpkt->tags, 1, tlen, fp);
	if (nr < tlen)
		goto err_free_pkb;

	nr = fread(pkb->buf + doff, 1, dlen, fp);
	if (nr < dlen)
		goto err_free_pkb;

	rv = pkb_read_finish(pkb, doff, dlen);
	if (rv < 0)
		goto err_free_pkb;

	*pkbp = pkb;
	return rv;

err_free_pkb:
	errval = errno;
	pkb_free(pkb);
	errno = errval;
	return -1;
}


int pkb_fd_read(struct pktbuf *pkb, int fd)
{
	struct xpkthdr *xh;
	size_t tlen;
	size_t xhlen;
	size_t doff;
	ssize_t dlen;
	ssize_t nr;

	abort_unless((fd >= 0) && pkb && pkb->buf);
	abort_unless(pkb->xpkt && pkb->xsize >= XPKT_HLEN);

	xh = &pkb->xpkt->hdr;
	if ((nr = io_read(fd, xh, XPKT_HLEN)) < XPKT_HLEN)
		return (nr == 0) ? 0 : -1;
	xpkt_unpack_hdr(xh);
	if (xpkt_validate_hdr(xh) < 0) {
		errno = EIO;
		return -1;
	}

	tlen = xh->tlen * 4;
	xhlen = tlen + XPKT_HLEN;
	doff = dlt_offset(xh->dltype) + HPADMIN;
	dlen = xh->len - xhlen;

	if (xhlen > pkb->xsize || dlen < 0 || dlen > PKB_MAX_PKTLEN ||
	    doff + dlen + TPADMIN < dlen || /* overflow check */
	    doff + dlen + TPADMIN > pkb->bufsize) {
		errno = ENOMEM;
		return -1;
	}

	nr = io_read(fd, pkb->xpkt->tags, tlen);
	if (nr < tlen)
		return -1;

	nr = io_read(fd, pkb->buf + doff, dlen);
	if (nr < dlen)
		return -1;

	return pkb_read_finish(pkb, doff, (size_t)dlen);
}


int pkb_fd_read_a(struct pktbuf **pkbp, int fd, pkb_alloc_f alloc, void *ctx)
{
	struct xpkthdr xh;
	int errval;
	struct pktbuf *pkb;
	size_t tlen;
	size_t xhlen;
	size_t doff;
	ssize_t dlen;
	ssize_t nr;
	int rv;

	abort_unless((fd >= 0) && pkbp);

	if (alloc == NULL) {
		alloc = &pkb_alloc_default;
		ctx = NULL;
	}

	if ((nr = io_read(fd, &xh, XPKT_HLEN)) < XPKT_HLEN)
		return (nr == 0) ? 0 : -1;
	xpkt_unpack_hdr(&xh);
	if (xpkt_validate_hdr(&xh) < 0) {
		errno = EIO;
		return -1;
	}

	tlen = xh.tlen * 4;
	xhlen = tlen + XPKT_HLEN;
	doff = dlt_offset(xh.dltype) + HPADMIN;
	dlen = xh.len - xhlen;

	/* overflow check */
	if (dlen < 0 || dlen > PKB_MAX_PKTLEN || doff + dlen + TPADMIN < dlen) {
		errno = ENOMEM;
		return -1;
	}

	pkb = (*alloc)(ctx, xhlen, doff + dlen + TPADMIN);
	if (pkb == NULL)
		return -1;

	pkb->xpkt->hdr = xh;
	nr = io_read(fd, pkb->xpkt->tags, tlen);
	if (nr < tlen)
		goto err_free_pkb;

	nr = io_read(fd, pkb->buf + doff, dlen);
	if (nr < dlen)
		goto err_free_pkb;

	rv = pkb_read_finish(pkb, doff, (size_t)dlen);
	if (rv < 0)
		goto err_free_pkb;

	*pkbp = pkb;
	return rv;

err_free_pkb:
	errval = errno;
	pkb_free(pkb);
	errno = errval;
	return -1;
}


int pkb_pack(struct pktbuf *pkb)
{
	struct xpkt *x;
	ulong len;

	abort_unless(pkb);

	if ((pkb->flags & PKB_F_PACKED))
		return 0;

	x = pkb->xpkt;

	/* When the buffer is packed, the xhlen caches the tag length */
	pkb->xhlen = xpkt_doff(x);

	len = pkb->xhlen + pdu_plen(&pkb->pdus);
	if (len < pkb->xhlen)
		return -1;
	if (xpkt_validate_tags(x->tags, x->hdr.tlen) < 0)
		return -2;
	x->hdr.len = len;
	xpkt_pack_tags(x->tags, x->hdr.tlen);
	xpkt_pack_hdr(&x->hdr);

	pkb->flags |= PKB_F_PACKED;

	return 0;
}


void pkb_unpack(struct pktbuf *pkb)
{
	struct xpkt *x;

	abort_unless(pkb);

	if (!(pkb->flags & PKB_F_PACKED))
		return;

	x = pkb->xpkt;
	xpkt_unpack_hdr(&x->hdr);
	xpkt_unpack_tags(x->tags, x->hdr.tlen);

	/* In unpacked state, the hdr.len says there is no data: only tags */
	x->hdr.len = x->hdr.tlen * 4 + XPKT_HLEN;

	pkb->flags &= ~PKB_F_PACKED;
}


int pkb_is_packed(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return (pkb->flags & PKB_F_PACKED) != 0;
}


int pkb_file_write(struct pktbuf *pkb, FILE *fp)
{
	size_t nw;
	long doff, dlen;

	abort_unless(fp && pkb);

	if (!(pkb->flags & PKB_F_PACKED)) {
		errno = EINVAL;
		return -1;
	}

	nw = fwrite(pkb->xpkt, 1, pkb->xhlen, fp);
	if (nw < pkb->xhlen)
		return -1;

	doff = pdu_poff(&pkb->pdus);
	dlen = pdu_plen(&pkb->pdus);
	nw = fwrite(pkb->buf + doff, 1, dlen, fp);
	if (nw < dlen)
		return -1;

	fflush(fp);

	return 0;
}


int pkb_fd_write(struct pktbuf *pkb, int fd)
{
	ssize_t nw;
	long doff, dlen;

	abort_unless((fd >= 0) && pkb);

	if (!(pkb->flags & PKB_F_PACKED)) {
		errno = EINVAL;
		return -1;
	}

	nw = io_write(fd, pkb->xpkt, pkb->xhlen);
	if (nw < pkb->xhlen)
		return -1;

	doff = pdu_poff(&pkb->pdus);
	dlen = pdu_plen(&pkb->pdus);
	nw = io_write(fd, pkb->buf + doff, dlen);
	if (nw < dlen)
		return -1;

	return 0;
}


int pkb_parse(struct pktbuf *pkb)
{
	struct pdu *pdu;
	uint prid;

	abort_unless(pkb);

	if ((pkb->flags & (PKB_F_PARSED|PKB_F_PACKED)))
		return -1;

	prid = pkb->xpkt->hdr.dltype;
	if (pdu_parse_packet(&pkb->pdus, pkb->buf, prid) < 0)
		return -1;

	for (pdu=pdu_next(&pkb->pdus); !pdu_list_end(pdu); pdu=pdu_next(pdu))
		pkb_set_layer(pkb, pdu, SET_LAYER_AUTO);

	pkb->flags |= PKB_F_PARSED;

	return 0;
}


void pkb_clear_parse(struct pktbuf *pkb)
{
	abort_unless(pkb);
	if ((pkb->flags & PKB_F_PARSED)) {
		reset_layers(pkb);
		pdu_clear(&pkb->pdus);
		pkb->flags &= ~PKB_F_PARSED;
	}
}


int pkb_is_parsed(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return (pkb->flags & PKB_F_PARSED) != 0;
}


static int islink(int prid)
{
	struct ns_namespace *ns = ns_lookup_by_prid(prid);
	return (ns && ns->pclass == PRID_PCLASS_LINK);
}


static int istunnel(int prid)
{
	struct ns_namespace *ns = ns_lookup_by_prid(prid);
	return (ns && ns->pclass == PRID_PCLASS_TUNNEL);
}


static int isnet(int prid)
{
	struct ns_namespace *ns = ns_lookup_by_prid(prid);
	return (ns && ns->pclass == PRID_PCLASS_NET);
}


static int isxport(int prid)
{
	struct ns_namespace *ns = ns_lookup_by_prid(prid);
	return (ns && ns->pclass == PRID_PCLASS_XPORT);
}


void pkb_set_layer(struct pktbuf *pkb, struct pdu *pdu, int layer)
{
	abort_unless(pkb && pdu && (layer < PKB_LAYER_NUM));
	/* XXX : should we sanity check that h in in pkt? */
	if (layer >= 0) {
		pkb->layers[layer] = pdu;
	} else {
		if (islink(pdu->prid)) {
			if (!pkb->layers[PKB_LAYER_DL] ||
			    layer == SET_LAYER_FORCE)
				pkb->layers[PKB_LAYER_DL] = pdu;
		} else if (istunnel(pdu->prid)) {
			if (!pkb->layers[PKB_LAYER_TUN] ||
			    layer == SET_LAYER_FORCE)
				pkb->layers[PKB_LAYER_TUN] = pdu;
		} else if (isnet(pdu->prid)) {
			if (!pkb->layers[PKB_LAYER_NET] ||
			    layer == SET_LAYER_FORCE)
				pkb->layers[PKB_LAYER_NET] = pdu;
		} else if (isxport(pdu->prid)) {
			if (!pkb->layers[PKB_LAYER_XPORT] ||
			    layer == SET_LAYER_FORCE)
				pkb->layers[PKB_LAYER_XPORT] = pdu;
		}
	}
}


void pkb_clr_layer(struct pktbuf *pkb, int layer)
{
	abort_unless(layer >= 0 && layer < PKB_LAYER_NUM);
	pkb->layers[layer] = NULL;
}


void pkb_fix_dltype(struct pktbuf *pkb)
{
	struct pdu *pdu;
	abort_unless((pkb->flags & PKB_F_PACKED) == 0);
	if (!pdu_empty(&pkb->pdus)) {
		pdu = pdu_next(&pkb->pdus);
		pkb->xpkt->hdr.dltype = pdu->prid;
	} else {
		pkb->xpkt->hdr.dltype = PRID_RAWPKT;
	}
}


void pkb_fix_dltype_if_parsed(struct pktbuf *pkb)
{
	struct pdu *pdu;
	abort_unless((pkb->flags & PKB_F_PACKED) == 0);
	if (!pdu_empty(&pkb->pdus)) {
		pdu = pdu_next(&pkb->pdus);
		pkb->xpkt->hdr.dltype = pdu->prid;
	}
}


int pkb_insert_pdu(struct pktbuf *pkb, struct pdu *ppdu, int prid)
{
	struct pduspec ps;
	int rv;
	long off;

	if (pkb == NULL || ppdu == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (pdu_get_spec(prid, ppdu, PDU_GSF_WRAPPLD, &ps) < 0)
		return -1;
	if (ps.hlen > pdu_hlen(&pkb->pdus) || ps.tlen > pdu_tlen(&pkb->pdus)) {
		errno = ENOMEM;
		return -1;
	}
	if (ps.hlen > 0) {
		off = pdu_hlen(ppdu);
		rv = pdu_inject(ppdu, pkb->buf, off, ps.hlen, 0);
		if (rv < 0)
			return -1;
		if (ppdu != &pkb->pdus)
			if (pdu_adj_off(ppdu, PDU_OI_POFF, -ps.hlen) < 0)
				return -1;
	}
	if (ps.tlen > 0) {
		off = pdu_plen(ppdu); /* hlen == 0: we just cut it */
		rv = pdu_inject(ppdu, pkb->buf, off, ps.tlen, 1);
		if (rv < 0)
			return -1;
	}
	if (pdu_add(ppdu, pkb->buf, &ps, 1) < 0)
		return -1;
	if (pdu_fix_nxthdr(ppdu, pkb->buf) < 0)
		return -1;
	pkb_set_layer(pkb, pdu_next(ppdu), SET_LAYER_AUTO);

	return 0;
}


int pkb_delete_pdu(struct pktbuf *pkb, struct pdu *pdu)
{
	struct pdu *ppdu;
	int i;

	if (pkb == NULL || pdu == NULL || pdu_is_root(pdu)) {
		errno = EINVAL;
		return -1;
	}

	ppdu = pdu->region;
	if (pdu_hlen(pdu) > 0)
		if (pdu_cut(pdu, pkb->buf, 0, pdu_hlen(pdu), 1) < 0)
			return -1;
	if (pdu_tlen(pdu) > 0)
		if (pdu_cut(pdu, pkb->buf, pdu_plen(pdu), pdu_tlen(pdu), 0) < 0)
			return -1;
	for (i = 0; i < PKB_LAYER_NUM; ++i) {
		if (pkb->layers[i] == pdu) {
			pkb->layers[i] = NULL;
			break;
		}
	}
	pdu_free_parse(pdu);
	pdu_fix_nxthdr(ppdu, pkb->buf);

	return 0;
}


struct xpkt *pkb_get_xpkt(struct pktbuf *pkb)
{
	abort_unless(pkb);
	if ((pkb->flags & PKB_F_PACKED))
		return NULL;
	return pkb->xpkt;
}


struct xpkt_tag_hdr *pkb_next_tag(struct pktbuf *pkb, struct xpkt_tag_hdr *t)
{
	abort_unless(pkb);
	if ((pkb->flags & PKB_F_PACKED))
		return NULL;
	return xpkt_next_tag(pkb->xpkt, t);
}


struct xpkt_tag_hdr *pkb_find_tag(struct pktbuf *pkb, byte_t type, int idx)
{
	abort_unless(pkb);
	if ((pkb->flags & PKB_F_PACKED))
		return NULL;
	return xpkt_find_tag(pkb->xpkt, type, idx);
}


int pkb_find_tag_idx(struct pktbuf *pkb, struct xpkt_tag_hdr *xth)
{
	abort_unless(pkb && xth);
	if ((pkb->flags & PKB_F_PACKED))
		return -1;
	return xpkt_find_tag_idx(pkb->xpkt, xth);
}


int pkb_add_tag(struct pktbuf *pkb, struct xpkt_tag_hdr *xth)
{
	ulong mlen;

	abort_unless(pkb && xth);
	if ((pkb->flags & PKB_F_PACKED))
		return -1;

	/* none of these can overflow:  long is 32 bits and tlen is 16, and */
	/* xpkt_tag_size will return <= 1024.  */
	mlen = pkb->xpkt->hdr.tlen * 4 + XPKT_HLEN;
	mlen += xpkt_tag_size(xth);

	if (mlen > pkb->xsize)
		return -1;

	return xpkt_add_tag(pkb->xpkt, xth, 1);
}


int pkb_del_tag(struct pktbuf *pkb, byte_t type, int idx)
{
	abort_unless(pkb && (idx >= 0));
	if ((pkb->flags & PKB_F_PACKED))
		return -1;
	return xpkt_del_tag(pkb->xpkt, type, idx, 1);
}


int pkb_get_lidx(uint prid)
{
	if (!PRID_IS_PCLASS(prid))
		return -1;
	/* packet buffer layers correspond one-to-one with in order */
	/* with protocol classes */
	return prid - PRID_PCLASS_MIN;
}
