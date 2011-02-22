#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <cat/pcache.h>
#include <cat/io.h>
#include "pktbuf.h"
#include "dltypes.h"
#include "stdproto.h"

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


#define DLT_INVALID_PAD		-1
#define DLT_NONE_PAD		0
#define DLT_ETHERNET2_PAD	2

int dloffs[DLT_MAX+1] = {
	DLT_INVALID_PAD,
	DLT_NONE_PAD,
	DLT_ETHERNET2_PAD,
};


static int dlt_valid(uint16_t dltype)
{
	return (dltype >= DLT_MIN) && (dltype <= DLT_MAX);
}

/* Returns the pad offset for this DL type -- usually 0-3 */
/* ONLY call with a valid dltype or it will abort. */
static int dlt_offset(uint16_t dltype)
{
	int offset = -1;
	if (dltype <= DLT_MAX) 
		offset = dloffs[dltype];
	abort_unless(offset >= 0);
	return offset;
}


uint16_t dlt2ppt(uint16_t dlt)
{
	return PPT_BUILD(PPT_PF_DLT, dlt);
}


uint16_t ppt2dlt(uint16_t ppt)
{
	return PPT_PROTO(ppt);
}


void pkb_init(uint num_buf_expected)
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


struct pktbuf *pkb_create(ulong bufsize)
{
	struct pktbuf *pkb; 
	void *xmp, *dp;
	int i;
	struct xpkthdr *xh;
	int pl;

	/* calculate the total size of the buffer */
	if (bufsize > PKB_MAX_DATA_LEN) {
		errno = ENOMEM;
		return NULL;
	}

	for (pl = 0; pl < pkb_num_data_pools; ++pl)
		if (bufsize <= pkb_data_pool_sizes[pl])
			break;
	abort_unless(pl < pkb_num_data_pools);

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
	pkb->buf = dp;
	pkb->bufsize = bufsize;
	pkb->xpkt = xmp;
	pkb->xsize = pkb_xpkt_pool_size;
	pkb->xhlen = 0;

	prp_init_parse(&pkb->prp, dp, bufsize);
	for (i = 0; i < PKB_LAYER_NUM; ++i)
		pkb->layers[i] = NULL;

	xh = (struct xpkthdr *)xmp;
	xh->len = XPKT_HLEN;
	xh->dltype = DLT_NONE;
	xh->tlen = 0;

	return pkb;
}


struct pktbuf *pkb_copy(struct pktbuf *opkb)
{
	struct pktbuf *npkb;
	int errval;
	struct prparse *nt, *ot, *layer;
	int i;

	if (!(npkb = pkb_create(opkb->bufsize)))
		return NULL;
	if (prp_copy(&npkb->prp, &opkb->prp, npkb->buf) < 0) {
		errval = errno;
		pkb_free(npkb);
		errno = errval;
		return NULL;
	}

	/* from here on we are safe */
	memcpy(npkb->buf + prp_poff(&npkb->prp),
	       opkb->buf + prp_poff(&opkb->prp), prp_plen(&opkb->prp));

	if ((opkb->flags & PKB_F_PACKED)) {
		memcpy(npkb->xpkt, opkb->xpkt, opkb->xhlen);
	} else {
		memcpy(npkb->xpkt, opkb->xpkt, xpkt_doff(opkb->xpkt));
	}

	/* Set the layers in the new packet buffer */
	for (i = 0; i < PKB_LAYER_NUM; ++i) { 
		if (!(layer = opkb->layers[i]))
			continue;
		ot = prp_next(&opkb->prp);
		nt = prp_next(&npkb->prp);
		while (!prp_list_end(ot) && (ot != layer)) {
			ot = prp_next(ot);
			nt = prp_next(nt);
		}
		abort_unless(!prp_list_end(ot));
		npkb->layers[i] = nt;
	}

	npkb->flags = opkb->flags;

	return npkb;
}


void pkb_free(struct pktbuf *pkb)
{
	if (pkb) {
		prp_clear(&pkb->prp);
		pc_free(pkb->xpkt);
		pc_free(pkb->buf);
		pc_free(pkb);
	}
}


ulong pkb_get_off(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return prp_poff(&pkb->prp);
}


ulong pkb_get_len(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return prp_plen(&pkb->prp);
}


uint16_t pkb_get_dltype(struct pktbuf *pkb)
{
	abort_unless(pkb && pkb->xpkt);
	return pkb->xpkt->hdr.dltype;
}


void pkb_set_off(struct pktbuf *pkb, ulong off)
{
	ulong l;

	abort_unless(!pkb_is_parsed(pkb));

	l = prp_plen(&pkb->prp);

	/* check for overflow/underflow:  integer then buffer */
	abort_unless(l + off >= off);
	abort_unless(l + off <= prp_totlen(&pkb->prp));

	prp_poff(&pkb->prp) = off;
	prp_toff(&pkb->prp) = off + l;
}


void pkb_set_len(struct pktbuf *pkb, ulong len)
{
	ulong l;

	abort_unless(!pkb_is_parsed(pkb));

	l = prp_poff(&pkb->prp);

	/* check for overflow/underflow:  integer then buffer */
	abort_unless(l + len >= len);
	abort_unless(l + len <= prp_totlen(&pkb->prp));

	prp_toff(&pkb->prp) = len + l;
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
	return pkb->buf + prp_poff(&pkb->prp);
}


#define HPADMIN		192
#define TPADMIN		192
int pkb_file_read(FILE *fp, struct pktbuf **pkbp)
{
	struct xpkthdr xh;
	int errval;
	struct pktbuf *pkb;
	uint hpad = HPADMIN;
	uint n;
	uint off;
	struct xpkt *x;
	size_t nr;

	abort_unless(fp && pkbp);

	if ((nr = fread(&xh, 1, XPKT_HLEN, fp)) < XPKT_HLEN)
		return (nr == 0) ? 0 : -1;
	xpkt_unpack_hdr(&xh);
	if ((xpkt_validate_hdr(&xh) < 0) || !dlt_valid(xh.dltype)) {
		errno = EIO;
		return -1;
	}

	n = xh.tlen * 4 + XPKT_HLEN;
	if (hpad < n)
		hpad = n;

	off = dlt_offset(xh.dltype);
	n = hpad + TPADMIN + off;
	if ((xh.len > PKB_MAX_DATA_LEN - n) ||
	    (xh.tlen * 4 + XPKT_HLEN > pkb_xpkt_pool_size)) {
		errno = ENOMEM;
		return -1;
	}

	if (!(pkb = pkb_create(xh.len + n)))
		return -1;

	n = hpad - xh.tlen * 4 + off;
	nr = fread(pkb->buf + n, 1, xh.len - XPKT_HLEN, fp);
	if (nr < xh.len - XPKT_HLEN)
		goto err_have_buf;

	x = pkb->xpkt;
	x->hdr = xh;
	memcpy(x->tags, pkb->buf + n, xh.tlen * 4);
	if (xpkt_unpack_tags(x->tags, x->hdr.tlen) < 0) {
		errno = EIO;
		goto err_have_buf;
	}
	if (xpkt_validate_tags(x->tags, x->hdr.tlen) < 0) {
		errno = EIO;
		goto err_have_buf;
	}

	prp_poff(&pkb->prp) = hpad + off;
	prp_toff(&pkb->prp) = hpad + off + xpkt_data_len(x);

	pkb->flags = 0;

	*pkbp = pkb;

	return 1;

err_have_buf:
	errval = errno;
	pkb_free(pkb);
	errno = errval;
	return -1;
}


int pkb_fd_read(int fd, struct pktbuf **pkbp)
{
	struct xpkthdr xh;
	int errval;
	struct pktbuf *pkb;
	uint hpad = HPADMIN;
	uint n;
	uint off;
	long dlen;
	struct xpkt *x;
	ssize_t nr;

	abort_unless((fd >= 0) && pkbp);

	if ((nr = io_read(fd, &xh, sizeof(XPKT_HLEN))) < XPKT_HLEN)
		return (nr == 0) ? 0 : -1;
	xpkt_unpack_hdr(&xh);
	if ((xpkt_validate_hdr(&xh) < 0) || !dlt_valid(xh.dltype)) {
		errno = EIO;
		return -1;
	}

	n = xh.tlen * 4 + XPKT_HLEN;
	if (hpad < n)
		hpad = n;

	off = dlt_offset(xh.dltype);
	n = hpad + TPADMIN + off;
	if ((xh.len > PKB_MAX_DATA_LEN - n) ||
	    (xh.tlen * 4 + XPKT_HLEN > pkb_xpkt_pool_size)) {
		errno = ENOMEM;
		return -1;
	}

	if (!(pkb = pkb_create(xh.len + n)))
		return -1;

	n = hpad - xh.tlen * 4 + off;
	dlen = xh.len - XPKT_HLEN;
	nr = io_read(fd, pkb->buf + n, dlen);
	if (nr < dlen)
		goto err_have_buf;

	x = pkb->xpkt;
	x->hdr = xh;
	memcpy(x->tags, pkb->buf + n, xh.tlen * 4);
	if (xpkt_unpack_tags(x->tags, x->hdr.tlen) < 0) {
		errno = EIO;
		goto err_have_buf;
	}
	if (xpkt_validate_tags(x->tags, x->hdr.tlen) < 0) {
		errno = EIO;
		goto err_have_buf;
	}

	prp_poff(&pkb->prp) = hpad + off;
	prp_toff(&pkb->prp) = hpad + off + xpkt_data_len(x);

	pkb->flags = 0;

	*pkbp = pkb;

	return 1;

err_have_buf:
	errval = errno;
	pkb_free(pkb);
	errno = errval;
	return -1;
}


int pkb_pack(struct pktbuf *pkb)
{
	struct xpkt *x;
	uint32_t len;

	abort_unless(pkb);

	if ((pkb->flags & PKB_F_PACKED))
		return 0;

	x = pkb->xpkt;

	/* When the buffer is packed, the xhlen caches the tag length */
	pkb->xhlen = xpkt_doff(x);

	len = pkb->xhlen + prp_plen(&pkb->prp);
	if (len > SIZE_MAX)
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


int pkb_file_write(FILE *fp, struct pktbuf *pkb)
{
	size_t nw;
	long doff, dlen;

	abort_unless(fp && pkb);

	if (!(pkb->flags & PKB_F_PACKED))
		return -1;

	nw = fwrite(pkb->xpkt, 1, pkb->xhlen, fp);
	if (nw < pkb->xhlen)
		return -1;

	doff = prp_poff(&pkb->prp);
	dlen = prp_plen(&pkb->prp);
	nw = fwrite(pkb->buf + doff, 1, dlen, fp);
	if (nw < dlen)
		return -1;

	fflush(fp);

	return 0;
}


int pkb_fd_write(int fd, struct pktbuf *pkb)
{
	ssize_t nw;
	long doff, dlen;

	abort_unless((fd >= 0) && pkb);

	if (!(pkb->flags & PKB_F_PACKED))
		return -1;

	nw = io_write(fd, pkb->xpkt, pkb->xhlen);
	if (nw < pkb->xhlen)
		return -1;

	doff = prp_poff(&pkb->prp);
	dlen = prp_plen(&pkb->prp);
	nw = io_write(fd, pkb->buf + doff, dlen);
	if (nw < dlen)
		return -1;

	return 0;
}


int pkb_parse(struct pktbuf *pkb)
{
	struct prparse *prp;
	uint ppt;

	abort_unless(pkb);

	if ((pkb->flags & PKB_F_PARSED))
		return -1;

	ppt = dlt2ppt(pkb->xpkt->hdr.dltype);
	if (prp_parse_packet(&pkb->prp, ppt) < 0)
		return -1;

	for (prp=prp_next(&pkb->prp); !prp_list_end(prp); prp=prp_next(prp))
		pkb_set_layer(pkb, prp, -1);

	pkb->flags |= PKB_F_PARSED;

	return 0;
}


void pkb_clear_parse(struct pktbuf *pkb)
{
	abort_unless(pkb);
	if (!(pkb->flags & PKB_F_PARSED)) {
		prp_clear(&pkb->prp);
		pkb->flags &= ~PKB_F_PARSED;
	}
}


int pkb_is_parsed(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return (pkb->flags & PKB_F_PARSED) != 0;
}


static int islink(int ppt)
{
	return ppt == PPT_ETHERNET2;
}


static int istunnel(int ppt)
{
	return 0;
}


static int isnet(int ppt)
{
	switch (ppt) {
	case PPT_IPV4:
	case PPT_IPV6:
	case PPT_ARP:
		return 1;
	default:
		return 0;
	}
	return (ppt == PPT_IPV4) || (ppt == PPT_IPV6) || (ppt == PPT_ARP);
}


static int isxport(int ppt)
{
	switch (ppt) {
	case PPT_ICMP:
	case PPT_ICMP6:
	case PPT_UDP:
	case PPT_TCP:
		return 1;
	default:
		return 0;
	}
}


void pkb_set_layer(struct pktbuf *pkb, struct prparse *prp, int layer)
{
	abort_unless(pkb && prp && (layer < PKB_LAYER_NUM));
	/* XXX : should we sanity check that h in in pkt? */
	if (layer >= 0) {
		pkb->layers[layer] = prp;
	} else {
		if (islink(prp->type)) {
			if (!pkb->layers[PKB_LAYER_DL])
				pkb->layers[PKB_LAYER_DL] = prp;
		} else if (istunnel(prp->type)) {
			if (!pkb->layers[PKB_LAYER_TUN])
				pkb->layers[PKB_LAYER_TUN] = prp;
		} else if (isnet(prp->type)) {
			if (!pkb->layers[PKB_LAYER_NET])
				pkb->layers[PKB_LAYER_NET] = prp;
		} else if (isxport(prp->type)) {
			if (!pkb->layers[PKB_LAYER_XPORT])
				pkb->layers[PKB_LAYER_XPORT] = prp;
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
	uint16_t dltype = DLT_NONE;
	if (pkb->layers[PKB_LAYER_DL] != NULL) {
		dltype = ppt2dlt(pkb->layers[PKB_LAYER_DL]->type);
		abort_unless(dltype != DLT_INVALID);
	}
	pkb->xpkt->hdr.dltype = dltype;
}


int pkb_pushprp(struct pktbuf *pkb, int ppt)
{
	if (prp_push(ppt, prp_prev(&pkb->prp), PPCF_FILL) < 0)
		return -1;
	pkb_set_layer(pkb, prp_prev(&pkb->prp), -1);
	return 0;
}


int pkb_wrapprp(struct pktbuf *pkb, int ppt)
{
	if (prp_push(ppt, &pkb->prp, PPCF_FILL) < 0)
		return -1;
	pkb_set_layer(pkb, prp_next(&pkb->prp), -1);
	return 0;
}


void pkb_popprp(struct pktbuf *pkb, int fromfront)
{
	struct prparse *topop;
	int i;
	if (fromfront)
		topop = prp_next(&pkb->prp);
	else
		topop = prp_prev(&pkb->prp);
	if (!prp_list_head(topop)) {
		for (i = 0; i < PKB_LAYER_NUM; ++i) {
			if (pkb->layers[i] == topop) {
				pkb->layers[i] = NULL;
				break;
			}
		}
		prp_free_parse(topop);
	}
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
	abort_unless(pkb && t);
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
	long mlen;
	abort_unless(pkb && xth);
	if ((pkb->flags & PKB_F_PACKED))
		return -1; 

	/* none of these can overflow:  long is 32 bits and tlen is 16, and */
	/* nwords is 8.  */
	mlen = pkb->xpkt->hdr.tlen * 4 + XPKT_HLEN;
	mlen += xth->nwords * 4;

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

