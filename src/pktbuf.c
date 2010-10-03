#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <cat/pcache.h>
#include <cat/io.h>
#include "pktbuf.h"
#include "dltypes.h"
#include "stdpp.h"

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
	pc_init(&pkb_xpkt_pool, sizeof(struct pktbuf), 65536,
		num_buf_expected, 0, &stdmm);
	pc_init(&pkb_xpkt_pool, pkb_xpkt_pool_size, pkb_xpkt_pool_size * 32,
		num_buf_expected, 0, &stdmm);
	for (i = 0; i < pkb_num_data_pools; ++i) {
		pc_init(&pkb_data_pools[i], pkb_data_pool_sizes[i],
			pkb_data_pool_sizes[i] * 32,
			num_buf_expected, 0, &stdmm);
	}
}


struct pktbuf *pkb_create(long bsize)
{
	struct pktbuf *pkb; 
	void *xmp, *dp;
	int i;
	struct xpkthdr *xh;
	int pl;

	/* calculate the total size of the buffer */
	if (bsize < 0) {
		errno = EINVAL;
		return NULL;
	}
	if (bsize > PKB_MAX_DATA_LEN) {
		errno = ENOMEM;
		return NULL;
	}

	for (pl = 0; pl < pkb_num_data_pools; ++pl)
		if (bsize <= pkb_data_pool_sizes[pl])
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

	l_init(&pkb->pkb_entry);
	pkb->pkb_buf = dp;
	pkb->pkb_bsize = bsize;
	pkb->pkb_xpkt = xmp;
	pkb->pkb_xsize = pkb_xpkt_pool_size;
	pkb->pkb_xtlen = 0;

	prp_init_parse(&pkb->pkb_prp, dp, bsize);
	for (i = 0; i < PKB_LAYER_NUM; ++i)
		pkb->pkb_layers[i] = NULL;

	xh = (struct xpkthdr *)xmp;
	xh->xh_len = XPKT_HLEN;
	xh->xh_dltype = DLT_NONE;
	xh->xh_tlen = 0;

	return pkb;
}


struct pktbuf *pkb_copy(struct pktbuf *opkb)
{
	struct pktbuf *npkb;
	int errval;
	struct prparse *nt, *ot, *layer;
	int i;

	if (!(npkb = pkb_create(opkb->pkb_bsize)))
		return NULL;
	if (prp_copy(&npkb->pkb_prp, &opkb->pkb_prp, npkb->pkb_buf) < 0) {
		errval = errno;
		pkb_free(npkb);
		errno = errval;
		return NULL;
	}

	/* from here on we are safe */
	memcpy(npkb->pkb_buf + prp_poff(&npkb->pkb_prp),
	       opkb->pkb_buf + prp_poff(&opkb->pkb_prp),
	       prp_plen(&opkb->pkb_prp));

	if ((opkb->pkb_flags & PKB_F_PACKED)) {
		memcpy(npkb->pkb_xpkt, opkb->pkb_xpkt, 
		       opkb->pkb_xtlen + XPKT_HLEN);
	} else {
		memcpy(npkb->pkb_xpkt, opkb->pkb_xpkt, 
		       opkb->pkb_xpkt->xpkt_len);
	}

	/* Set the layers in the new packet buffer */
	for (i = 0; i < PKB_LAYER_NUM; ++i) { 
		if (!(layer = opkb->pkb_layers[i]))
			continue;
		ot = prp_next(&opkb->pkb_prp);
		nt = prp_next(&npkb->pkb_prp);
		while (!prp_list_end(ot) && (ot != layer)) {
			ot = prp_next(ot);
			nt = prp_next(nt);
		}
		abort_unless(!prp_list_end(ot));
		npkb->pkb_layers[i] = nt;
	}

	npkb->pkb_flags = opkb->pkb_flags;

	return npkb;
}


void pkb_free(struct pktbuf *pkb)
{
	if (pkb) {
		prp_clear(&pkb->pkb_prp);
		pc_free(pkb->pkb_xpkt);
		pc_free(pkb->pkb_buf);
		pc_free(pkb);
	}
}


long pkb_get_off(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return prp_poff(&pkb->pkb_prp);
}


long pkb_get_len(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return prp_plen(&pkb->pkb_prp);
}


uint16_t pkb_get_dltype(struct pktbuf *pkb)
{
	abort_unless(pkb && pkb->pkb_xpkt);
	return pkb->pkb_xpkt->xpkt_dltype;
}


void pkb_set_off(struct pktbuf *pkb, long off)
{
	long l;

	abort_unless(!pkb_is_parsed(pkb));
	abort_unless(off >= 0);

	l = prp_plen(&pkb->pkb_prp);

	/* check for overflow/underflow:  integer then buffer */
	abort_unless(l + off >= 0);
	abort_unless(l + off <= prp_totlen(&pkb->pkb_prp));

	prp_poff(&pkb->pkb_prp) = off;
	prp_toff(&pkb->pkb_prp) = off + l;
}


void pkb_set_len(struct pktbuf *pkb, long len)
{
	long l;

	abort_unless(!pkb_is_parsed(pkb));
	abort_unless(len >= 0);

	l = prp_poff(&pkb->pkb_prp);

	/* check for overflow/underflow:  integer then buffer */
	abort_unless(l + len >= 0);
	abort_unless(l + len <= prp_totlen(&pkb->pkb_prp));

	prp_toff(&pkb->pkb_prp) = len + l;
}


/* Set the offset field in the packet buffer */
void pkb_set_dltype(struct pktbuf *pkb, uint16_t dltype)
{
	abort_unless(pkb && pkb->pkb_xpkt);
	pkb->pkb_xpkt->xpkt_dltype = dltype;
}


void *pkb_data(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return pkb->pkb_buf + prp_poff(&pkb->pkb_prp);
}


#define HPADMIN		192
#define TPADMIN		192
int pkb_file_read(FILE *fp, struct pktbuf **pkbp)
{
	struct xpkthdr xh;
	int errval;
	struct pktbuf *pkb;
	uint hpad = HPADMIN;
	uint hread;
	uint off;
	struct xpkt *x;
	size_t nr;

	abort_unless(fp && pkbp);

	if ((nr = fread(&xh, 1, XPKT_HLEN, fp)) < XPKT_HLEN)
		return (nr == 0) ? 0 : -1;
	xpkt_unpack_hdr(&xh);
	if ((xpkt_validate_hdr(&xh) < 0) || !dlt_valid(xh.xh_dltype)) {
		errno = EIO;
		return -1;
	}

	hread = xh.xh_tlen + dlt_offset(xh.xh_dltype);
	if (hpad < hread)
		hpad = hread;

	if ((xh.xh_len > PKB_MAX_DATA_LEN - hpad - TPADMIN) ||
	    (xh.xh_tlen + sizeof(xh) > pkb_xpkt_pool_size)) {
		errno = ENOMEM;
		return -1;
	}

	if (!(pkb = pkb_create(xh.xh_len + hpad + TPADMIN)))
		return -1;

	off = hpad - xh.xh_tlen;
	nr = fread(pkb->pkb_buf + off, 1, xh.xh_len - XPKT_HLEN, fp);
	if (nr < xh.xh_len - XPKT_HLEN)
		goto err_have_buf;

	x = pkb->pkb_xpkt;
	x->hdr = xh;
	memcpy(x->xpkt_tags, pkb->pkb_buf + off, xh.xh_tlen);
	pkb->pkb_xtlen = xh.xh_tlen = XPKT_HLEN;
	if (xpkt_unpack_tags(x->xpkt_tags, x->xpkt_tlen) < 0) {
		errno = EIO;
		goto err_have_buf;
	}
	if (xpkt_validate_tags(x->xpkt_tags, x->xpkt_tlen) < 0) {
		errno = EIO;
		goto err_have_buf;
	}

	prp_adj_off(&pkb->pkb_prp, PRP_OI_POFF, hpad);
	prp_adj_off(&pkb->pkb_prp, PRP_OI_TOFF, hpad + xpkt_data_len(x));

	pkb->pkb_flags = 0;

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
	uint hread;
	uint off;
	long dlen;
	struct xpkt *x;
	ssize_t nr;

	abort_unless((fd >= 0) && pkbp);

	if ((nr = io_read(fd, &xh, sizeof(XPKT_HLEN))) < XPKT_HLEN)
		return (nr == 0) ? 0 : -1;
	xpkt_unpack_hdr(&xh);
	if ((xpkt_validate_hdr(&xh) < 0) || !dlt_valid(xh.xh_dltype)) {
		errno = EIO;
		return -1;
	}

	hread = xh.xh_tlen + dlt_offset(xh.xh_dltype);
	if (hpad < hread)
		hpad = hread;

	if ((xh.xh_len > PKB_MAX_DATA_LEN - hpad - TPADMIN) ||
	    (xh.xh_tlen + sizeof(xh) > pkb_xpkt_pool_size)) {
		errno = ENOMEM;
		return -1;
	}

	if (!(pkb = pkb_create(xh.xh_len + hpad + TPADMIN)))
		return -1;

	off = hpad - xh.xh_tlen;
	dlen = xh.xh_len - XPKT_HLEN;
	nr = io_read(fd, pkb->pkb_buf + off, dlen);
	if (nr < dlen)
		goto err_have_buf;

	x = pkb->pkb_xpkt;
	x->hdr = xh;
	memcpy(x->xpkt_tags, pkb->pkb_buf + off, xh.xh_tlen);
	pkb->pkb_xtlen = xh.xh_tlen = XPKT_HLEN;
	if (xpkt_unpack_tags(x->xpkt_tags, x->xpkt_tlen) < 0) {
		errno = EIO;
		goto err_have_buf;
	}
	if (xpkt_validate_tags(x->xpkt_tags, x->xpkt_tlen) < 0) {
		errno = EIO;
		goto err_have_buf;
	}

	prp_poff(&pkb->pkb_prp) = hpad;
	prp_toff(&pkb->pkb_prp) = hpad + dlen;

	pkb->pkb_flags = 0;

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

	if ((pkb->pkb_flags & PKB_F_PACKED))
		return 0;

	x = pkb->pkb_xpkt;

	/* When the buffer is packed, the pkb_xtlen caches the tag length */
	pkb->pkb_xtlen = x->xpkt_tlen;

	len = x->xpkt_len + prp_plen(&pkb->pkb_prp);
	if (len > SIZE_MAX)
		return -1;
	if (xpkt_validate_tags(x->xpkt_tags, x->xpkt_tlen) < 0)
		return -2;
	x->xpkt_len = len;
	xpkt_pack_tags(x->xpkt_tags, x->xpkt_tlen);
	xpkt_pack_hdr(&x->hdr);

	pkb->pkb_flags |= PKB_F_PACKED;

	return 0;
}


void pkb_unpack(struct pktbuf *pkb)
{
	struct xpkt *x;

	abort_unless(pkb);

	if (!(pkb->pkb_flags & PKB_F_PACKED))
		return;

	x = pkb->pkb_xpkt;
	xpkt_unpack_hdr(&x->hdr);
	xpkt_unpack_tags(x->xpkt_tags, x->xpkt_tlen);

	/* In unpacked state, the xpkt_len says there is no data: only tags */
	x->xpkt_len = x->xpkt_tlen + XPKT_HLEN;

	pkb->pkb_flags &= ~PKB_F_PACKED;
}


int pkb_is_packed(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return (pkb->pkb_flags & PKB_F_PACKED) != 0;
}


int pkb_file_write(FILE *fp, struct pktbuf *pkb)
{
	size_t nw;
	long doff, dlen;

	abort_unless(fp && pkb);

	if (!(pkb->pkb_flags & PKB_F_PACKED))
		return -1;

	dlen = pkb->pkb_xtlen + XPKT_HLEN;
	nw = fwrite(pkb->pkb_xpkt, 1, dlen, fp);
	if (nw < dlen)
		return -1;

	doff = prp_poff(&pkb->pkb_prp);
	dlen = prp_plen(&pkb->pkb_prp);
	nw = fwrite(pkb->pkb_buf + doff, 1, dlen, fp);
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

	if (!(pkb->pkb_flags & PKB_F_PACKED))
		return -1;

	dlen = pkb->pkb_xtlen + XPKT_HLEN;
	nw = io_write(fd, pkb->pkb_xpkt, dlen);
	if (nw < dlen)
		return -1;

	doff = prp_poff(&pkb->pkb_prp);
	dlen = prp_plen(&pkb->pkb_prp);
	nw = io_write(fd, pkb->pkb_buf + doff, dlen);
	if (nw < dlen)
		return -1;

	return 0;
}


int pkb_parse(struct pktbuf *pkb)
{
	struct prparse *prp;
	uint ppt;

	abort_unless(pkb);

	if ((pkb->pkb_flags & PKB_F_PARSED))
		return -1;

	ppt = dlt2ppt(pkb->pkb_xpkt->xpkt_dltype);
	if (prp_parse_packet(&pkb->pkb_prp, ppt) < 0)
		return -1;

	for (prp=prp_next(&pkb->pkb_prp); !prp_list_end(prp); prp=prp_next(prp))
		pkb_set_layer(pkb, prp, -1);

	pkb->pkb_flags |= PKB_F_PARSED;

	return 0;
}


void pkb_clear_parse(struct pktbuf *pkb)
{
	abort_unless(pkb);
	if (!(pkb->pkb_flags & PKB_F_PARSED)) {
		prp_clear(&pkb->pkb_prp);
		pkb->pkb_flags &= ~PKB_F_PARSED;
	}
}


int pkb_is_parsed(struct pktbuf *pkb)
{
	abort_unless(pkb);
	return (pkb->pkb_flags & PKB_F_PARSED) != 0;
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
		pkb->pkb_layers[layer] = prp;
	} else {
		if (islink(prp->type)) {
			if (!pkb->pkb_layers[PKB_LAYER_DL])
				pkb->pkb_layers[PKB_LAYER_DL] = prp;
		} else if (istunnel(prp->type)) {
			if (!pkb->pkb_layers[PKB_LAYER_TUN])
				pkb->pkb_layers[PKB_LAYER_TUN] = prp;
		} else if (isnet(prp->type)) {
			if (!pkb->pkb_layers[PKB_LAYER_NET])
				pkb->pkb_layers[PKB_LAYER_NET] = prp;
		} else if (isxport(prp->type)) {
			if (!pkb->pkb_layers[PKB_LAYER_XPORT])
				pkb->pkb_layers[PKB_LAYER_XPORT] = prp;
		}
	}
}


void pkb_clr_layer(struct pktbuf *pkb, int layer)
{
	abort_unless(layer >= 0 && layer < PKB_LAYER_NUM);
	pkb->pkb_layers[layer] = NULL;
}


void pkb_fix_dltype(struct pktbuf *pkb)
{
	uint16_t dltype = DLT_NONE;
	if (pkb->pkb_layers[PKB_LAYER_DL] != NULL) {
		dltype = ppt2dlt(pkb->pkb_layers[PKB_LAYER_DL]->type);
		abort_unless(dltype != DLT_INVALID);
	}
	pkb->pkb_xpkt->xpkt_dltype = dltype;
}


int pkb_pushprp(struct pktbuf *pkb, int ppt)
{
	if (prp_push(ppt, prp_prev(&pkb->pkb_prp), PPCF_FILL) < 0)
		return -1;
	pkb_set_layer(pkb, prp_prev(&pkb->pkb_prp), -1);
	return 0;
}


int pkb_wrapprp(struct pktbuf *pkb, int ppt)
{
	if (prp_push(ppt, &pkb->pkb_prp, PPCF_FILL) < 0)
		return -1;
	pkb_set_layer(pkb, prp_next(&pkb->pkb_prp), -1);
	return 0;
}


void pkb_popprp(struct pktbuf *pkb, int fromfront)
{
	struct prparse *topop;
	int i;
	if (fromfront)
		topop = prp_next(&pkb->pkb_prp);
	else
		topop = prp_prev(&pkb->pkb_prp);
	if (!prp_list_head(topop)) {
		for (i = 0; i < PKB_LAYER_NUM; ++i) {
			if (pkb->pkb_layers[i] == topop) {
				pkb->pkb_layers[i] = NULL;
				break;
			}
		}
		prp_free_parse(topop);
	}
}


struct xpkt *pkb_get_xpkt(struct pktbuf *pkb)
{
	abort_unless(pkb);
	if ((pkb->pkb_flags & PKB_F_PACKED))
		return NULL;
	return pkb->pkb_xpkt;
}


struct xpkt_tag_hdr *pkb_next_tag(struct pktbuf *pkb, struct xpkt_tag_hdr *t)
{
	abort_unless(pkb && t);
	if ((pkb->pkb_flags & PKB_F_PACKED))
		return NULL;
	return xpkt_next_tag(pkb->pkb_xpkt, t);
}


struct xpkt_tag_hdr *pkb_find_tag(struct pktbuf *pkb, byte_t type, int idx)
{
	abort_unless(pkb);
	if ((pkb->pkb_flags & PKB_F_PACKED))
		return NULL;
	return xpkt_find_tag(pkb->pkb_xpkt, type, idx);
}


int pkb_find_tag_idx(struct pktbuf *pkb, struct xpkt_tag_hdr *xth)
{
	abort_unless(pkb && xth);
	if ((pkb->pkb_flags & PKB_F_PACKED))
		return -1;
	return xpkt_find_tag_idx(pkb->pkb_xpkt, xth);
}


int pkb_add_tag(struct pktbuf *pkb, struct xpkt_tag_hdr *xth)
{
	long mlen;
	abort_unless(pkb && xth);
	if ((pkb->pkb_flags & PKB_F_PACKED))
		return -1; 

	/* none of these can overflow:  long is 32 bits and tlen is 16, and */
	/* nwords is 8.  */
	mlen = pkb->pkb_xpkt->xpkt_tlen + XPKT_HLEN;
	mlen += xth->xth_nwords * 4;

	if (mlen > pkb->pkb_xsize)
		return -1;

	return xpkt_add_tag(pkb->pkb_xpkt, xth, 1);
}


int pkb_del_tag(struct pktbuf *pkb, byte_t type, int idx)
{
	abort_unless(pkb && (idx >= 0));
	if ((pkb->pkb_flags & PKB_F_PACKED))
		return -1;
	return xpkt_del_tag(pkb->pkb_xpkt, type, idx, 1);
}

