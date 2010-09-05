#include "config.h"
#include "metapkt.h"
#include "stdpp.h"
#include <cat/emalloc.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


/* NB: we pull these out because I'm thinking of changing the allocation */
/* scheme for metapackets in the future.  If so, I need  to change newpmeta() */
/* and freepmeta() */
static NETTOOLS_INLINE struct metapkt *newpmeta()
{
	struct metapkt *pkt = ecalloc(1, sizeof(struct metapkt));
	if (pkt)
		l_init(&pkt->entry);
	return pkt;
}


static NETTOOLS_INLINE void freepmeta(struct metapkt *pkt)
{
	free(pkt);
}


static unsigned dltype_to_ppt(uint32_t dltype)
{
	switch (dltype) {
	case PKTDL_ETHERNET2:
		return PPT_ETHERNET;
	case PKTDL_NONE:
		return PPT_NONE;
	default:
		return PPT_INVALID;
	}
}


static uint32_t ppt_to_dltype(int ppt)
{
	switch (ppt) {
	case PPT_ETHERNET:
		return PKTDL_ETHERNET2;
	case PPT_NONE:
		return PKTDL_NONE;
	default:
		return PKTDL_INVALID;
	}
}


struct metapkt *metapkt_new(size_t plen, int ppt)
{
	struct metapkt *pkt;
	uint32_t dltype = ppt_to_dltype(ppt);
	if (dltype == PKTDL_INVALID) {
		errno = EINVAL;
		return NULL;
	}
	if (!(pkt = newpmeta()))
		return NULL;
	if (pkb_create(&pkt->pkb, plen, dltype) < 0) {
		free(pkt);
		return NULL;
	}
	pkt->headers =
	    prp_create_parse(pkt->pkb->pkb_buffer, 0, pkt->pkb->pkb_buflen);
	if (!pkt->headers) {
		pkb_free(pkt->pkb);
		freepmeta(pkt);
		return NULL;
	}
	return pkt;
}


struct metapkt *pktbuf_to_metapkt(struct pktbuf *pkb)
{
	struct metapkt *pkt;
	struct prparse *prp;
	unsigned ppt;

	abort_unless(pkb);
	ppt = dltype_to_ppt(pkb->pkb_dltype);
	if (!(pkt = newpmeta()))
		return NULL;
	pkt->pkb = pkb;
	if (ppt != PPT_INVALID) {
		pkt->headers =
		    prp_parse_packet(ppt, pkb->pkb_buffer, pkb->pkb_offset,
				     pkb->pkb_len);
		/* add head and tail slack space to the main header */
		prp_adj_off(pkt->headers, PRP_OI_SOFF, -(long)pkb->pkb_offset);
		abort_unless(pkb->pkb_buflen >=
			     (pkb->pkb_len + pkb->pkb_offset));
		prp_adj_off(pkt->headers, PRP_OI_EOFF,
			    pkb->pkb_buflen - (pkb->pkb_len + pkb->pkb_offset));
	} else {
		pkt->headers =
		    prp_create_parse(pkb->pkb_buffer, 0, pkb->pkb_buflen);
	}
	if (!pkt->headers) {
		freepmeta(pkt);
		return NULL;
	}
	for (prp = prp_next(pkt->headers); prp->type != PPT_NONE;
	     prp = prp_next(prp))
		metapkt_set_layer(pkt, prp, -1);
	return pkt;
}


static int get_prp_index(struct metapkt *pkt, struct prparse *prp)
{
	int i = 0;
	struct prparse *t;
	for (t = prp_next(pkt->headers); t->type != PPT_NONE; t = prp_next(t)) {
		++i;
		if (t == prp)
			break;
	}
	abort_unless(t == prp && i > 0);
	return i;
}


static struct prparse *get_prp_byindex(struct metapkt *pkt, int i)
{
	struct prparse *t;
	abort_unless(i > 0);
	for (t = prp_next(pkt->headers); --i > 0; t = prp_next(t)) {
		abort_unless(t->type != PPT_NONE);
	}
	return t;
}


struct metapkt *metapkt_copy(struct metapkt *pkt)
{
	struct metapkt *pnew;
	int l;
	abort_unless(pkt && pkt->pkb && pkt->headers);
	if (!(pnew = newpmeta()))
		return NULL;
	if (pkb_copy(pkt->pkb, &pnew->pkb) < 0) {
		freepmeta(pnew);
		return NULL;
	}
	if (!(pnew->headers = prp_copy(pkt->headers, pnew->pkb->pkb_buffer))) {
		pkb_free(pnew->pkb);
		freepmeta(pnew);
		return NULL;
	}
	for (l = MPKT_LAYER_LINK; l <= MPKT_LAYER_MAX; ++l)
		if (pkt->layer[l])
			pnew->layer[l] =
			    get_prp_byindex(pnew,
					    get_prp_index(pkt, pkt->layer[l]));
	return pnew;
}


void metapkt_free(struct metapkt *pkt, int freebuf)
{
	if (pkt) {
		l_rem(&pkt->entry);
		if (pkt->headers) {
			prp_free(pkt->headers);
			pkt->headers = NULL;
		}
		if (pkt->pkb && freebuf)
			pkb_free(pkt->pkb);
		pkt->pkb = NULL;
		freepmeta(pkt);
	}
}


static int islink(int ppt)
{
	return ppt == PPT_ETHERNET;
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


void metapkt_set_layer(struct metapkt *pkt, struct prparse *h, int layer)
{
	abort_unless(pkt && h && (layer <= MPKT_LAYER_MAX));
	/* XXX : should we sanity check that h in in pkt? */
	if (layer >= 0) {
		pkt->layer[layer] = h;
	} else {
		if (islink(h->type)) {
			if (!pkt->layer[MPKT_LAYER_LINK])
				pkt->layer[MPKT_LAYER_LINK] = h;
		} else if (istunnel(h->type)) {
			if (!pkt->layer[MPKT_LAYER_TUN])
				pkt->layer[MPKT_LAYER_TUN] = h;
		} else if (isnet(h->type)) {
			if (!pkt->layer[MPKT_LAYER_NET])
				pkt->layer[MPKT_LAYER_NET] = h;
		} else if (isxport(h->type)) {
			if (!pkt->layer[MPKT_LAYER_XPORT])
				pkt->layer[MPKT_LAYER_XPORT] = h;
		}
	}
}


void metapkt_clr_layer(struct metapkt *pkt, int layer)
{
	abort_unless(layer >= 0 && layer <= MPKT_LAYER_MAX);
	pkt->layer[layer] = NULL;
}


int metapkt_pushprp(struct metapkt *pkt, int htype)
{
	if (prp_push(htype, prp_prev(pkt->headers), PPCF_FILL) < 0)
		return -1;
	metapkt_set_layer(pkt, prp_prev(pkt->headers), -1);
	return 0;
}


int metapkt_wrapprp(struct metapkt *pkt, int htype)
{
	if (prp_push(htype, pkt->headers, PPCF_WRAP) < 0)
		return -1;
	metapkt_set_layer(pkt, prp_next(pkt->headers), -1);
	return 0;
}


void metapkt_popprp(struct metapkt *pkt, int fromfront)
{
	struct prparse *topop;
	int i;
	if (fromfront)
		topop = prp_next(pkt->headers);
	else
		topop = prp_prev(pkt->headers);
	if (!prp_list_head(topop)) {
		for (i = 0; i <= MPKT_LAYER_MAX; ++i) {
			if (pkt->layer[i] == topop) {
				pkt->layer[i] = NULL;
				break;
			}
		}
		prp_free(topop);
	}
}


void metapkt_fixdlt(struct metapkt *pkt)
{
	uint32_t dltype = PKTDL_NONE;
	if (pkt->layer[MPKT_LAYER_LINK] != NULL) {
		dltype = ppt_to_dltype(pkt->layer[MPKT_LAYER_LINK]->type);
		abort_unless(dltype != PKTDL_INVALID);
	}
	pkt->pkb->pkb_dltype = dltype;
}
