#include "config.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "stdproto.h"
#include "util.h"
#include "ns.h"
#include <cat/emalloc.h>
#include <cat/pack.h>
#include <string.h>
#include <stdlib.h>

extern struct prparse_ops eth_prparse_ops;
extern struct prparse_ops arp_prparse_ops;
extern struct prparse_ops ipv4_prparse_ops;
extern struct prparse_ops ipv6_prparse_ops;
extern struct prparse_ops icmp_prparse_ops;
extern struct prparse_ops icmpv6_prparse_ops;
extern struct prparse_ops udp_prparse_ops;
extern struct prparse_ops tcp_prparse_ops;


struct eth_parse {
	struct prparse prp;
	ulong xfields[PRP_ETH_NXFIELDS];
};


struct arp_parse {
	struct prparse prp;
	ulong xfields[PRP_ARP_NXFIELDS];
};


struct ip_parse {
	struct prparse prp;
	ulong xfields[PRP_IP_NXFIELDS];
};


struct ipv6_parse {
	struct prparse prp;
	uint8_t nexth;
	ulong jlenoff;
};


struct tcp_parse {
	struct prparse prp;
	ulong xfields[PRP_TCP_NXFIELDS];
};


static void resetxfields(struct prparse *prp)
{
	uint i;
	for (i = PRP_OI_EXTRA; i < prp->noff; ++i)
		prp->offs[i] = PRP_OFF_INVALID;
}


/* NB:  right now we are using emalloc() fpr header allocation, but we */
/* may not do that in the future.  When that happens, we need to change */
/* newprp, crtprp, and freeprp */
static struct prparse *newprp(size_t sz, uint prid, struct prparse *pprp,
			      struct prparse_ops *ops, uint nxfields)
{
	struct prparse *prp;
	abort_unless(sz >= sizeof(struct prparse));
	prp = emalloc(sz);
	prp->prid = prid;
	prp->error = 0;
	prp_soff(prp) = prp_poff(pprp);
	prp_eoff(prp) = prp_toff(pprp);
	prp_poff(prp) = prp_soff(prp);
	prp_toff(prp) = prp_eoff(prp);
	prp->noff = PRP_OI_MIN_NUM + nxfields;
	prp->ops = ops;
	/* all of the default protocol parsers nest layers within layers  */
	/* this won't be true for all protocol parsers */
	prp->region = pprp;
	l_ins(&pprp->node, &prp->node);
	resetxfields(prp);
	return prp;
}

static struct prparse *crtprp(size_t sz, uint prid, long off, long hlen,
			      long plen, long tlen, struct prparse_ops *ops,
			      uint nxfields)
{
	struct prparse *prp;
	abort_unless(sz >= sizeof(struct prparse));
	prp = emalloc(sz);
	prp->prid = prid;
	prp->error = 0;
	prp_soff(prp) = off;
	prp_poff(prp) = off + hlen;
	prp_toff(prp) = off + hlen + plen;
	prp_eoff(prp) = off + hlen + plen + tlen;
	prp->noff = PRP_OI_MIN_NUM + nxfields;
	abort_unless(prp_soff(prp) >= 0 && prp_poff(prp) >= prp_soff(prp) &&
		     prp_toff(prp) >= prp_poff(prp) &&
		     prp_eoff(prp) >= prp_toff(prp));
	prp->ops = ops;
	l_init(&prp->node);
	resetxfields(prp);
	return prp;
}


static NETTOOLS_INLINE void freeprp(struct prparse *prp)
{
	free(prp);
}


static struct prparse *default_parse(struct prparse *pprp, byte_t *buf,
				     uint *nextprid)
{
	return NULL;
}


static struct prparse *default_add(long off, long len, long hlen, long plen,
				   byte_t *buf, int mode)
{
	return NULL;
}


static void default_update(struct prparse *prp, byte_t *buf)
{
	resetxfields(prp);
}


static int default_fixlen(struct prparse *prp, byte_t *buf)
{
	return 0;
}


static int default_fixcksum(struct prparse *prp, byte_t *buf)
{
	return 0;
}


static void default_free(struct prparse *prp)
{
	/* presently unused */
	(void)default_add;
	(void)default_parse;
	(void)default_update;
	freeprp(prp);
}


static struct prparse *simple_copy(struct prparse *oprp, size_t psize)
{
	struct prparse *prp;
	if (oprp == NULL)
		return NULL;
	prp = emalloc(psize);
	memcpy(prp, oprp, psize);
	prp->region = NULL;
	l_init(&prp->node);
	return prp;
}


static struct prparse *default_copy(struct prparse *oprp)
{
	return simple_copy(oprp, sizeof(struct prparse));
}


/* -- ops for Ethernet type -- */
static struct prparse *eth_parse(struct prparse *pprp, byte_t *buf,
				 uint *nextprid)
{
	struct prparse *prp;
	ushort etype;
	byte_t *p;
	ulong poff;
	uint vidx;

	abort_unless(pprp && nextprid);

	prp = newprp(sizeof(struct eth_parse), PRID_ETHERNET2, pprp, 
		     &eth_prparse_ops, PRP_ETH_NXFIELDS);
	if (!prp)
		return NULL;
	if (prp_totlen(prp) < ETHHLEN) {
		prp->error = PRP_ERR_TOOSMALL;
		*nextprid = PRID_INVALID;
		return prp;
	}

	poff = prp_soff(prp) + ETHHLEN;
	p = prp_header(prp, buf, byte_t) + ETHHLEN - 2;
	vidx = PRP_ETHFLD_VLAN0;
	do {
		unpack(p, 2, "h", &etype);
		switch (etype) {
		case ETHTYPE_IP:
			*nextprid = PRID_IPV4;
			break;
		case ETHTYPE_IPV6:
			*nextprid = PRID_IPV6;
			break;
		case ETHTYPE_ARP:
			*nextprid = PRID_ARP;
			break;
		case ETHTYPE_VLAN:
			if (prp_totlen(prp) < (poff - prp_soff(prp) + 4)) {
				prp->error = PRP_ERR_TOOSMALL;
				*nextprid = PRID_INVALID;
				return prp;
			}
			if (vidx < (PRP_OI_EXTRA + PRP_ETH_NXFIELDS)) {
				prp->offs[vidx] = poff;
				vidx += 1;
			}
			p += 4;
			poff += 4;
			break;
		default:
			*nextprid = PRID_INVALID;
		}
	} while (etype == ETHTYPE_VLAN);

	prp_poff(prp) = poff;
	prp->offs[PRP_ETHFLD_ETYPE] = poff - 2;

	return prp;
}


static struct prparse *eth_add(ulong off, ulong len, ulong hlen, ulong plen,
			       byte_t *buf, int mode)
{
	struct prparse *prp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len);

	if (mode == PRP_ADD_FILL) {
		if (len < ETHHLEN)
			return NULL;
		plen = len - ETHHLEN;
		hlen = ETHHLEN;
	} else if (mode == PRP_ADD_WRAP) {
		if (hlen < ETHHLEN)
			return NULL;
		hlen = ETHHLEN;
		off -= ETHHLEN;
		len = plen + hlen;
	} else {
		abort_unless(len - plen >= hlen);
		abort_unless(mode == PRP_ADD_WRAPFILL);
		if (hlen < ETHHLEN)
			return NULL;
	}
	prp = crtprp(sizeof(struct prparse), PRID_ETHERNET2, off, hlen, plen, 0,
		     &eth_prparse_ops, 0);
	if (prp && buf) {
		memset(buf + off, 0, prp_hlen(prp));
	}

	return prp;
}


static void eth_update(struct prparse *prp, byte_t *buf)
{
	ulong poff;
	ushort etype;
	byte_t *p;
	uint vidx;

	prp->error = 0;
	resetxfields(prp);

	if (prp_totlen(prp) < ETHHLEN) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < ETHHLEN) {
		prp->error |= PRP_ERR_HLEN;
		return;
	}

	poff = prp_soff(prp) + ETHHLEN;
	p = prp_header(prp, buf, byte_t) + ETHHLEN - 2;
	vidx = PRP_ETHFLD_VLAN0;
	do {
		unpack(p, 2, "h", &etype);
		if (etype == ETHTYPE_VLAN) {
			if (prp_totlen(prp) <  (poff - prp_soff(prp) + 4)) {
				prp->error = PRP_ERR_TOOSMALL;
				return;
			}
			if (vidx < (PRP_OI_EXTRA + PRP_ETH_NXFIELDS)) {
				prp->offs[vidx] = poff;
				vidx += 1;
			}
			p += 4;
			poff += 4;
			break;
		}
	} while (etype == ETHTYPE_VLAN);

	prp_poff(prp) = poff;
	prp->offs[PRP_ETHFLD_ETYPE] = poff - 2;
}


/* -- ops for ARP type -- */
static byte_t ethiparpstr[6] = {0, 1, 8, 0, 6, 4 };

static struct prparse *arp_parse(struct prparse *pprp, byte_t *buf,
				 uint *nextprid)
{
	struct prparse *prp;
	struct arph *arp;

	abort_unless(pprp && nextprid);

	prp = newprp(sizeof(struct arp_parse), PRID_ARP, pprp, &arp_prparse_ops,
		     PRP_ARP_NXFIELDS);
	if (!prp)
		return NULL;
	*nextprid = PRID_INVALID;

	if (prp_totlen(prp) < 8) {
		prp->error = PRP_ERR_TOOSMALL;
	} else {
		prp_poff(prp) = prp_soff(prp) + 8;
		/* check for short ether-ip ARP packet */
		arp = prp_header(prp, buf, struct arph);
		if (arp->hwlen * 2 + arp->prlen * 2 > prp_plen(prp)) {
			prp->error |= PRP_ERR_LENGTH;
			return prp;
		} else if (arp->hwlen * 2 + arp->prlen * 2 < prp_plen(prp)) {
			prp_eoff(prp) = prp_toff(prp) = 
				prp_poff(prp) + arp->hwlen * 2 + arp->prlen * 2;
		}
		if (!memcmp(ethiparpstr, arp, sizeof(ethiparpstr))) {
			prp->offs[PRP_ARPFLD_ETHARP] = prp_soff(prp);
		}
	}
	return prp;
}


static void arp_update(struct prparse *prp, byte_t *buf)
{
	struct arph *arp;
	prp->error = 0;
	resetxfields(prp);

	if (prp_totlen(prp) < 8) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}
	prp_poff(prp) = prp_soff(prp) + 8;
	resetxfields(prp);
	arp = prp_header(prp, buf, struct arph);
	if (arp->hwlen * 2 + arp->prlen * 2 != prp_plen(prp)) {
		prp->error |= PRP_ERR_LENGTH;
		return;
	} 
	if (!memcmp(ethiparpstr, arp, sizeof(ethiparpstr))) {
		prp->offs[PRP_ARPFLD_ETHARP] = prp_soff(prp);
	}
}


static int arp_fixlen(struct prparse *prp, byte_t *buf)
{
	if (prp_hlen(prp) < 8)
		return -1;
	return 0;
}


static struct prparse *arp_add(ulong off, ulong len, ulong hlen, ulong plen,
			       byte_t *buf, int mode)
{
	struct prparse *prp;
	struct arph *arp;
	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len);
	if ((mode != PRP_ADD_FILL) || (len < 8))
		return NULL;
	prp = crtprp(sizeof(struct arp_parse), PRID_ARP, off, 8, len - 8, 0,
		     &arp_prparse_ops, PRP_ARP_NXFIELDS);
	if (prp && buf) {
		memset(buf + off, 0, prp_totlen(prp));
		if (prp_plen(prp) >= 20) {
			prp_toff(prp) = prp_eoff(prp) = prp_poff(prp) + 20;
			prp->offs[PRP_ARPFLD_ETHARP] = prp_soff(prp);
			arp = prp_header(prp, buf, struct arph);
			pack(&arp, 8, "hhbbh", ARPT_ETHERNET, ETHTYPE_IP, 6, 4,
			     ARPOP_REQUEST);
		}
	}
	return prp;
}

static struct prparse *arp_copy(struct prparse *oprp)
{
	return simple_copy(oprp, sizeof(struct arp_parse));
}


/* -- ops for IPV4 type -- */
static int ipv4_parse_opt(struct prparse *prp, byte_t *op, size_t olen)
{
	byte_t *osave = op;
	uint oc;
	uint oidx;
	uint t;
	ulong ooff = prp_soff(prp) + 20;

	while (olen > 0) {
		/* check for type 1 options first */
		oc = *op;
		if (oc == IPOPT_EOP) {
			return 0;
		} else if (oc == IPOPT_NOP) {
			olen -= 1;
			++op;
			continue;
		} else if ((olen < 2) || (olen < op[1])) {
			goto err;
		}

		/* check type 2 options */
		switch(oc) {
		case IPOPT_RR:
		case IPOPT_LSR:
		case IPOPT_SSR:
			if ((op[1] < 7) || ((op[1] & 3) != 3)) {
				prp->error |= PRP_ERR_OPTERR;
				return -1;
			}
			if (oc == IPOPT_RR) {
				oidx = PRP_IPFLD_RR;
			} else if (oc == IPOPT_LSR) {
				oidx = PRP_IPFLD_LSR;
			} else {
				oidx = PRP_IPFLD_SRR;
			}
			if (prp->offs[oidx] != PRP_OFF_INVALID)
				goto err;
			prp->offs[oidx] = ooff + (op - osave);
			break;
		case IPOPT_TS:
			if ((prp->offs[PRP_IPFLD_TS] != PRP_OFF_INVALID) ||
			    (op[1] < 4) || (op[1] > 40))
				goto err;
			t = (op[3] & 0xF);
			if ((t != 0) && (t != 1) && (t != 3))
				goto err;
			if (((t == 0) && ((op[2] % 4) != 1)) ||
			    ((t != 0) && ((op[2] % 8) != 5)))
				goto err;
			prp->offs[PRP_IPFLD_TS] = ooff + (op - osave);
			break;
		case IPOPT_SID:
			if (op[1] != 4)
				goto err;
		case IPOPT_SEC:
			if (op[1] < 3)
				goto err;
			break;
		case IPOPT_RA:
			if ((prp->offs[PRP_IPFLD_RA] != PRP_OFF_INVALID) ||
			    (op[1] != 4))
				goto err;
			prp->offs[PRP_IPFLD_RA] = ooff + (op - osave);
			break;
		}

		olen -= op[1];
		op += op[1];
	}

	return 0;
err:
	prp->error |= PRP_ERR_OPTERR;
	return -1;
}


static struct prparse *ipv4_parse(struct prparse *pprp, byte_t *buf,
				  uint *nextprid)
{
	struct prparse *prp;
	struct ipv4h *ip;
	int hlen, tlen;
	ushort iplen;
	uint16_t sum;

	prp = newprp(sizeof(struct ip_parse), PRID_IPV4, pprp, &ipv4_prparse_ops,
		     PRP_IP_NXFIELDS);
	if (!prp)
		return NULL;

	ip = prp_header(prp, buf, struct ipv4h);
	hlen = IPH_HLEN(*ip);
	tlen = prp_totlen(prp);
	if (tlen < 20) {
		prp->error |= PRP_ERR_TOOSMALL;
		*nextprid = PRID_INVALID;
	} else if (hlen > tlen) {
		prp->error |= PRP_ERR_HLEN;
		*nextprid = PRID_INVALID;
	} else {
		if ((ip->vhl & 0xf0) != 0x40)
			prp->error |= PRP_ERR_INVALID;
		prp_poff(prp) = prp_soff(prp) + hlen;
		unpack(&ip->len, 2, "h", &iplen);
		if (iplen > prp_totlen(prp))
			prp->error |= PRP_ERR_LENGTH;
		/* check whether datagram is smaller than enclosing packet */
		if (iplen < prp_totlen(prp)) {
			prp_eoff(prp) = prp_toff(prp) = prp_soff(prp) + iplen;
		}
		sum = ~ones_sum(ip, hlen, 0);
		if (sum != 0) {
			prp->error |= PRP_ERR_CKSUM;
			return prp;
		}
		if (ip->fragoff != 0) {
			uint16_t fragoff = ntoh32(ip->fragoff);
			if ((uint32_t) IPH_FRAGOFF(fragoff) + iplen > 65535)
				prp->error |= PRP_ERR_INVALID;
			if ((IPH_RFMASK & fragoff))
				prp->error |= PRP_ERR_INVALID;
		}
		if (hlen > 20) {
			if (ipv4_parse_opt(prp, (byte_t*)(ip+1), hlen-20) < 0)
				return prp;
		}
		*nextprid = PRID_BUILD(PRID_PF_INET, ip->proto);
	}
	return prp;
}


static struct prparse *ipv4_add(ulong off, ulong len, ulong hlen, ulong plen,
				byte_t *buf, int mode)
{
	struct prparse *prp;
	struct ipv4h *ip;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len);

	if (mode == PRP_ADD_FILL) {
		if ((len < 20) || (len > 65535))
			return NULL;
		hlen = 20;
		plen = len - 20;
	} else if (mode == PRP_ADD_WRAP) {
		if (hlen < 20)
			return NULL;
		if (plen > 65515)
			plen = 65515;
		hlen = 20;
		off -= 20;
	} else {
		abort_unless(mode == PRP_ADD_WRAPFILL);
		if ((hlen < 20) || (hlen > 60) || ((hlen & 0x3) != 0) ||
		    (len != plen + hlen) || (len > 65535))
			return NULL;
	}
	prp = crtprp(sizeof(struct ip_parse), PRID_IPV4, off, hlen, plen, 0,
		     &ipv4_prparse_ops, PRP_IP_NXFIELDS);
	if (prp && buf) {
		ip = prp_header(prp, buf, struct ipv4h);
		memset(ip, 0, prp_hlen(prp));
		ip->vhl = 0x40 | (hlen >> 2);
		ip->len = hton16(prp_totlen(prp));
		if (hlen > 20) {
			byte_t *p = (byte_t *)(ip + 1);
			byte_t *end = p + hlen - 20;
			while (p < end)
				*p++ = IPOPT_NOP;
		}
	}

	return prp;
}


static void ipv4_update(struct prparse *prp, byte_t *buf)
{
	ushort iplen;
	struct ipv4h *ip;
	ulong tlen;

	prp->error = 0;
	resetxfields(prp);
	ip = prp_header(prp, buf, struct ipv4h);

	if (IPH_VERSION(*ip) != 4)
		prp->error |= PRP_ERR_INVALID;

	tlen = prp_totlen(prp);
	if (tlen < 20) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}
	if ((IPH_HLEN(*ip) < 20) || (IPH_HLEN(*ip) != prp_hlen(prp))) {
		prp->error |= PRP_ERR_HLEN;
		return;
	}
	unpack(&ip->len, 2, "h", &iplen);
	if (tlen != iplen) {
		prp->error |= PRP_ERR_LENGTH;
		return;
	}
	if (prp_hlen(prp) > 20) {
		if (ipv4_parse_opt(prp, (byte_t *)(ip+1), prp_hlen(prp)-20)) {
			return;
		}
	}
}


static int ipv4_fixlen(struct prparse *prp, byte_t *buf)
{
	struct ipv4h *ip;
	long hlen;
	ushort tlen;

	abort_unless(prp);

	ip = prp_header(prp, buf, struct ipv4h);
	hlen = prp_hlen(prp);
	if ((hlen < 20) || (hlen > 60) || (hlen > prp_totlen(prp)))
		return -1;
	ip->vhl = 0x40 | (hlen >> 2);
	if (prp_totlen(prp) > 65535)
		return -1;
	tlen = prp_totlen(prp);
	pack(&ip->len, 2, "h", tlen);
	return 0;
}


static int ipv4_fixcksum(struct prparse *prp, byte_t *buf)
{
	long hlen;
	struct ipv4h *ip;

	abort_unless(prp);
	ip = prp_header(prp, buf, struct ipv4h);
	hlen = IPH_HLEN(*ip);
	if (hlen < 20)
		return -1;
	ip->cksum = 0;
	ip->cksum = ~ones_sum(ip, IPH_HLEN(*ip), 0);

	return 0;
}


static struct prparse *ipv4_copy(struct prparse *oprp)
{
	return simple_copy(oprp, sizeof(struct ip_parse));
}


static void ipv4_free(struct prparse *prp)
{
	freeprp(prp);
}


static uint16_t pseudo_cksum(struct prparse *prp, byte_t *buf, uint8_t proto)
{
	struct prparse *pprp = prp->region;
	uint16_t sum = 0;
	if (pprp->prid == PRID_IPV4) {
		struct pseudoh ph;
		struct ipv4h *ip = prp_header(pprp, buf, struct ipv4h);
		memset(&ph, 0, sizeof(ph));
		ph.saddr = ip->saddr;
		ph.daddr = ip->daddr;
		ph.proto = proto;
		ph.totlen = ntoh16(prp_totlen(prp));
		sum = ones_sum(&ph, 12, 0);
	} else {
		struct pseudo6h ph;
		struct ipv6h *ip6 = prp_header(pprp, buf, struct ipv6h);
		abort_unless(pprp->prid == PRID_IPV6);
		memset(&ph, 0, sizeof(ph));
		ph.saddr = ip6->saddr;
		ph.daddr = ip6->daddr;
		ph.proto = proto;
		ph.totlen = ntoh32(prp_totlen(prp));
		sum = ones_sum(&ph, 40, 0);
	}
	return ~ones_sum(prp_header(prp, buf, void), prp_totlen(prp), sum);
}


/* -- parse options for UDP protocol -- */
static struct prparse *udp_parse(struct prparse *pprp, byte_t *buf,
				 uint *nextprid)
{
	struct prparse *prp;
	struct udph *udp;
	ushort ulen;

	switch (pprp->prid) {
	case PRID_IPV4:
	case PRID_IPV6:
		break;
	default:
		return NULL;
	}
	prp = newprp(sizeof(*prp), PRID_UDP, pprp, &udp_prparse_ops, 0);
	if (!prp)
		return NULL;
	*nextprid = PRID_INVALID;
	if (prp_totlen(prp) < 8) {
		prp->error |= PRP_ERR_TOOSMALL;
	} else if ((pprp->error & PRP_ERR_LENGTH)) {
		prp_poff(prp) = prp_soff(prp) + 8;
		prp->error |= PRP_ERR_LENGTH | PRP_ERR_CKSUM;
	} else {
		prp_poff(prp) = prp_soff(prp) + 8;
		udp = prp_header(prp, buf, struct udph);

		unpack(&udp->len, 2, "h", &ulen);
		if (prp_totlen(prp) < ulen)
			prp->error |= PRP_ERR_LENGTH;

		if ((udp->cksum != 0) && (pseudo_cksum(prp, buf, IPPROT_UDP) != 0))
			prp->error |= PRP_ERR_CKSUM;
	}
	return prp;
}


static struct prparse *udp_add(ulong off, ulong len, ulong hlen, ulong plen,
			       byte_t *buf, int mode)
{
	struct prparse *prp;
	struct udph *udp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len);

	if (mode == PRP_ADD_FILL) {
		if (len < 8)
			return NULL;
		hlen = 8;
		plen = len - 8;
		if (plen > 65527)
			return NULL;
	} else if (mode == PRP_ADD_WRAP) {
		if (hlen < 8)
			return NULL;
		hlen = 8;
		off -= 8;
		if (plen > 65527)
			plen = 65527;
	} else {
		abort_unless(mode == PRP_ADD_WRAPFILL);
		if ((hlen != 8) || (plen > 65527) || (len != hlen + plen))
			return NULL;
	}
	prp = crtprp(sizeof(*prp), PRID_UDP, off, hlen, plen, 0,
		     &udp_prparse_ops, 0);
	if (prp && buf) {
		udp = prp_header(prp, buf, struct udph);
		memset(udp, 0, sizeof(*udp));
		pack(&udp->len, 2, "h", (ushort) prp_totlen(prp));
	}
	return prp;
}


static void udp_update(struct prparse *prp, byte_t *buf)
{
	ushort ulen;
	struct udph *udp;
	if (prp_totlen(prp) < 8) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 8) {
		prp->error = PRP_ERR_HLEN;
		return;
	}
	udp = prp_header(prp, buf, struct udph);
	unpack(&udp->len, 2, "h", &ulen);
	if (prp_totlen(prp) < ulen)
		prp->error |= PRP_ERR_LENGTH;
	if ((udp->cksum != 0) && (pseudo_cksum(prp, buf, IPPROT_UDP) != 0))
		prp->error |= PRP_ERR_CKSUM;
}


static int udp_fixlen(struct prparse *prp, byte_t *buf)
{
	if (prp_hlen(prp) != 8)
		return -1;
	if (prp_plen(prp) > 65527)
		return -1;
	pack(&prp_header(prp, buf, struct udph)->len, 2, "h",
	     (ushort)prp_totlen(prp));
	return 0;
}


static int udp_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct udph *udp = prp_header(prp, buf, struct udph);
	abort_unless(prp->region);
	if ((prp_hlen(prp) != 8) ||
	    ((prp->region->prid != PRID_IPV4) &&
	     (prp->region->prid != PRID_IPV6)))
		return -1;
	udp->cksum = 0;
	udp->cksum = pseudo_cksum(prp, buf, IPPROT_UDP);
	return 0;
}


/* -- TCP functions -- */
static int tcp_parse_opt(struct prparse *prp, struct tcph *tcp, size_t olen)
{
	uint oc;
	ulong ooff = prp_soff(prp) + 20;
	byte_t *op = (byte_t *)(tcp + 1);
	byte_t *osave = op;

	while (olen > 0) {
		/* Check for type 1 options first */
		oc = *op;
		if (oc == TCPOPT_EOP) {
			return 0;
		} else if (oc == TCPOPT_NOP) {
			olen -= 1;
			++op;
			continue;
		} else if ((olen < 2) || (olen < op[1])) {
			goto err;
		}

		/* Check type 2 options */
		switch(oc) {
		case TCPOPT_MSS:
			if ((op[1] != 4) || ((tcp->flags & TCPF_SYN) == 0) ||
			    (prp->offs[PRP_TCPFLD_MSS] != PRP_OFF_INVALID))
				goto err;
			prp->offs[PRP_TCPFLD_MSS] = ooff + (op - osave);
			break;
		case TCPOPT_WSCALE:
			if ((op[1] != 3) || ((tcp->flags & TCPF_SYN) == 0) ||
			    (prp->offs[PRP_TCPFLD_WSCALE] != PRP_OFF_INVALID) ||
			    (op[2] > 14))
				goto err;
			prp->offs[PRP_TCPFLD_WSCALE] = ooff + (op - osave);
			break;
		case TCPOPT_SACKOK:
			if ((op[1] != 2) || ((tcp->flags & TCPF_SYN) == 0) ||
			    (prp->offs[PRP_TCPFLD_SACKOK] != PRP_OFF_INVALID))
				goto err;
			prp->offs[PRP_TCPFLD_SACKOK] = ooff + (op - osave);
			break;
		case TCPOPT_SACK:
			if ((op[1] < 10) || (((op[1] - 2) & 7) != 0) ||
			    (prp->offs[PRP_TCPFLD_SACK] != PRP_OFF_INVALID))
				goto err;
			prp->offs[PRP_TCPFLD_SACK] = ooff + (op - osave);
			prp->offs[PRP_TCPFLD_SACK_END] = 
				prp->offs[PRP_TCPFLD_SACK] + op[1];
			break;
		case TCPOPT_TSTAMP:
			if ((op[1] != 10) ||
			    (prp->offs[PRP_TCPFLD_TSTAMP] != PRP_OFF_INVALID))
				goto err;
			prp->offs[PRP_TCPFLD_TSTAMP] = ooff + (op - osave);
			break;
		case TCPOPT_MD5:
			if ((op[1] != 18) ||
			    (prp->offs[PRP_TCPFLD_MD5] != PRP_OFF_INVALID))
				goto err;
			prp->offs[PRP_TCPFLD_MD5] = ooff + (op - osave);
			break;
		}

		olen -= op[1];
		op += op[1];
	}

	return 0;
err:
	prp->error |= PRP_ERR_OPTERR;
	return -1;
}


static struct prparse *tcp_parse(struct prparse *pprp, byte_t *buf,
				 uint *nextprid)
{
	struct prparse *prp;
	struct tcph *tcp;
	int hlen, tlen;

	switch (pprp->prid) {
	case PRID_IPV4:
	case PRID_IPV6:
		break;
	default:
		return NULL;
	}

	prp = newprp(sizeof(struct tcp_parse), PRID_TCP, pprp, &tcp_prparse_ops,
		     PRP_TCP_NXFIELDS);
	if (!prp)
		return NULL;
	*nextprid = PRID_INVALID;
	tcp = prp_header(prp, buf, struct tcph);
	hlen = TCPH_HLEN(*tcp);
	tlen = prp_totlen(prp);
	if (tlen < 20) {
		prp->error |= PRP_ERR_TOOSMALL;
	} else if (hlen > tlen) {
		prp->error |= PRP_ERR_HLEN;
	} else if ((pprp->error & PRP_ERR_LENGTH)) {
		prp_poff(prp) = prp_soff(prp) + hlen;
		prp->error |= PRP_ERR_LENGTH | PRP_ERR_CKSUM;
	} else {
		prp_poff(prp) = prp_soff(prp) + hlen;
		if (pseudo_cksum(prp, buf, IPPROT_TCP) != 0)
			prp->error |= PRP_ERR_CKSUM;
		if (hlen > 20) {
			if (tcp_parse_opt(prp, tcp, hlen-20) < 0)
				return prp;
		}
	}
	return prp;
}


static struct prparse *tcp_add(ulong off, ulong len, ulong hlen, ulong plen,
			       byte_t *buf, int mode)
{
	struct prparse *prp;
	struct tcph *tcp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len);

	if (mode == PRP_ADD_FILL) {
		if (len < 20)
			return NULL;
		hlen = 20;
		plen = len - 20;
	} else if (mode == PRP_ADD_WRAP) {
		if (hlen < 20)
			return NULL;
		hlen = 20;
		off -= 20;
		len = plen + hlen;
	} else {
		abort_unless(mode == PRP_ADD_WRAPFILL);
		if ((hlen < 20) || (hlen > 60) || ((hlen & 3) != 0) ||
		    (len != hlen + plen))
			return NULL;
	}
	prp = crtprp(sizeof(struct tcp_parse), PRID_TCP, off, hlen, plen, 0,
		     &tcp_prparse_ops, PRP_TCP_NXFIELDS);
	if (prp && buf) {
		memset(prp_header(prp, buf, void), 0, prp_hlen(prp));
		tcp = prp_header(prp, buf, struct tcph);
		tcp->doff = hlen << 2;
	}
	return prp;
}


static void tcp_update(struct prparse *prp, byte_t *buf)
{
	struct tcph *tcp;
	uint hlen;

	prp->error = 0;
	resetxfields(prp);
	tcp = prp_header(prp, buf, struct tcph);
	hlen = TCPH_HLEN(*tcp);

	if (prp_totlen(prp) < 20) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}
	if ((prp_hlen(prp) < 20) || (prp_hlen(prp) != hlen)) {
		prp->error = PRP_ERR_HLEN;
		return;
	}
	if (pseudo_cksum(prp, buf, IPPROT_TCP) != 0)
		prp->error |= PRP_ERR_CKSUM;
	if (hlen > 20) {
		if (tcp_parse_opt(prp, tcp, hlen-20) < 0)
			return;
	}
}


static int tcp_fixlen(struct prparse *prp, byte_t *buf)
{
	struct tcph *tcp;
	long hlen;

	abort_unless(prp);
	tcp = prp_header(prp, buf, struct tcph);
	hlen = prp_hlen(prp);
	if ((hlen < 20) || (hlen > 60) || (hlen > prp_totlen(prp)))
		return -1;
	tcp->doff = hlen << 2;

	return 0;
}


static int tcp_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct tcph *tcp;

	abort_unless(prp);
	abort_unless(prp->region);
	tcp = prp_header(prp, buf, struct tcph);
	if ((prp->region->prid != PRID_IPV4) && 
	    (prp->region->prid != PRID_IPV6))
		return -1;
	tcp->cksum = 0;
	tcp->cksum = pseudo_cksum(prp, buf, IPPROT_TCP);
	return 0;
}


static struct prparse *tcp_copy(struct prparse *oprp)
{
	return simple_copy(oprp, sizeof(struct tcp_parse));
}


static void tcp_free(struct prparse *prp)
{
	freeprp(prp);
}


/* -- ICMP Protocol functions -- */
static struct prparse *icmp_parse(struct prparse *pprp, byte_t *buf,
				  uint *nextprid)
{
	struct prparse *prp;
	struct icmph *icmp;
	uint16_t csum;

	prp = newprp(sizeof(*prp), PRID_ICMP, pprp, &icmp_prparse_ops, 0);
	if (!prp)
		return NULL;
	*nextprid = PRID_INVALID;

	if (prp_totlen(prp) < 8) {
		prp->error |= PRP_ERR_TOOSMALL;
		goto done;
	}
	if ((pprp->error & PRP_ERR_LENGTH)) {
		prp_poff(prp) = prp_soff(prp) + 8;
		prp->error |= PRP_ERR_LENGTH;
		prp->error |= PRP_ERR_CKSUM;
		goto done;
	} else {
		prp_poff(prp) = prp_soff(prp) + 8;
		icmp = prp_header(prp, buf, struct icmph);
		csum = ~ones_sum(icmp, prp_totlen(prp), 0);
		if (csum)
			prp->error |= PRP_ERR_CKSUM;
	}
	/* types which can have a returned IP header in them */
	if ((icmp->type == ICMPT_DEST_UNREACH) ||
	    (icmp->type == ICMPT_TIME_EXCEEDED) ||
	    (icmp->type == ICMPT_PARAM_PROB) ||
	    (icmp->type == ICMPT_SRC_QUENCH) ||
	    (icmp->type == ICMPT_REDIRECT)) {
		*nextprid = PRID_IPV4;
	}

done:
	return prp;
}


static struct prparse *icmp_add(ulong off, ulong len, ulong hlen, ulong plen,
				byte_t *buf, int mode)
{
	struct prparse *prp;
	struct icmph *icmp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len);

	if (mode == PRP_ADD_FILL) {
		if (len < 8)
			return NULL;
		hlen = 8;
		plen = len - 8;
	} else if (mode == PRP_ADD_WRAP) {
		if (hlen < 8)
			return NULL;
		hlen = 8;
		off -= 8;
	} else {
		abort_unless(mode == PRP_ADD_WRAPFILL);
		if ((hlen != 8) || (len != hlen + plen))
			return NULL;
	}
	prp = crtprp(sizeof(struct prparse), PRID_ICMP, off, hlen, plen, 0, 
		     &icmp_prparse_ops, 0);
	if (prp && buf) {
		icmp = prp_header(prp, buf, struct icmph);
		memset(icmp, 0, sizeof(*icmp));
	}
	return prp;
}


static void icmp_update(struct prparse *prp, byte_t *buf)
{
	struct icmph *icmp;

	prp->error = 0;
	resetxfields(prp);

	if (prp_totlen(prp) < 8) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 8) {
		prp->error = PRP_ERR_HLEN;
		return;
	}

	icmp = prp_header(prp, buf, struct icmph);
	if (ones_sum(icmp, prp_totlen(prp), 0))
		prp->error |= PRP_ERR_CKSUM;

	/* TODO: check by type? */
}


static int icmp_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct icmph *icmp = prp_header(prp, buf, struct icmph);
	if ((prp_hlen(prp) != 8) || (prp->region->prid != PRID_IPV4))
		return -1;
	icmp->cksum = 0;
	icmp->cksum = ~ones_sum(icmp, prp_totlen(prp), 0);
	return 0;
}


/* -- IPv6 functions -- */
static int isv6ext(uint8_t proto)
{
	/* we consider IPsec protocols their own protocol */
	return (proto == IPPROT_V6_HOPOPT) ||
	    (proto == IPPROT_V6_ROUTE_HDR) ||
	    (proto == IPPROT_V6_FRAG_HDR) ||
	    (proto == IPPROT_V6_DSTOPS) || (proto == IPPROT_AH);
}


/* search for jumbogram options */
static int parse_ipv6_hopopt(struct ipv6_parse *ip6prp, struct ipv6h *ip6,
			     byte_t *p, long olen)
{
	byte_t *end = p + olen;

	abort_unless(olen >= 0);

	p += 2;
	while (p < end) {
		if (*p == 0) {	/* pad1 option */
			++p;
			continue;
		}
		if (p + p[1] + 2 > end) {	/* padn + all other options */
			ip6prp->prp.error |= PRP_ERR_OPTLEN;
			return -1;
		}
		if (*p == 0xC2) {	/* jumbogram option */
			if ((p[1] != 4) || (ip6->len != 0)
			    || (ip6prp->jlenoff > 0)
			    || (((p - (byte_t *) ip6) & 3) != 2)) {
				ip6prp->prp.error |= PRP_ERR_OPTERR;
				return -1;
			}
			ip6prp->jlenoff = p - (byte_t *) ip6;
		}
		p += p[1] + 2;
	}
	return 0;
}


static int parse_ipv6_opt(struct ipv6_parse *ip6prp, struct ipv6h *ip6,
			  long len)
{
	size_t xlen = 0;
	uint8_t nexth;
	uint olen;
	byte_t *p;

	abort_unless(len >= 0);

	nexth = ip6->nxthdr;
	p = (byte_t *) ip6 + 40;

	while (isv6ext(nexth)) {
		if ((xlen + 8 < xlen) || (xlen + 8 > len)) {
			ip6prp->prp.error |= PRP_ERR_OPTLEN;
			return -1;
		}
		if (nexth == IPPROT_AH)	/* AH is idiotic and useless */
			olen = (p[1] << 2) + 8;
		else
			olen = (p[1] << 3) + 8;
		if ((xlen + olen < xlen) || (xlen + olen > len)) {
			ip6prp->prp.error |= PRP_ERR_OPTLEN;
			return -1;
		}
		/* hop-by-hop options can only come first */
		if (nexth == IPPROT_V6_HOPOPT) {
			if (p != (byte_t *) ip6 + 40) {
				ip6prp->prp.error |= PRP_ERR_OPTERR;
			} else {
				if (parse_ipv6_hopopt(ip6prp, ip6, p, olen) < 0)
					return -1;
			}
		}

		nexth = p[0];
		xlen += olen;
		p += olen;
	}

	prp_poff(&ip6prp->prp) = prp_soff(&ip6prp->prp) + 40 + xlen;
	ip6prp->nexth = nexth;

	return 0;
}


static struct prparse *ipv6_parse(struct prparse *pprp, byte_t *buf,
				  uint *nextprid)
{
	struct prparse *prp;
	struct ipv6_parse *ip6prp;
	struct ipv6h *ip6;
	ushort paylen;
	ulong tlen;

	prp = newprp(sizeof(struct ipv6_parse), PRID_IPV6, pprp,
		     &ipv6_prparse_ops, 0);
	ip6prp = (struct ipv6_parse *)prp;
	if (!prp)
		return NULL;
	*nextprid = PRID_INVALID;
	ip6prp->nexth = 0;
	ip6prp->jlenoff = 0;
	ip6 = prp_header(prp, buf, struct ipv6h);

	if (IPV6H_PVERSION(ip6) != 6) {
		prp->error |= PRP_ERR_INVALID;
		goto done;
	}

	tlen = prp_totlen(prp);
	if (tlen < 40) {
		prp->error |= PRP_ERR_TOOSMALL;
		goto done;
	}

	unpack(&ip6->len, 2, "h", &paylen);
	if (tlen < paylen + 40) {
		prp->error |= PRP_ERR_LENGTH;
		goto done;
	}

	if (tlen > paylen + 40) {
		ulong extra = tlen - paylen - 40;
		prp_eoff(prp) = prp_toff(prp) = prp_soff(prp) + 40 + paylen;
		tlen -= extra;
	}

	/* sets hlen */
	if (parse_ipv6_opt(ip6prp, ip6, tlen - 40) < 0)
		goto done;

	if ((paylen == 0) && (ip6prp->jlenoff > 0)) {
		unsigned long jlen;
		unpack(prp_payload(prp, buf) + ip6prp->jlenoff, 4, "w", &jlen);
		if ((jlen != prp_totlen(prp) - 40) || (jlen < 65536))
			prp->error |= PRP_ERR_LENGTH;
	} else if (tlen > (uint32_t)paylen + 40) {
		prp_toff(prp) = prp_soff(prp) + 40 + paylen;
	}
	*nextprid = PRID_BUILD(PRID_PF_INET, ip6prp->nexth);

done:
	return prp;
}


static struct prparse *ipv6_add(ulong off, ulong len, ulong hlen, ulong plen,
				byte_t *buf, int mode)
{
	struct prparse *prp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len);

	if (mode == PRP_ADD_FILL) {
		/* TODO support jumbo frames ? */
		if ((len < 40) || (len > 65575))
			return NULL;
		hlen = 40;
		plen = len - 40;
	} else if (mode == PRP_ADD_WRAP) {
		if (hlen < 40)
			return NULL;
		if (plen > 65535)
			len = 65535;
		hlen = 40;
		off -= 40;
	} else {
		abort_unless(mode == PRP_ADD_WRAPFILL);
		if ((hlen != 40) || (plen > 65535) || (hlen + plen != len))
			return NULL;
	}
	prp = crtprp(sizeof(struct ipv6_parse), PRID_IPV6, off, hlen, plen, 0,
		     &ipv6_prparse_ops, 0);
	if (prp && buf) {
		struct ipv6_parse *ip6prp = (struct ipv6_parse *)prp;
		struct ipv6h *ip6 = prp_header(prp, buf, struct ipv6h);
		ip6prp->nexth = 0;
		ip6prp->jlenoff = 0;
		memset(ip6, 0, prp_hlen(prp));
		*(byte_t *) ip6 = 0x60;
		ip6->len = hton16(prp_totlen(prp));
	}
	return prp;
}


static void ipv6_update(struct prparse *prp, byte_t *buf)
{
	struct ipv6_parse *ip6prp;
	ushort paylen;
	ulong tlen;
	struct ipv6h *ip6;

	prp->error = 0;
	resetxfields(prp);
	ip6prp = (struct ipv6_parse *)prp;
	ip6 = prp_header(prp, buf, struct ipv6h);

	if (IPV6H_PVERSION(ip6) != 6)
		prp->error |= PRP_ERR_INVALID;

	tlen = prp_totlen(prp);
	if (tlen < 40) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 40) {
		prp->error = PRP_ERR_HLEN;
		return;
	}
	unpack(&ip6->len, 2, "h", &paylen);
	if (tlen < (uint32_t)paylen + 40) {
		prp->error |= PRP_ERR_LENGTH;
		return;
	}

	if (parse_ipv6_opt(ip6prp, ip6, tlen - 40) < 0)
		return;

	if ((paylen == 0) && (ip6prp->jlenoff > 0)) {
		unsigned long jlen;
		unpack(prp_payload(prp, buf) + ip6prp->jlenoff, 4, "w", &jlen);
		if ((jlen != prp_totlen(prp) - 40) || (jlen < 65536))
			prp->error |= PRP_ERR_LENGTH;
	}
}


static int ipv6_fixlen(struct prparse *prp, byte_t *buf)
{
	struct ipv6h *ip6;
	ushort plen;
	abort_unless(prp);
	ip6 = prp_header(prp, buf, struct ipv6h);
	if (prp_plen(prp) > 65535)
		return -1;
	plen = prp_plen(prp);
	pack(&ip6->len, 2, "h", plen);
	return 0;
}


static struct prparse *ipv6_copy(struct prparse *oprp)
{
	return simple_copy(oprp, sizeof(struct ipv6_parse));
}


static void ipv6_free(struct prparse *prp)
{
	freeprp(prp);
}


/* -- ICMPv6 Functions -- */
static struct prparse *icmp6_parse(struct prparse *pprp, byte_t *buf,
				   uint *nextprid)
{
	struct prparse *prp;
	struct icmp6h *icmp6;

	prp = newprp(sizeof(*prp), PRID_ICMP6, pprp, &icmpv6_prparse_ops, 0);
	if (!prp)
		return NULL;
	*nextprid = PRID_INVALID;
	if (prp_totlen(prp) < 8) {
		prp->error |= PRP_ERR_TOOSMALL;
		goto done;
	}
	if ((pprp->error & PRP_ERR_LENGTH)) {
		prp_poff(prp) = prp_soff(prp) + 8;
		prp->error |= PRP_ERR_LENGTH;
		prp->error |= PRP_ERR_CKSUM;
	} else {
		abort_unless(pprp->prid == PRID_IPV6);
		prp_poff(prp) = prp_soff(prp) + 8;
		if (pseudo_cksum(prp, buf, IPPROT_ICMPV6) != 0)
			prp->error |= PRP_ERR_CKSUM;
	}
	icmp6 = prp_header(pprp, buf, struct icmp6h);
	if ((icmp6->type == ICMP6T_DEST_UNREACH) ||
	    (icmp6->type == ICMP6T_PKT_TOO_BIG) ||
	    (icmp6->type == ICMP6T_TIME_EXCEEDED) ||
	    (icmp6->type == ICMP6T_PARAM_PROB))
		*nextprid = PRID_IPV6;

 done:
	return prp;
}


static struct prparse *icmp6_add(ulong off, ulong len, ulong hlen, ulong plen,
				 byte_t *buf, int mode)
{
	struct prparse *prp;
	struct icmp6h *icmp6;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len);

	if (mode == PRP_ADD_FILL) {
		if (len < 8)
			return NULL;
		hlen = 8;
		plen = len - 8;
	} else if (mode == PRP_ADD_WRAP) {
		if (hlen < 8)
			return NULL;
		hlen = 8;
		off -= 8;
	} else {
		abort_unless(mode == PRP_ADD_WRAPFILL);
		if ((hlen != 8) || (len != hlen + plen))
			return NULL;
	}
	prp = crtprp(sizeof(struct prparse), PRID_ICMP6, off, hlen, plen, 0,
		     &icmpv6_prparse_ops, 0);
	if (prp && buf) {
		icmp6 = prp_header(prp, buf, struct icmp6h);
		memset(icmp6, 0, sizeof(*icmp6));
	}
	return prp;
}


static void icmp6_update(struct prparse *prp, byte_t *buf)
{
	prp->error = 0;
	resetxfields(prp);

	if (prp_totlen(prp) < 8) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 8) {
		prp->error = PRP_ERR_HLEN;
		return;
	}
	if (pseudo_cksum(prp, buf, IPPROT_ICMPV6) != 0)
		prp->error |= PRP_ERR_CKSUM;
	/* TODO: check by type? */
}


static int icmp6_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct icmp6h *icmp6 = prp_header(prp, buf, struct icmp6h);
	if ((prp_hlen(prp) != 8) || (prp->region->prid != PRID_IPV6))
		return -1;
	icmp6->cksum = 0;
	icmp6->cksum = pseudo_cksum(prp, buf, IPPROT_ICMPV6);
	return 0;
}


/* -- op structures for default initialization -- */
struct proto_parser_ops eth_proto_parser_ops = {
	eth_parse,
	eth_add
};

struct prparse_ops eth_prparse_ops = {
	eth_update,
	default_fixlen,
	default_fixcksum,
	default_copy,
	default_free
};

struct proto_parser_ops arp_proto_parser_ops = {
	arp_parse,
	arp_add
};

struct prparse_ops arp_prparse_ops = {
	arp_update,
	arp_fixlen,
	default_fixcksum,
	arp_copy,
	default_free
};

struct proto_parser_ops ipv4_proto_parser_ops = {
	ipv4_parse,
	ipv4_add
};

struct prparse_ops ipv4_prparse_ops = {
	ipv4_update,
	ipv4_fixlen,
	ipv4_fixcksum,
	ipv4_copy,
	ipv4_free
};

struct proto_parser_ops ipv6_proto_parser_ops = {
	ipv6_parse,
	ipv6_add
};

struct prparse_ops ipv6_prparse_ops = {
	ipv6_update,
	ipv6_fixlen,
	default_fixcksum,
	ipv6_copy,
	ipv6_free
};

struct proto_parser_ops icmp_proto_parser_ops = {
	icmp_parse,
	icmp_add
};

struct prparse_ops icmp_prparse_ops = {
	icmp_update,
	default_fixlen,
	icmp_fixcksum,
	default_copy,
	default_free
};

struct proto_parser_ops icmpv6_proto_parser_ops = {
	icmp6_parse,
	icmp6_add
};

struct prparse_ops icmpv6_prparse_ops = {
	icmp6_update,
	default_fixlen,
	icmp6_fixcksum,
	default_copy,
	default_free
};

struct proto_parser_ops udp_proto_parser_ops = {
	udp_parse,
	udp_add
};

struct prparse_ops udp_prparse_ops = {
	udp_update,
	udp_fixlen,
	udp_fixcksum,
	default_copy,
	default_free
};

struct proto_parser_ops tcp_proto_parser_ops = {
	tcp_parse,
	tcp_add
};

struct prparse_ops tcp_prparse_ops = {
	tcp_update,
	tcp_fixlen,
	tcp_fixcksum,
	tcp_copy,
	tcp_free
};




/* --------- Namespaces ---------- */

#define STDPROTO_NS_ELEN	64
#define STDPROTO_NS_SUB_ELEN	16

/* Ethernet Namespace */
extern struct ns_elem *stdproto_eth2_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace eth2_ns = 
	NS_NAMESPACE_I("eth", NULL, PRID_ETHERNET2, PRID_PCLASS_LINK,
		"Ethernet II -- Offset %lu, Length %lu",
		stdproto_eth2_ns_elems, array_length(stdproto_eth2_ns_elems));

static struct ns_pktfld eth2_ns_dst =
	NS_BYTEFIELD_I("dst", &eth2_ns, PRID_ETHERNET2, 0, 6,
		       "Destination Address: %s", &ns_fmt_etha);
static struct ns_pktfld eth2_ns_src =
	NS_BYTEFIELD_I("src", &eth2_ns, PRID_ETHERNET2, 6, 6,
		       "Source Address:      %s", &ns_fmt_etha);
static struct ns_pktfld eth2_ns_ethtype =
	NS_BYTEFIELD_IDX_I("ethtype", &eth2_ns, PRID_ETHERNET2, 
			PRP_ETHFLD_ETYPE, 0, 2,
		       "Ethernet Type:       %04x", &ns_fmt_num);

extern struct ns_elem *stdproto_eth2_vlan0_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_eth2_vlan1_ns_elems[STDPROTO_NS_SUB_ELEN];

static struct ns_namespace eth2_vlan0_ns = 
	NS_NAMESPACE_IDX_I("vlan0", &eth2_ns, PRID_ETHERNET2, PRID_NONE,
		PRP_ETHFLD_VLAN0, 4,
		"Ethernet VLAN 0 -- Length %lu, Offset %lu",
		stdproto_eth2_vlan0_ns_elems,
		array_length(stdproto_eth2_vlan0_ns_elems));
static struct ns_pktfld eth2_vlan0_tpid =
	NS_BYTEFIELD_IDX_I("tpid", &eth2_vlan0_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN0, 0, 2,
	       "Tag Proto ID:        %04x", &ns_fmt_num);
static struct ns_pktfld eth2_vlan0_pcp =
	NS_BITFIELD_IDX_I("pcp", &eth2_vlan0_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN0, 2, 0, 3,
	       "Priority Code Point: %u", &ns_fmt_num);
static struct ns_pktfld eth2_vlan0_cfi =
	NS_BITFIELD_IDX_I("cfi", &eth2_vlan0_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN0, 2, 3, 1,
	       "Canonical Field Ind: %u", &ns_fmt_num);
static struct ns_pktfld eth2_vlan0_vid =
	NS_BITFIELD_IDX_I("vid", &eth2_vlan0_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN0, 2, 4, 12,
	       "VLAN ID:             %u", &ns_fmt_num);
struct ns_elem *stdproto_eth2_vlan0_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&eth2_vlan0_tpid, (struct ns_elem *)&eth2_vlan0_pcp, 
	(struct ns_elem *)&eth2_vlan0_cfi, (struct ns_elem *)&eth2_vlan0_vid, 
};

static struct ns_namespace eth2_vlan1_ns = 
	NS_NAMESPACE_IDX_I("vlan1", &eth2_ns, PRID_ETHERNET2, PRID_NONE,
		PRP_ETHFLD_VLAN1, 4,
		"Ethernet VLAN 1 -- Length %lu, Offset %lu",
		stdproto_eth2_vlan1_ns_elems,
		array_length(stdproto_eth2_vlan1_ns_elems));
static struct ns_pktfld eth2_vlan1_tpid =
	NS_BYTEFIELD_IDX_I("tpid", &eth2_vlan1_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN1, 0, 2,
	       "Tag Proto ID:        %04x", &ns_fmt_num);
static struct ns_pktfld eth2_vlan1_pcp =
	NS_BITFIELD_IDX_I("pcp", &eth2_vlan1_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN1, 2, 0, 3,
	       "Priority Code Point: %u", &ns_fmt_num);
static struct ns_pktfld eth2_vlan1_cfi =
	NS_BITFIELD_IDX_I("cfi", &eth2_vlan1_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN1, 2, 3, 1,
	       "Canonical Field Ind: %u", &ns_fmt_num);
static struct ns_pktfld eth2_vlan1_vid =
	NS_BITFIELD_IDX_I("vid", &eth2_vlan1_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN1, 2, 4, 12,
	       "VLAN ID:             %u", &ns_fmt_num);
struct ns_elem *stdproto_eth2_vlan1_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&eth2_vlan1_tpid, (struct ns_elem *)&eth2_vlan1_pcp, 
	(struct ns_elem *)&eth2_vlan1_cfi, (struct ns_elem *)&eth2_vlan1_vid, 
};

struct ns_elem *stdproto_eth2_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&eth2_ns_dst, (struct ns_elem *)&eth2_ns_src,
	(struct ns_elem *)&eth2_ns_ethtype, (struct ns_elem *)&eth2_vlan0_ns,
	(struct ns_elem *)&eth2_vlan1_ns,
};


/* ARP Namespace */
extern struct ns_elem *stdproto_arp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace arp_ns = 
	NS_NAMESPACE_I("arp", NULL, PRID_ARP, PRID_PCLASS_NET,
	       "Address Resolution Protocol -- Offset %lu, Length %lu bytes",
	       stdproto_arp_ns_elems, array_length(stdproto_arp_ns_elems));

static struct ns_pktfld arp_ns_hwfmt =
	NS_BYTEFIELD_I("hwfmt", &arp_ns, PRID_ARP, 0, 2,
		"HW Address Format:    %lx", &ns_fmt_num);
static struct ns_pktfld arp_ns_prfmt =
	NS_BYTEFIELD_I("prfmt", &arp_ns, PRID_ARP, 2, 2,
		"Proto Address Format: %lx", &ns_fmt_num);
static struct ns_pktfld arp_ns_hwlen =
	NS_BYTEFIELD_I("hwlen", &arp_ns, PRID_ARP, 4, 1,
		"HW Address length:    %lu", &ns_fmt_num);
static struct ns_pktfld arp_ns_prlen =
	NS_BYTEFIELD_I("prlen", &arp_ns, PRID_ARP, 5, 1,
		"Proto Address length: %lu", &ns_fmt_num);
static struct ns_pktfld arp_ns_op =
	NS_BYTEFIELD_I("op", &arp_ns, PRID_ARP, 6, 2,
		"Operation:            %lu", &ns_fmt_num);
static struct ns_pktfld arp_ns_sndhwaddr =
	NS_BYTEFIELD_IDX_I("sndhwaddr", &arp_ns, PRID_ARP,
		PRP_ARPFLD_ETHARP, 8, 6, 
		"Sender HW Address:    %s", &ns_fmt_etha);
static struct ns_pktfld arp_ns_sndpraddr =
	NS_BYTEFIELD_IDX_I("sndpraddr", &arp_ns, PRID_ARP,
		PRP_ARPFLD_ETHARP, 14, 4, 
		"Sender IP Address:    %s", &ns_fmt_ipv4a);
static struct ns_pktfld arp_ns_trghwaddr =
	NS_BYTEFIELD_IDX_I("trghwaddr", &arp_ns, PRID_ARP,
		PRP_ARPFLD_ETHARP, 18, 6, 
		"Target HW Address:    %s", &ns_fmt_etha);
static struct ns_pktfld arp_ns_trgpraddr =
	NS_BYTEFIELD_IDX_I("trgpraddr", &arp_ns, PRID_ARP,
		PRP_ARPFLD_ETHARP, 24, 4, 
		"Target IP Address:    %s", &ns_fmt_ipv4a);

struct ns_elem *stdproto_arp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&arp_ns_hwfmt, (struct ns_elem *)&arp_ns_prfmt, 
	(struct ns_elem *)&arp_ns_hwlen, (struct ns_elem *)&arp_ns_prlen, 
	(struct ns_elem *)&arp_ns_op,
	(struct ns_elem *)&arp_ns_sndhwaddr, 
	(struct ns_elem *)&arp_ns_sndpraddr, 
	(struct ns_elem *)&arp_ns_trghwaddr, 
	(struct ns_elem *)&arp_ns_trgpraddr,
};


extern struct ns_elem *stdproto_ipv4_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace ipv4_ns = 
	NS_NAMESPACE_I("ip", NULL, PRID_IPV4, PRID_PCLASS_NET,
		"Internet Protocol Version 4 -- Offset %lu, Length %lu",
		stdproto_ipv4_ns_elems, array_length(stdproto_ipv4_ns_elems));

static struct ns_pktfld ipv4_ns_vers =
	NS_BITFIELD_I("vers", &ipv4_ns, PRID_IPV4, 0, 0, 4,
		"Version:              %lu", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_hlen =
	NS_BITFIELD_I("hlen", &ipv4_ns, PRID_IPV4, 0, 4, 4,
		"Header Length:        %lu (%lu bytes)", &ns_fmt_wlen);
static struct ns_pktfld ipv4_ns_diffsrv =
	NS_BITFIELD_I("diffsrv", &ipv4_ns, PRID_IPV4, 1, 0, 6,
		"Diffserv:             %02lx", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_ecn =
	NS_BITFIELD_I("ecn", &ipv4_ns, PRID_IPV4, 1, 6, 2,
		"ECN:                  %lx", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_len =
	NS_BYTEFIELD_I("len", &ipv4_ns, PRID_IPV4, 2, 2,
		"Total Length:         %lu bytes", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_id =
	NS_BYTEFIELD_I("id", &ipv4_ns, PRID_IPV4, 4, 2,
		"Identifier:           %lx", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_rf =
	NS_BITFIELD_I("rf", &ipv4_ns, PRID_IPV4, 6, 0, 1,
		"Reserved Frag Bit:    %lu..", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_df =
	NS_BITFIELD_I("df", &ipv4_ns, PRID_IPV4, 6, 1, 1,
		"Don't Fragment Bit:   .%lu.", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_mf =
	NS_BITFIELD_I("mf", &ipv4_ns, PRID_IPV4, 6, 2, 1,
		"More Fragments Bit:   ..%lu", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_fragoff =
	NS_BITFIELD_I("fragoff", &ipv4_ns, PRID_IPV4, 6, 3, 13,
		"Fragment Offset:      %lu quadwords", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_ttl =
	NS_BYTEFIELD_I("ttl", &ipv4_ns, PRID_IPV4, 8, 1,
		"Time to Live:         %lu", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_proto =
	NS_BYTEFIELD_I("proto", &ipv4_ns, PRID_IPV4, 9, 1,
		"IP Protocol:          %lu", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_cksum =
	NS_BYTEFIELD_I("cksum", &ipv4_ns, PRID_IPV4, 10, 2,
		"Header Checksum:      %lx", &ns_fmt_num);
static struct ns_pktfld ipv4_ns_saddr =
	NS_BYTEFIELD_I("saddr", &ipv4_ns, PRID_IPV4, 12, 4,
		"Source Address:       %s", &ns_fmt_ipv4a);
static struct ns_pktfld ipv4_ns_daddr =
	NS_BYTEFIELD_I("daddr", &ipv4_ns, PRID_IPV4, 16, 4,
		"Destination Address:  %s", &ns_fmt_ipv4a);
static struct ns_pktfld ipv4_ns_opt =
	NS_BYTEFIELD_VARLEN_I("opt", &ipv4_ns, PRID_IPV4, PRP_OI_SOFF, 20,
		PRP_OI_POFF,
		"IP Options -- Offset %lu, Length %lu", &ns_fmt_hdr);

struct ns_elem *stdproto_ipv4_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&ipv4_ns_vers, (struct ns_elem *)&ipv4_ns_hlen,
	(struct ns_elem *)&ipv4_ns_diffsrv, (struct ns_elem *)&ipv4_ns_ecn,
	(struct ns_elem *)&ipv4_ns_len, (struct ns_elem *)&ipv4_ns_id, 
	(struct ns_elem *)&ipv4_ns_rf, (struct ns_elem *)&ipv4_ns_df,
	(struct ns_elem *)&ipv4_ns_mf, (struct ns_elem *)&ipv4_ns_fragoff,
	(struct ns_elem *)&ipv4_ns_ttl, (struct ns_elem *)&ipv4_ns_proto,
	(struct ns_elem *)&ipv4_ns_cksum, (struct ns_elem *)&ipv4_ns_saddr,
	(struct ns_elem *)&ipv4_ns_daddr, (struct ns_elem *)&ipv4_ns_opt
};


extern struct ns_elem *stdproto_ipv6_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace ipv6_ns = 
	NS_NAMESPACE_I("ip6", NULL, PRID_IPV6, PRID_PCLASS_NET,
		"Internet Protocol Version 6 -- Offset %lu, Length %lu",
	       	stdproto_ipv6_ns_elems, array_length(stdproto_ipv6_ns_elems));

static struct ns_pktfld ipv6_ns_vers =
	NS_BITFIELD_I("vers", &ipv6_ns, PRID_IPV6, 0, 0, 4,
		"Version:              %lu", &ns_fmt_num);
static struct ns_pktfld ipv6_ns_class =
	NS_BITFIELD_I("class", &ipv6_ns, PRID_IPV6, 0, 4, 8,
		"Traffic Class:        %lu", &ns_fmt_num);
static struct ns_pktfld ipv6_ns_flowid =
	NS_BITFIELD_I("flowid", &ipv6_ns, PRID_IPV6, 0, 12, 20,
		"Flow ID:              %lu", &ns_fmt_num);
static struct ns_pktfld ipv6_ns_len =
	NS_BYTEFIELD_I("len", &ipv6_ns, PRID_IPV6, 4, 2,
		"Total Length:         %lu", &ns_fmt_num);
static struct ns_pktfld ipv6_ns_nxthdr =
	NS_BYTEFIELD_I("nxthdr", &ipv6_ns, PRID_IPV6, 6, 1,
		"Next Header:          %lu", &ns_fmt_num);
static struct ns_pktfld ipv6_ns_hoplim =
	NS_BYTEFIELD_I("hoplim", &ipv6_ns, PRID_IPV6, 7, 1,
		"Hop Limit:            %lu", &ns_fmt_num);
static struct ns_pktfld ipv6_ns_saddr =
	NS_BYTEFIELD_I("saddr", &ipv6_ns, PRID_IPV6, 8, 16,
		"Source Address:       %s", &ns_fmt_ipv6a);
static struct ns_pktfld ipv6_ns_daddr =
	NS_BYTEFIELD_I("daddr", &ipv6_ns, PRID_IPV6, 24, 16,
		"Destination Address:  %s", &ns_fmt_ipv6a);
static struct ns_pktfld ipv6_ns_exth =
	NS_BYTEFIELD_VARLEN_I("exth", &ipv6_ns, PRID_IPV6, PRP_OI_SOFF, 20,
		PRP_OI_POFF,
		"Extension Headers -- Offset %lu, Length %lu", &ns_fmt_hdr);

struct ns_elem *stdproto_ipv6_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&ipv6_ns_vers, (struct ns_elem *)&ipv6_ns_class,
	(struct ns_elem *)&ipv6_ns_flowid, (struct ns_elem *)&ipv6_ns_len,
	(struct ns_elem *)&ipv6_ns_nxthdr, (struct ns_elem *)&ipv6_ns_hoplim,
	(struct ns_elem *)&ipv6_ns_saddr, (struct ns_elem *)&ipv6_ns_daddr,
	(struct ns_elem *)&ipv6_ns_exth, 
};


extern struct ns_elem *stdproto_icmp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace icmp_ns = 
	NS_NAMESPACE_I("icmp", NULL, PRID_ICMP, PRID_PCLASS_XPORT,
		"Internet Control Message Protocol -- Offset %lu, Length %lu",
	       	stdproto_icmp_ns_elems, array_length(stdproto_icmp_ns_elems));

static struct ns_pktfld icmp_ns_type =
	NS_BYTEFIELD_I("type", &icmp_ns, PRID_ICMP, 0, 1,
		"Type:                 %lu", &ns_fmt_num);
static struct ns_pktfld icmp_ns_code =
	NS_BYTEFIELD_I("code", &icmp_ns, PRID_ICMP, 1, 1,
		"Code:                 %lu", &ns_fmt_num);
static struct ns_pktfld icmp_ns_cksum =
	NS_BYTEFIELD_I("cksum", &icmp_ns, PRID_ICMP, 2, 2,
		"Checksum:             %lx", &ns_fmt_num);
static struct ns_pktfld icmp_ns_id =
	NS_BYTEFIELD_I("id", &icmp_ns, PRID_ICMP, 4, 2,
		"Identifier:           %lu", &ns_fmt_num);
static struct ns_pktfld icmp_ns_seq =
	NS_BYTEFIELD_I("seq", &icmp_ns, PRID_ICMP, 6, 2,
		"Sequence Number:      %lu", &ns_fmt_num);
static struct ns_pktfld icmp_ns_mtu =
	NS_BYTEFIELD_I("mtu", &icmp_ns, PRID_ICMP, 6, 2,
		"MTU:                  %lu", &ns_fmt_num);
static struct ns_pktfld icmp_ns_ptr =
	NS_BYTEFIELD_I("ptr", &icmp_ns, PRID_ICMP, 4, 1,
		"Pointer:              %lu", &ns_fmt_num);
static struct ns_pktfld icmp_ns_gateway =
	NS_BYTEFIELD_I("gw", &icmp_ns, PRID_ICMP, 4, 4,
		"Gateway:              %lu", &ns_fmt_ipv4a);
static struct ns_pktfld icmp_ns_unused =
	NS_BYTEFIELD_I("unused", &icmp_ns, PRID_ICMP, 4, 4,
		"Unused data:          %lx", &ns_fmt_num);

struct ns_elem *stdproto_icmp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&icmp_ns_type, (struct ns_elem *)&icmp_ns_code,
	(struct ns_elem *)&icmp_ns_cksum, (struct ns_elem *)&icmp_ns_id,
	(struct ns_elem *)&icmp_ns_seq, (struct ns_elem *)&icmp_ns_mtu,
	(struct ns_elem *)&icmp_ns_ptr, (struct ns_elem *)&icmp_ns_gateway,
	(struct ns_elem *)&icmp_ns_unused,
};


extern struct ns_elem *stdproto_icmp6_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace icmp6_ns = 
	NS_NAMESPACE_I("icmp6", NULL, PRID_ICMP6, PRID_PCLASS_XPORT,
		"Internet Control Message Protocol v6 -- Offset %lu, Length %lu",
		stdproto_icmp6_ns_elems, array_length(stdproto_icmp6_ns_elems));

static struct ns_pktfld icmp6_ns_type =
	NS_BYTEFIELD_I("type", &icmp6_ns, PRID_ICMP6, 0, 1,
		"Type:                 %lu", &ns_fmt_num);
static struct ns_pktfld icmp6_ns_code =
	NS_BYTEFIELD_I("code", &icmp6_ns, PRID_ICMP6, 1, 1,
		"Code:                 %lu", &ns_fmt_num);
static struct ns_pktfld icmp6_ns_cksum =
	NS_BYTEFIELD_I("cksum", &icmp6_ns, PRID_ICMP6, 2, 2,
		"Checksum:             %lx", &ns_fmt_num);
static struct ns_pktfld icmp6_ns_hdata =
	NS_BYTEFIELD_I("hdata", &icmp6_ns, PRID_ICMP6, 4, 4,
		"Header Data:          %lx", &ns_fmt_num);

struct ns_elem *stdproto_icmp6_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&icmp6_ns_type, (struct ns_elem *)&icmp6_ns_code, 
	(struct ns_elem *)&icmp6_ns_cksum, (struct ns_elem *)&icmp6_ns_hdata
};


extern struct ns_elem *stdproto_udp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace udp_ns = 
	NS_NAMESPACE_I("udp", NULL, PRID_UDP, PRID_PCLASS_XPORT,
		"User Datagram Protocol -- Offset %lu, Length %lu",
	       	stdproto_udp_ns_elems, array_length(stdproto_udp_ns_elems));

static struct ns_pktfld udp_ns_sport =
	NS_BYTEFIELD_I("sport", &udp_ns, PRID_UDP, 0, 2,
		"Source Port:          %lu", &ns_fmt_num);
static struct ns_pktfld udp_ns_dport =
	NS_BYTEFIELD_I("dport", &udp_ns, PRID_UDP, 2, 2,
		"Destination Port:     %lu", &ns_fmt_num);
static struct ns_pktfld udp_ns_len =
	NS_BYTEFIELD_I("len", &udp_ns, PRID_UDP, 4, 2,
		"Length:               %lu", &ns_fmt_num);
static struct ns_pktfld udp_ns_cksum =
	NS_BYTEFIELD_I("cksum", &udp_ns, PRID_UDP, 6, 2,
		"Checksum:             %lx", &ns_fmt_num);

struct ns_elem *stdproto_udp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&udp_ns_sport, (struct ns_elem *)&udp_ns_dport, 
	(struct ns_elem *)&udp_ns_len, (struct ns_elem *)&udp_ns_cksum
};


extern struct ns_elem *stdproto_tcp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace tcp_ns = 
	NS_NAMESPACE_I("tcp", NULL, PRID_TCP, PRID_PCLASS_XPORT,
		"Transmission Control Protocol -- Offset %lu, Length %lu",
	       	stdproto_tcp_ns_elems, array_length(stdproto_tcp_ns_elems));

static struct ns_pktfld tcp_ns_sport =
	NS_BYTEFIELD_I("sport", &tcp_ns, PRID_TCP, 0, 2,
		"Source Port:          %lu", &ns_fmt_num);
static struct ns_pktfld tcp_ns_dport =
	NS_BYTEFIELD_I("dport", &tcp_ns, PRID_TCP, 2, 2,
		"Destination Port:     %lu", &ns_fmt_num);
static struct ns_pktfld tcp_ns_seqn =
	NS_BYTEFIELD_I("seqn", &tcp_ns, PRID_TCP, 4, 4,
		"Sequence Number:      %lu", &ns_fmt_num);
static struct ns_pktfld tcp_ns_ackn =
	NS_BYTEFIELD_I("ackn", &tcp_ns, PRID_TCP, 8, 4,
		"Acknowlege Number:    %lu", &ns_fmt_num);
static struct ns_pktfld tcp_ns_doff =
	NS_BITFIELD_I("doff", &tcp_ns, PRID_TCP, 12, 0, 4,
		"Data Offset:          %lu (%lu bytes)", 
		&ns_fmt_wlen);
static struct ns_pktfld tcp_ns_resv =
	NS_BITFIELD_I("resv", &tcp_ns, PRID_TCP, 12, 4, 4,
		"Reserved Bits:        %lx", &ns_fmt_num);
static struct ns_pktfld tcp_ns_cwr =
	NS_BITFIELD_I("cwr", &tcp_ns, PRID_TCP, 13, 0, 1,
		"Congest Win Reduced:  %lu.......", &ns_fmt_num);
static struct ns_pktfld tcp_ns_ece =
	NS_BITFIELD_I("ece", &tcp_ns, PRID_TCP, 13, 1, 1,
		"ECN Enabled:          .%lu......", &ns_fmt_num);
static struct ns_pktfld tcp_ns_urg =
	NS_BITFIELD_I("urg", &tcp_ns, PRID_TCP, 13, 2, 1,
		"Urgent:               ..%lu.....", &ns_fmt_num);
static struct ns_pktfld tcp_ns_ack =
	NS_BITFIELD_I("ack", &tcp_ns, PRID_TCP, 13, 3, 1,
		"Acknowledgement:      ...%lu....", &ns_fmt_num);
static struct ns_pktfld tcp_ns_psh =
	NS_BITFIELD_I("psh", &tcp_ns, PRID_TCP, 13, 4, 1,
		"Push:                 ....%lu...", &ns_fmt_num);
static struct ns_pktfld tcp_ns_rst =
	NS_BITFIELD_I("rst", &tcp_ns, PRID_TCP, 13, 5, 1,
		"Reset:                .....%lu..", &ns_fmt_num);
static struct ns_pktfld tcp_ns_syn =
	NS_BITFIELD_I("syn", &tcp_ns, PRID_TCP, 13, 6, 1,
		"Synchronize:          ......%lu.", &ns_fmt_num);
static struct ns_pktfld tcp_ns_fin =
	NS_BITFIELD_I("fin", &tcp_ns, PRID_TCP, 13, 7, 1,
		"Finalize:             .......%lu", &ns_fmt_num);
static struct ns_pktfld tcp_ns_win =
	NS_BYTEFIELD_I("win", &tcp_ns, PRID_TCP, 14, 2,
		"Window:               %lu", &ns_fmt_num);
static struct ns_pktfld tcp_ns_cksum =
	NS_BYTEFIELD_I("cksum", &tcp_ns, PRID_TCP, 16, 2,
		"Checksum:             %lx", &ns_fmt_num);
static struct ns_pktfld tcp_ns_urgp =
	NS_BYTEFIELD_I("urgp", &tcp_ns, PRID_TCP, 18, 2,
		"Urgent Pointer:       %lu", &ns_fmt_num);
static struct ns_pktfld tcp_ns_opt =
	NS_BYTEFIELD_VARLEN_I("opt", &tcp_ns, PRID_TCP, 20, PRP_OI_SOFF,
		PRP_OI_POFF,
		"TCP Options -- Offset %lu, Length %lu", &ns_fmt_hdr);

/* option forward declarations */
extern struct ns_elem *stdproto_tcp_mss_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_wscale_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_sackok_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_sack_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_ts_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_md5_ns_elems[STDPROTO_NS_SUB_ELEN];

/* TCP MSS Option */
static struct ns_namespace tcp_mss_ns = 
	NS_NAMESPACE_IDX_I("mss", &tcp_ns, PRID_TCP, PRID_NONE, PRP_TCPFLD_MSS, 4,
		"TCP Maximum Segment Size Option -- Length %lu, Offset %lu",
		stdproto_tcp_mss_ns_elems,
		array_length(stdproto_tcp_mss_ns_elems));
static struct ns_pktfld tcp_mss_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_mss_ns, PRID_TCP, PRP_TCPFLD_MSS, 0, 1,
		"Kind:                 %lu", &ns_fmt_num);
static struct ns_pktfld tcp_mss_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_mss_ns, PRID_TCP, PRP_TCPFLD_MSS, 1, 1,
		"Length:               %lu", &ns_fmt_num);
static struct ns_pktfld tcp_mss_mss =
	NS_BYTEFIELD_IDX_I("mss", &tcp_mss_ns, PRID_TCP, PRP_TCPFLD_MSS, 2, 2,
		"Max Segment Size:     %lu", &ns_fmt_num);
struct ns_elem *stdproto_tcp_mss_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_mss_kind, (struct ns_elem *)&tcp_mss_len,
	(struct ns_elem *)&tcp_mss_mss,
};

/* TCP Window Scale Option */
static struct ns_namespace tcp_wscale_ns = 
	NS_NAMESPACE_IDX_I("wscale", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_WSCALE, 4,
		"TCP Window Scale Option -- Length %lu, Offset %lu",
		stdproto_tcp_wscale_ns_elems,
		array_length(stdproto_tcp_wscale_ns_elems));
static struct ns_pktfld tcp_wscale_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_wscale_ns, PRID_TCP, PRP_TCPFLD_WSCALE,
		0, 1, 
		"Kind:                 %lu", &ns_fmt_num);
static struct ns_pktfld tcp_wscale_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_wscale_ns, PRID_TCP, PRP_TCPFLD_WSCALE,
		1, 1, 
		"Length:               %lu", &ns_fmt_num);
static struct ns_pktfld tcp_wscale_scale =
	NS_BYTEFIELD_IDX_I("scale", &tcp_wscale_ns, PRID_TCP, PRP_TCPFLD_WSCALE,
		2, 1,
		"Window Scale:         %lu", &ns_fmt_num);
struct ns_elem *stdproto_tcp_wscale_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_wscale_kind, (struct ns_elem *)&tcp_wscale_len,
	(struct ns_elem *)&tcp_wscale_scale,
};

/* TCP Selective Acknowledgement Permitted Option */
static struct ns_namespace tcp_sackok_ns = 
	NS_NAMESPACE_IDX_I("sackok", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_SACKOK, 2,
		"TCP Window Scale Option -- Length %lu, Offset %lu",
		stdproto_tcp_sackok_ns_elems,
		array_length(stdproto_tcp_sackok_ns_elems));
static struct ns_pktfld tcp_sackok_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_sackok_ns, PRID_TCP, PRP_TCPFLD_SACKOK,
		0, 1, 
		"Kind:                 %lu", &ns_fmt_num);
static struct ns_pktfld tcp_sackok_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_sackok_ns, PRID_TCP, PRP_TCPFLD_SACKOK,
		1, 1, 
		"Length:               %lu", &ns_fmt_num);
struct ns_elem *stdproto_tcp_sackok_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_sackok_kind, (struct ns_elem *)&tcp_sackok_len,
};

/* TCP Selective Acknowledgement Option */
static struct ns_namespace tcp_sack_ns = 
	NS_NAMESPACE_VARLEN_I("sack", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_SACK,
		PRP_TCPFLD_SACK_END,
		"TCP Selective Acknowledgement Option -- Length %lu, Offset %lu",
		stdproto_tcp_sack_ns_elems,
		array_length(stdproto_tcp_sack_ns_elems));
static struct ns_pktfld tcp_sack_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_sack_ns, PRID_TCP, PRP_TCPFLD_SACK, 
		0, 1, 
		"Kind:                 %lu", &ns_fmt_num);
static struct ns_pktfld tcp_sack_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_sack_ns, PRID_TCP, PRP_TCPFLD_SACK,
		1, 1, 
		"Length:               %lu", &ns_fmt_num);
static struct ns_pktfld tcp_sack_blocks =
	NS_BYTEFIELD_VARLEN_I("blocks", &tcp_sack_ns, PRID_TCP, PRP_TCPFLD_SACK,
		2, PRP_TCPFLD_SACK_END, 
		"Selective Acknowledgements -- Offset %lu, Length %lu",
		&ns_fmt_hdr);
struct ns_elem *stdproto_tcp_sack_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_sack_kind, (struct ns_elem *)&tcp_sack_len,
	(struct ns_elem *)&tcp_sack_blocks,
};


/* TCP Timestamp Option */
static struct ns_namespace tcp_ts_ns = 
	NS_NAMESPACE_IDX_I("ts", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_TSTAMP, 10,
		"TCP Timestamp Option -- Length %lu, Offset %lu",
		stdproto_tcp_ts_ns_elems,
		array_length(stdproto_tcp_ts_ns_elems));
static struct ns_pktfld tcp_ts_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_ts_ns, PRID_TCP, PRP_TCPFLD_TSTAMP,
		0, 1, 
		"Kind:                 %lu", &ns_fmt_num);
static struct ns_pktfld tcp_ts_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_ts_ns, PRID_TCP, PRP_TCPFLD_TSTAMP,
		1, 1, 
		"Length:               %lu", &ns_fmt_num);
static struct ns_pktfld tcp_ts_val =
	NS_BYTEFIELD_IDX_I("val", &tcp_ts_ns, PRID_TCP, PRP_TCPFLD_TSTAMP, 
		2, 4, 
		"Value:                %lu", &ns_fmt_num);
static struct ns_pktfld tcp_ts_echo =
	NS_BYTEFIELD_IDX_I("echo", &tcp_ts_ns, PRID_TCP, PRP_TCPFLD_TSTAMP,
		6, 4, 
		"Echoed Value:         %lu", &ns_fmt_num);
struct ns_elem *stdproto_tcp_ts_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_ts_kind, (struct ns_elem *)&tcp_ts_len,
	(struct ns_elem *)&tcp_ts_val, (struct ns_elem *)&tcp_ts_echo,
};


/* TCP MD5 Signature Option */
static struct ns_namespace tcp_md5_ns = 
	NS_NAMESPACE_IDX_I("md5", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_MD5, 18,
		"TCP MD5 Signature Option -- Length %lu, Offset %lu",
		stdproto_tcp_md5_ns_elems,
		array_length(stdproto_tcp_md5_ns_elems));
static struct ns_pktfld tcp_md5_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_md5_ns, PRID_TCP, PRP_TCPFLD_MD5,
		0, 1, 
		"Kind:                 %lu", &ns_fmt_num);
static struct ns_pktfld tcp_md5_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_md5_ns, PRID_TCP, PRP_TCPFLD_MD5,
		1, 1, 
		"Length:               %lu", &ns_fmt_num);
static struct ns_pktfld tcp_md5_sig =
	NS_BYTEFIELD_IDX_I("sig", &tcp_md5_ns, PRID_TCP, PRP_TCPFLD_MD5,
		2, 16, 
		"Signature -- Length %lu, Offset %lu", &ns_fmt_hdr);
struct ns_elem *stdproto_tcp_md5_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_md5_kind, (struct ns_elem *)&tcp_md5_len,
	(struct ns_elem *)&tcp_md5_sig,
};

struct ns_elem *stdproto_tcp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&tcp_ns_sport, (struct ns_elem *)&tcp_ns_dport,
	(struct ns_elem *)&tcp_ns_seqn, (struct ns_elem *)&tcp_ns_ackn,
	(struct ns_elem *)&tcp_ns_doff, (struct ns_elem *)&tcp_ns_resv,
	(struct ns_elem *)&tcp_ns_cwr, (struct ns_elem *)&tcp_ns_ece, 
	(struct ns_elem *)&tcp_ns_urg, (struct ns_elem *)&tcp_ns_ack, 
	(struct ns_elem *)&tcp_ns_psh, (struct ns_elem *)&tcp_ns_rst, 
	(struct ns_elem *)&tcp_ns_syn, (struct ns_elem *)&tcp_ns_fin, 
	(struct ns_elem *)&tcp_ns_win, (struct ns_elem *)&tcp_ns_cksum, 
	(struct ns_elem *)&tcp_ns_urgp, (struct ns_elem *)&tcp_ns_opt,

	/* Options */
	(struct ns_elem *)&tcp_mss_ns,
	(struct ns_elem *)&tcp_wscale_ns,
	(struct ns_elem *)&tcp_sackok_ns,
	(struct ns_elem *)&tcp_sack_ns,
	(struct ns_elem *)&tcp_ts_ns,
	(struct ns_elem *)&tcp_md5_ns,
};


int register_std_proto()
{
	if (pp_register(PRID_ETHERNET2, &eth_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_ARP, &arp_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_IPV4, &ipv4_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_IPV6, &ipv6_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_ICMP, &icmp_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_ICMP6, &icmpv6_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_UDP, &udp_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_TCP, &tcp_proto_parser_ops) < 0)
		goto fail;

	if (ns_add_elem(NULL, (struct ns_elem *)&eth2_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&arp_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&ipv4_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&ipv6_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&icmp_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&icmp6_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&udp_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&tcp_ns) < 0)
		goto fail;

	return 0;
fail:
	unregister_std_proto();
	return -1;
}


void unregister_std_proto()
{
	pp_unregister(PRID_ETHERNET2);
	pp_unregister(PRID_ARP);
	pp_unregister(PRID_IPV4);
	pp_unregister(PRID_IPV6);
	pp_unregister(PRID_ICMP);
	pp_unregister(PRID_ICMP6);
	pp_unregister(PRID_UDP);
	pp_unregister(PRID_TCP);

	ns_rem_elem((struct ns_elem *)&eth2_ns);
	ns_rem_elem((struct ns_elem *)&arp_ns);
	ns_rem_elem((struct ns_elem *)&ipv4_ns);
	ns_rem_elem((struct ns_elem *)&ipv6_ns);
	ns_rem_elem((struct ns_elem *)&icmp_ns);
	ns_rem_elem((struct ns_elem *)&icmp6_ns);
	ns_rem_elem((struct ns_elem *)&udp_ns);
	ns_rem_elem((struct ns_elem *)&tcp_ns);
}
