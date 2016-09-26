/*
 * ONICS
 * Copyright 2012-2016
 * Christopher Adam Telfer
 *
 * stdproto.c -- Standard library of Internet protocol parsers.
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
#include "sysdeps.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "stdproto.h"
#include "util.h"
#include "ns.h"
#include <cat/emalloc.h>
#include <cat/pack.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

extern struct prparse_ops eth_prparse_ops;
extern struct prparse_ops arp_prparse_ops;
extern struct prparse_ops ipv4_prparse_ops;
extern struct prparse_ops ipv6_prparse_ops;
extern struct prparse_ops icmp_prparse_ops;
extern struct prparse_ops icmpv6_prparse_ops;
extern struct prparse_ops udp_prparse_ops;
extern struct prparse_ops tcp_prparse_ops;
extern struct prparse_ops gre_prparse_ops;
extern struct prparse_ops nvgre_prparse_ops;
extern struct prparse_ops vxlan_prparse_ops;
extern struct prparse_ops mpls_prparse_ops;


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


struct icmp_parse {
	struct prparse prp;
	ulong xfields[PRP_ICMP_NXFIELDS];
};


struct ipv6_parse {
	struct prparse prp;
	ulong xfields[PRP_IPV6_NXFIELDS];
};


struct tcp_parse {
	struct prparse prp;
	ulong xfields[PRP_TCP_NXFIELDS];
};


struct icmp6_parse {
	struct prparse prp;
	ulong xfields[PRP_ICMP6_NXFIELDS];
};


struct gre_parse {
	struct prparse prp;
	ulong xfields[PRP_GRE_NXFIELDS];
};


struct mpls_parse {
	struct prparse prp;
	ulong xfields[PRP_MPLS_NXFIELDS];
};


/* NB:  right now we are using emalloc() fpr header allocation, but we */
/* may not do that in the future.  When that happens, we need to change */
/* newprp, and freeprp */
static struct prparse *newprp(size_t sz, uint prid, ulong off, ulong hlen,
			      ulong plen, ulong tlen, struct prparse_ops *ops,
			      struct prparse *reg, uint nxfields)
{
	struct prparse *prp;
	abort_unless(sz >= sizeof(struct prparse));
	prp = emalloc(sz);
	prp_init_parse(prp, prid, off, hlen, plen, tlen, ops, reg, nxfields);
	return prp;
}


static ONICS_INLINE void freeprp(struct prparse *prp)
{
	free(prp);
}


static struct prparse *stdpr_parse(struct prparse *pprp, byte_t *buf,
				     ulong off, ulong maxlen)
{
	return NULL;
}


static int stdpr_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
			  uint *prid, ulong *off, ulong *maxlen)
{
	return 0;
}


static int stdpr_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	errno = ENOTSUP;
	return -1;
}


static struct prparse *stdpr_add(struct prparse *reg, byte_t *buf,
				   struct prpspec *ps, int enclose)
{
	return NULL;
}


static void stdpr_update(struct prparse *prp, byte_t *buf)
{
	prp_reset_xfields(prp);
}


static void stdpr_free(struct prparse *prp)
{
	/* presently unused */
	(void)stdpr_getspec;
	(void)stdpr_add;
	(void)stdpr_parse;
	(void)stdpr_update;
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


static struct prparse *stdpr_copy(struct prparse *oprp)
{
	return simple_copy(oprp, sizeof(struct prparse));
}


/* -- ops for Ethernet type -- */
static void eth_update(struct prparse *prp, byte_t *buf);

static struct prparse *eth_parse(struct prparse *reg, byte_t *buf,
				 ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newprp(sizeof(struct eth_parse), PRID_ETHERNET2, off, 0,
		     maxlen, 0, &eth_prparse_ops, reg, PRP_ETH_NXFIELDS);
	if (!prp)
		return NULL;
	eth_update(prp, buf);
	return prp;
}


int eth_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
	       uint *prid, ulong *off, ulong *maxlen)
{
	byte_t *p;
	uint x;

	if (cld != NULL)
		return 0;

	abort_unless(buf);
	abort_unless(reg->offs[PRP_ETHFLD_ETYPE] <= prp_poff(reg) - 2);

	p = buf + reg->offs[PRP_ETHFLD_ETYPE];
	x = etypetoprid(ntoh16x(p));
	if (x == PRID_NONE)
		return 0;
	*prid = x;
	*off = prp_poff(reg);
	*maxlen = prp_plen(reg);
	return 1;
}


static int eth_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_ETHERNET2, ETHHLEN, 0, enclose);
}


static int eth_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		   int enclose)
{
	struct prparse *prp, *cld;
	uint16_t etype;
	byte_t *p;

	abort_unless(reg && ps && ps->prid == PRID_ETHERNET2);
	if (ps->hlen < ETHHLEN) {
		errno = EINVAL;
		return -1;
	}

	prp = newprp(sizeof(struct eth_parse), PRID_ETHERNET2, 
		     ps->off, ps->hlen, ps->plen, ps->tlen,
		     &eth_prparse_ops, reg, PRP_ETH_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf && prp_hlen(prp) >= ETHHLEN) {
		memset(prp_header(prp, buf, void), 0, prp_hlen(prp));
		prp->offs[PRP_ETHFLD_ETYPE] = prp_poff(prp) - 2;
		if (enclose) {
			cld = prp_next_in_region(prp, prp);
			if (cld != NULL) {
				etype = pridtoetype(cld->prid);
				p = buf + prp_poff(prp) - 2;
				hton16i(etype, p);
			}
		}
	}

	return 0;
}


static int etype_is_vlan(uint16_t etype)
{
	return etype == ETHTYPE_C_VLAN ||
	       etype == ETHTYPE_S_VLAN;
}


static void eth_update(struct prparse *prp, byte_t *buf)
{
	ushort etype;
	byte_t *p;
	ulong poff;
	uint vidx;

	prp->error = 0;
	prp_reset_xfields(prp);

	if (prp_totlen(prp) < ETHHLEN) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}

	p = prp_header(prp, buf, byte_t) + ETHHLEN - 2;
	vidx = PRP_ETHFLD_VLAN0;
	poff = prp_soff(prp) + ETHHLEN;
	etype = ntoh16x(p);
	while (etype_is_vlan(etype)) {
		if (prp_totlen(prp) < (poff - prp_soff(prp) + 4)) {
			prp->error = PRP_ERR_TOOSMALL;
			return;
		}
		if (vidx < (PRP_OI_EXTRA + PRP_ETH_NXFIELDS)) {
			prp->offs[vidx] = poff - 2;
			vidx += 1;
		}
		p += 4;
		poff += 4;
		etype = ntoh16x(p);
	} 

	prp_poff(prp) = poff;
	prp->offs[PRP_ETHFLD_ETYPE] = poff - 2;
}


static int eth_fixnxt(struct prparse *prp, byte_t *buf)
{
	struct prparse *next;
	next = prp_next(prp);
	if (!prp_list_end(next))
		hton16i(pridtoetype(next->prid), buf + prp_poff(prp) - 2);
	return 0;
}


/* -- ops for ARP type -- */
static byte_t ethiparpstr[6] = {0, 1, 8, 0, 6, 4};
static void arp_update(struct prparse *prp, byte_t *buf);

static struct prparse *arp_parse(struct prparse *reg, byte_t *buf,
				 ulong off, ulong maxlen)
{
	struct prparse *prp;
	abort_unless(reg && buf);
	prp = newprp(sizeof(struct arp_parse), PRID_ARP, off, 0, maxlen, 0,
		     &arp_prparse_ops, reg, PRP_ARP_NXFIELDS);
	if (!prp)
		return NULL;
	arp_update(prp, buf);
	return prp;
}


static void arp_update(struct prparse *prp, byte_t *buf)
{
	struct arph *arp;
	prp->error = 0;
	prp_reset_xfields(prp);

	if (prp_totlen(prp) < 8) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}
	prp_reset_xfields(prp);
	arp = prp_header(prp, buf, struct arph);
	if (arp->hwlen * 2 + arp->prlen * 2 > prp_totlen(prp) - 8) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	} 
	prp_eoff(prp) = prp_toff(prp) = prp_poff(prp) =
		prp_soff(prp) + arp->hwlen * 2 + arp->prlen * 2 + 8;
	if (memcmp(ethiparpstr, arp, sizeof(ethiparpstr)) == 0)
		prp->offs[PRP_ARPFLD_ETHARP] = prp_soff(prp);
}


static int arp_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	ps->prid = PRID_ARP;
	ps->hlen = 28;
	ps->plen = 0;
	ps->tlen = 0;
	if (enclose) {
		/* ARP can not enclose any real data */
		if (prp_soff(prp) < 28 || prp_totlen(prp) != 0) {
			errno = EINVAL;
			return -1;
		}
		ps->off = prp_soff(prp) - 28;
	} else {
		if (prp_plen(prp) < 28) {
			errno = ENOSPC;
			return -1;
		}
		ps->off = prp_poff(prp);
	}
	return 0;
}


static int arp_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		   int enclose)
			       
{
	struct prparse *prp;
	struct arph *arp;
	
	if (ps->hlen < 8) {
		errno = EINVAL;
		return -1;
	}
	prp = newprp(sizeof(struct arp_parse), PRID_ARP, ps->off, ps->hlen,
		     ps->plen, ps->tlen, &arp_prparse_ops, reg, 
		     PRP_ARP_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf) {
		memset(buf + ps->off, 0, prp_totlen(prp));
		if (prp_hlen(prp) >= 28) {
			prp->offs[PRP_ARPFLD_ETHARP] = prp_soff(prp);
			arp = prp_header(prp, buf, struct arph);
			pack(arp, 8, "hhbbh", ARPT_ETHERNET, ETHTYPE_IP, 6, 4,
			     ARPOP_REQUEST);
		}
	}

	return 0;
}


static int arp_fixlen(struct prparse *prp, byte_t *buf)
{
	struct arph *arp;
	if (prp_hlen(prp) < 8)
		return -1;
	arp = prp_header(prp, buf, struct arph);
	if (arp->hwlen * 2 + arp->prlen * 2 + 8 > prp_hlen(prp))
		return -1;
	prp->error &= ~(PRP_ERR_TRUNC | PRP_ERR_HLEN | PRP_ERR_TOOSMALL);
	return 0;
}


static struct prparse *arp_copy(struct prparse *oprp)
{
	return simple_copy(oprp, sizeof(struct arp_parse));
}


/* -- ops for IPV4 type -- */
static void ipv4_update(struct prparse *prp, byte_t *buf);

static int ipv4_parse_opt(struct prparse *prp, byte_t *op, size_t olen)
{
	byte_t *osave = op;
	uint oc;
	uint oidx;
	uint t;
	ulong ooff = prp_soff(prp) + 20;

	prp->offs[PRP_IPFLD_OPT] = ooff;

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


static struct prparse *ipv4_parse(struct prparse *reg, byte_t *buf,
				  ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newprp(sizeof(struct ip_parse), PRID_IPV4, off, 0, maxlen, 0,
		     &ipv4_prparse_ops, reg, PRP_IP_NXFIELDS);
	if (!prp)
		return NULL;
	ipv4_update(prp, buf);
	return prp;
}


int ipv4_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
	        uint *prid, ulong *off, ulong *maxlen)
{
	struct ipv4h *ip;

	if (cld != NULL)
		return 0;

	abort_unless(buf);
	ip = prp_header(reg, buf, struct ipv4h);
	/* non-first-fragment won't have reliable next proto info */
	if ((ntoh16(ip->fragoff) & IPH_FRAGOFFMASK) > 0)
		return 0;
	if (ip->proto == IPPROT_V6V4)
		*prid = PRID_IPV6;
	else
		*prid = PRID_BUILD(PRID_PF_INET, ip->proto);
	*off = prp_poff(reg);
	*maxlen = prp_plen(reg);
	return 1;
}


static int ipv4_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_IPV4, IPH_MINLEN, 0, enclose);
}


static int ipv4_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		    int enclose)
				
{
	struct prparse *prp, *cld;
	struct ipv4h *ip;

	if (ps->hlen < 20 || ps->hlen > 60) {
		errno = EINVAL;
		return -1;
	}
	prp = newprp(sizeof(struct ip_parse), PRID_IPV4, ps->off, ps->hlen, 
		     ps->plen, ps->tlen, &ipv4_prparse_ops, reg,
		     PRP_IP_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf) {
		memset(prp_header(prp, buf, void), 0, prp_hlen(prp));
		ip = prp_header(prp, buf, struct ipv4h);
		ip->vhl = 0x40 | (ps->hlen >> 2);
		ip->len = hton16(prp_totlen(prp));
		if (ps->hlen > IPH_MINLEN) {
			byte_t *p = (byte_t *)(ip + 1);
			byte_t *end = p + ps->hlen - IPH_MINLEN;
			while (p < end)
				*p++ = IPOPT_NOP;
		}

		ip->proto = IPPROT_RESERVED;
		if (enclose) {
			cld = prp_next_in_region(prp, prp);
			if (cld != NULL)
				ip->proto = pridtoiptype(cld->prid);
		}
		ip->cksum = ~ones_sum(ip, IPH_HLEN(*ip), 0);
	}

	return 0;
}


static void ipv4_update(struct prparse *prp, byte_t *buf)
{
	ushort sum, iplen, hlen;
	struct ipv4h *ip;
	ulong len, fragoff;

	prp->error = 0;
	prp_reset_xfields(prp);

	len = prp_totlen(prp);
	if (len < IPH_MINLEN) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}

	ip = prp_header(prp, buf, struct ipv4h);
	hlen = IPH_HLEN(*ip);
	if (hlen < IPH_MINLEN || hlen > len)  {
		prp->error |= PRP_ERR_HLEN;
		return;
	}
	prp_poff(prp) = prp_soff(prp) + hlen;

	if (IPH_VERSION(*ip) != 4)
		prp->error |= PRP_ERR_INVALID;

	sum = ~ones_sum(ip, hlen, 0) & 0xFFFF;
	if (sum != 0)
		prp->error |= PRP_ERR_CKSUM;

	/* check whether datagram is smaller than enclosing packet */
	iplen = ntoh16x(&ip->len);
	if (len < iplen) {
		prp->error |= PRP_ERR_TRUNC;
	} else if (iplen < len) {
		prp_eoff(prp) = prp_toff(prp) = prp_soff(prp) + iplen;
	}

	fragoff = ntoh32(ip->fragoff);
	if (fragoff != 0) {
		if (IPH_FRAGOFF(fragoff) + iplen > 65535)
			prp->error |= PRP_ERR_INVALID;
		if ((IPH_RFMASK & fragoff))
			prp->error |= PRP_ERR_INVALID;
	}
	if (hlen > IPH_MINLEN) 
		ipv4_parse_opt(prp, (byte_t *)(ip + 1), hlen - IPH_MINLEN);
}


static int ipv4_fixnxt(struct prparse *prp, byte_t *buf)
{
	struct prparse *next;
	struct ipv4h *ip;
	uchar proto;
	ulong sum;

	next = prp_next(prp);
	if (!prp_list_end(next)) {
		proto = pridtoiptype(next->prid);
		ip = prp_header(prp, buf, struct ipv4h);
		sum = hton16(((~ip->proto & 0xFF) << 8) + (proto << 8)) + 
		      ip->cksum;
		sum = (sum >> 16) + (sum & 0xFFFF);
		ip->cksum = (sum >> 16) + (sum & 0xFFFF);
		ip->proto = proto;
	}
	return 0;
}


static int ipv4_fixlen(struct prparse *prp, byte_t *buf)
{
	struct ipv4h *ip;
	long hlen;
	ushort tlen;

	abort_unless(prp);

	ip = prp_header(prp, buf, struct ipv4h);
	hlen = prp_hlen(prp);
	if ((hlen < IPH_MINLEN) || (hlen > IPH_MAXLEN) || ((hlen & 3) != 0) ||
	    (hlen > prp_totlen(prp)))
		return -1;
	ip->vhl = 0x40 | (hlen >> 2);
	if (prp_totlen(prp) > 65535)
		return -1;
	tlen = prp_totlen(prp);
	hton16i(tlen, &ip->len);
	prp->error &= ~(PRP_ERR_TRUNC | PRP_ERR_HLEN | PRP_ERR_TOOSMALL);

	return 0;
}


static int ipv4_fixcksum(struct prparse *prp, byte_t *buf)
{
	long hlen;
	struct ipv4h *ip;

	abort_unless(prp);
	ip = prp_header(prp, buf, struct ipv4h);
	hlen = IPH_HLEN(*ip);
	if (hlen < IPH_MINLEN)
		return -1;
	ip->cksum = 0;
	ip->cksum = ~ones_sum(ip, IPH_HLEN(*ip), 0);
	prp->error &= ~PRP_ERR_CKSUM;

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


static uint16_t pseudo_cksum(struct prparse *prp, struct prparse *ipprp,
			     byte_t *buf, uint8_t proto)
{
	uint16_t sum = 0;
	if (ipprp->prid == PRID_IPV4) {
		struct pseudoh ph;
		struct ipv4h *ip = prp_header(ipprp, buf, struct ipv4h);
		memset(&ph, 0, sizeof(ph));
		ph.saddr = ip->saddr;
		ph.daddr = ip->daddr;
		ph.proto = proto;
		ph.totlen = hton16(prp_totlen(prp));
		sum = ones_sum(&ph, 12, 0);
	} else {
		struct pseudo6h ph;
		struct ipv6h *ip6 = prp_header(ipprp, buf, struct ipv6h);
		abort_unless(ipprp->prid == PRID_IPV6);
		memset(&ph, 0, sizeof(ph));
		ph.saddr = ip6->saddr;
		ph.daddr = ip6->daddr;
		ph.proto = proto;
		ph.totlen = hton32(prp_totlen(prp));
		sum = ones_sum(&ph, 40, 0);
	}
	sum = ones_sum(prp_header(prp, buf, void), prp_totlen(prp), sum);
	return ~sum;
}


static struct prparse *find_ipprp(struct prparse *prp)
{
	while (prp != NULL && prp->prid != PRID_IPV4 && prp->prid != PRID_IPV6)
		prp = prp->region;
	return prp;
}


/* -- parse options for UDP protocol -- */
static void udp_update(struct prparse *prp, byte_t *buf);

static struct prparse *udp_parse(struct prparse *reg, byte_t *buf,
				 ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newprp(sizeof(*prp), PRID_UDP, off, 0, maxlen, 0,  
		     &udp_prparse_ops, reg, 0);
	if (!prp)
		return NULL;
	udp_update(prp, buf);
	return prp;
}


static int udp_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
		      uint *prid, ulong *off, ulong *maxlen)
{
	struct udph *udp;
	ushort dport;

	if (cld != NULL)
		return 0;

	/* Look for tunnel encapsulations over UDP */
	udp = prp_header(reg, buf, struct udph);
	dport = ntoh16x(&udp->dport);

	/* 
	 * VXLAN must be:
	 *   - on the right port
	 *   - have enough room for the header
	 *   - match the correct fixed value in the first word
	 */
	if (dport == VXLAN_PORT && prp_plen(reg) >= VXLAN_HLEN &&
	    hton32(*(uint32_t *)prp_payload(reg, buf)) == VXLAN_FLAG_VNI) {
		*prid = PRID_VXLAN;
		*off = prp_poff(reg);
		*maxlen = prp_plen(reg);
		return 1;
	/* 
	 * MPLS must be:
	 *   - on the right port
	 *   - have enough room for the header
	 */
	} else if (dport == MPLS_PORT && prp_plen(reg) >= MPLS_HLEN) {
		*prid = PRID_MPLS;
		*off = prp_poff(reg);
		*maxlen = prp_plen(reg);
		return 1;
	/*
	 * No further encapsulated protocols yet.
	 */
	} else {
		return 0;
	}
}


static int udp_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_UDP, UDPH_LEN, 0, enclose);
}


static int udp_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		   int enclose)
{
	struct prparse *prp, *cld;
	struct udph *udp;

	(void)enclose;
	if (ps->hlen != UDPH_LEN) {
		errno = EINVAL;
		return -1;
	}

	prp = newprp(sizeof(*prp), PRID_UDP, ps->off, ps->hlen, ps->plen, 
		     ps->tlen, &udp_prparse_ops, reg, 0);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf) {
		memset(prp_header(prp, buf, void), 0, prp_hlen(prp));
		udp = prp_header(prp, buf, struct udph);
		hton16i(prp_totlen(prp), &udp->len);
		/* check for known protocols within UDP */
		cld = prp_next_in_region(prp, prp);
		if (cld != NULL) {
			if (cld->prid == PRID_VXLAN)
				hton16i(VXLAN_PORT, &udp->dport);
		}
	}

	return 0;
}


static void udp_update(struct prparse *prp, byte_t *buf)
{
	ushort ulen;
	struct udph *udp;
	struct prparse *ipprp;

	if (prp_totlen(prp) < UDPH_LEN) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}

	prp_poff(prp) = prp_soff(prp) + UDPH_LEN;

	udp = prp_header(prp, buf, struct udph);
	ulen = ntoh16x(&udp->len);

	if (prp_totlen(prp) < ulen) {
		prp->error |= PRP_ERR_TRUNC | PRP_ERR_CKSUM;
	} else if (udp->cksum != 0) {
		ipprp = find_ipprp(prp->region);
		if ((ipprp == NULL) || 
		    (pseudo_cksum(prp, ipprp, buf, IPPROT_UDP) & 0xFFFF) != 0)
			prp->error |= PRP_ERR_CKSUM;
	}
}


static int udp_fixnxt(struct prparse *prp, byte_t *buf)
{
	struct prparse *next;
	struct udph *udp;
	ulong sum;

	next = prp_next(prp);
	if (!prp_list_end(next)) {
		udp = prp_header(prp, buf, struct udph);
		sum = (~udp->dport) & 0xFFFF;
		if (next->prid == PRID_VXLAN) {
			hton16i(VXLAN_PORT, &udp->dport);
		} else if (next->prid == PRID_MPLS) {
			hton16i(MPLS_PORT, &udp->dport);
		} else {
			return 0;
		}
		if (udp->cksum != 0) {
			sum += udp->cksum + udp->dport;
			sum = (sum >> 16) + (sum & 0xFFFF);
			udp->cksum = (sum >> 16) + (sum & 0xFFFF);
		}
	}
	return 0;
}


static int udp_fixlen(struct prparse *prp, byte_t *buf)
{
	if (prp_hlen(prp) != UDPH_LEN)
		return -1;
	if (prp_plen(prp) > 65527)
		return -1;
	hton16i(prp_totlen(prp), &prp_header(prp, buf, struct udph)->len);
	prp->error &= ~(PRP_ERR_TRUNC | PRP_ERR_HLEN | PRP_ERR_TOOSMALL);
	return 0;
}


static int udp_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct udph *udp = prp_header(prp, buf, struct udph);
	struct prparse *ipprp = find_ipprp(prp->region);

	if ((prp_hlen(prp) != UDPH_LEN) || (ipprp == NULL))
		return -1;
	if (udp->cksum != 0) {
		udp->cksum = 0;
		udp->cksum = pseudo_cksum(prp, ipprp, buf, IPPROT_UDP);
	}
	prp->error &= ~PRP_ERR_CKSUM;

	return 0;
}


/* -- TCP functions -- */
static void tcp_update(struct prparse *prp, byte_t *buf);

static int tcp_parse_opt(struct prparse *prp, struct tcph *tcp, size_t olen)
{
	uint oc;
	ulong ooff = prp_soff(prp) + 20;
	byte_t *op = (byte_t *)(tcp + 1);
	byte_t *osave = op;

	prp->offs[PRP_TCPFLD_OPT] = ooff;

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


static struct prparse *tcp_parse(struct prparse *reg, byte_t *buf,
				 ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newprp(sizeof(struct tcp_parse), PRID_TCP, off, 0, maxlen, 0,
		     &tcp_prparse_ops, reg, PRP_TCP_NXFIELDS);
	if (!prp)
		return NULL;
	prp->region = reg;
	tcp_update(prp, buf);
	return prp;
}


static int tcp_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_TCP, TCPH_MINLEN, 0, enclose);
}


static int tcp_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		   int enclose)
{
	struct prparse *prp, *ipprp;
	struct tcph *tcp;

	(void)enclose;
	if (ps->hlen < TCPH_MINLEN || ps->hlen > TCPH_MAXLEN) {
		errno = EINVAL;
		return -1;
	}

	prp = newprp(sizeof(struct tcp_parse), PRID_TCP, 
		     ps->off, ps->hlen, ps->plen, ps->tlen,
		     &tcp_prparse_ops, reg, PRP_TCP_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf) {
		memset(prp_header(prp, buf, void), 0, prp_hlen(prp));
		tcp = prp_header(prp, buf, struct tcph);
		tcp->doff = ps->hlen << 2;
		if (ps->hlen > TCPH_MINLEN) {
			byte_t *p = (byte_t *)(tcp + 1);
			byte_t *end = p + ps->hlen - TCPH_MINLEN;
			while (p < end)
				*p++ = TCPOPT_NOP;
		}
		ipprp = find_ipprp(reg);
		if (ipprp == NULL) {
			prp->error |= PRP_ERR_CKSUM;
		} else {
			tcp->cksum = 0;
			tcp->cksum = pseudo_cksum(prp, ipprp, buf, IPPROT_TCP);
		}
	}

	return 0;
}


static void tcp_update(struct prparse *prp, byte_t *buf)
{
	struct prparse *ipprp;
	struct tcph *tcp;
	uint hlen;
	ulong len;

	prp->error = 0;
	prp_reset_xfields(prp);

	len = prp_totlen(prp);
	if (len < TCPH_MINLEN) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}

	tcp = prp_header(prp, buf, struct tcph);
	hlen = TCPH_HLEN(*tcp);
	if (hlen > len) {
		prp->error |= PRP_ERR_HLEN;
		return;
	}
	prp_poff(prp) = prp_soff(prp) + hlen;

	ipprp = find_ipprp(prp);
	if ((ipprp == NULL) ||
	    (pseudo_cksum(prp, ipprp, buf, IPPROT_TCP) & 0xFFFF) != 0) {
		prp->error |= PRP_ERR_CKSUM;
	}

	if (hlen > TCPH_MINLEN)
		tcp_parse_opt(prp, tcp, hlen - TCPH_MINLEN);
}


static int tcp_fixlen(struct prparse *prp, byte_t *buf)
{
	struct tcph *tcp;
	long hlen;

	abort_unless(prp);
	tcp = prp_header(prp, buf, struct tcph);
	hlen = prp_hlen(prp);
	if ((hlen < TCPH_MINLEN) || (hlen > TCPH_MAXLEN) || ((hlen & 3) != 0) ||
	    (hlen > prp_totlen(prp)))
		return -1;
	tcp->doff = hlen << 2;
	prp->error &= ~(PRP_ERR_TRUNC | PRP_ERR_HLEN | PRP_ERR_TOOSMALL);

	return 0;
}


static int tcp_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct tcph *tcp;
	struct prparse *ipprp = find_ipprp(prp->region);

	abort_unless(prp);
	tcp = prp_header(prp, buf, struct tcph);
	if (prp_hlen(prp) < TCPH_MINLEN || ipprp == NULL)
		return -1;
	tcp->cksum = 0;
	tcp->cksum = pseudo_cksum(prp, ipprp, buf, IPPROT_TCP);
	prp->error &= ~PRP_ERR_CKSUM;

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
static void icmp_update(struct prparse *prp, byte_t *buf);

static struct prparse *icmp_parse(struct prparse *reg, byte_t *buf,
				  ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newprp(sizeof(struct icmp_parse), PRID_ICMP, off, 0, maxlen, 0,
		     &icmp_prparse_ops, reg, PRP_ICMP_NXFIELDS);
	if (!prp)
		return NULL;
	icmp_update(prp, buf);
	return prp;
}


static int icmp_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
		       uint *prid, ulong *off, ulong *maxlen)
{
	struct icmph *icmp;

	if (cld != NULL)
		return 0;

	icmp = prp_header(reg, buf, struct icmph);
	/* types which can have a returned IP header in them */
	if (ICMPT_HAS_OPKT(icmp->type)) {
		*prid = PRID_IPV4;
		*off = prp_poff(reg);
		*maxlen = prp_plen(reg);
		return 1;
	} else {
		return 0;
	}
}


static int icmp_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_ICMP, ICMPH_LEN, 0, enclose);
}


static int icmp_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		    int enclose)
{
	struct prparse *prp;
	struct icmph *icmp;

	if (ps->hlen != ICMPH_LEN) {
		errno = EINVAL;
		return -1;
	}

	prp = newprp(sizeof(struct icmp_parse), PRID_ICMP, ps->off, ps->hlen,
		     ps->plen, ps->tlen, &icmp_prparse_ops, reg,
		     PRP_ICMP_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf) {
		memset(prp_header(prp, buf, void), 0, prp_hlen(prp));
		icmp = prp_header(prp, buf, struct icmph);
		icmp->type = ICMPT_ECHO_REQUEST;
		icmp->cksum = ~ones_sum(icmp, prp_totlen(prp), 0);
	}

	return 0;
}


static void icmp_update(struct prparse *prp, byte_t *buf)
{
	struct icmph *icmp;

	prp->error = 0;
	prp_reset_xfields(prp);

	if (prp_totlen(prp) < ICMPH_LEN) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}
	prp_poff(prp) = prp_soff(prp) + ICMPH_LEN;

	icmp = prp_header(prp, buf, struct icmph);
	if ((~ones_sum(icmp, prp_totlen(prp), 0) & 0xFFFF) != 0)
		prp->error |= PRP_ERR_CKSUM;

	/* set offsets for the subfields that may or may not be present */
	if (ICMPT_IS_QUERY(icmp->type)) {
		prp->offs[PRP_ICMPFLD_QUERY] = prp_soff(prp) + 4;
		if (ICMPT_IS_TSTAMP(icmp->type))
			prp->offs[PRP_ICMPFLD_TS] = prp_soff(prp) + 8;
	} else if (icmp->type == ICMPT_PARAM_PROB) {
		prp->offs[PRP_ICMPFLD_PPTR] = prp_soff(prp) + 4;
	} else if (icmp->type == ICMPT_DEST_UNREACH) {
		if (icmp->code == ICMPC_TTL_EXCEEDED)
			prp->offs[PRP_ICMPFLD_MTU] = prp_soff(prp) + 4;
		else
			prp->offs[PRP_ICMPFLD_RESERVED] = prp_soff(prp) + 4;
	} else if (icmp->type == ICMPT_REDIRECT) {
		prp->offs[PRP_ICMPFLD_GW] = prp_soff(prp) + 4;
	} else {
		prp->offs[PRP_ICMPFLD_RESERVED] = prp_soff(prp) + 4;
	}
}


static int icmp_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct icmph *icmp = prp_header(prp, buf, struct icmph);
	if (prp_hlen(prp) != ICMPH_LEN)
		return -1;
	icmp->cksum = 0;
	icmp->cksum = ~ones_sum(icmp, prp_totlen(prp), 0);
	prp->error &= ~PRP_ERR_CKSUM;
	return 0;
}


/* -- IPv6 functions -- */
static void ipv6_update(struct prparse *prp, byte_t *buf);

static int isv6ext(uint8_t proto)
{
	/* we consider IPsec protocols their own protocol */
	/* IPPROT_ESP could go here except that we can't */
	/* parse past it.  So this function should be called */
	/* is_v6_parsable_ext() */
	return (proto == IPPROT_V6_HOPOPT) ||
	       (proto == IPPROT_V6_ROUTE_HDR) ||
	       (proto == IPPROT_V6_FRAG_HDR) ||
	       (proto == IPPROT_V6_DSTOPS) || 
	       (proto == IPPROT_AH) ||
	       (proto == IPPROT_ESP);
}


/* search for jumbogram options */
static int parse_ipv6_hopopt(struct prparse *prp, struct ipv6h *ip6,
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
			prp->error |= PRP_ERR_OPTLEN | PRP_ERR_HLEN;
			return -1;
		}
		if (p[0] == 0xC2) {	/* jumbogram option */
			if (prp_off_valid(prp, PRP_IPV6FLD_JLEN)) {
				prp->error |= PRP_ERR_OPTLEN | PRP_ERR_HLEN;
				return -1;
			}
			if ((p[1] != 4) || (ip6->len != 0) ||
			    prp_off_valid(prp, PRP_IPV6FLD_JLEN) || 
			    (((p - (byte_t *) ip6) & 3) != 2)) {
				prp->error |= PRP_ERR_OPTERR | PRP_ERR_HLEN;
				return -1;
			}
			prp->offs[PRP_IPV6FLD_JLEN] = (p - (byte_t *)ip6) + 
				          	      prp_soff(prp);
		}
		p += p[1] + 2;
	}
	return 0;
}


static int setv6opt(struct prparse *prp, int oidx, ulong xoff)
{
	if (!prp_off_valid(prp, oidx)) {
		prp->offs[oidx] = prp_soff(prp) + IPV6H_LEN + xoff;
		return 1;
	} else {
		return 0;
	}
}


static int parse_reg_v6_opt(struct prparse *prp, ulong xoff, uint8_t opt,
			    byte_t *p)
{
	switch(opt) {
	case IPPROT_V6_HOPOPT:
		/* hop-by-hop options can only come first */
		if (xoff != 0) {
			prp->error |= PRP_ERR_OPTERR | PRP_ERR_HLEN;
			return -1;
		}
		prp->offs[PRP_IPV6FLD_HOPOPT] =
			prp_soff(prp) + IPV6H_LEN + xoff;
		break;

	case IPPROT_V6_ROUTE_HDR:
		if (!setv6opt(prp, PRP_IPV6FLD_RTOPT, xoff))
			setv6opt(prp, PRP_IPV6FLD_EXTOPT, xoff);
		break;

	case IPPROT_V6_DSTOPS:
		if (!setv6opt(prp, PRP_IPV6FLD_DSTOPT1, xoff))
			if (!setv6opt(prp, PRP_IPV6FLD_DSTOPT2, xoff))
				setv6opt(prp, PRP_IPV6FLD_EXTOPT, xoff);
		break;
	default:
		if (!setv6opt(prp, PRP_IPV6FLD_UNKOPT, xoff))
			setv6opt(prp, PRP_IPV6FLD_EXTOPT, xoff);
		break;
	}

	return 0;
}


static int parse_ipv6_opt(struct prparse *prp, struct ipv6h *ip6, ulong len)
{
	ulong xlen = 0;
	uint8_t nexth;
	uint olen;
	byte_t *p;

	abort_unless(len >= 0);

	nexth = ip6->nxthdr;
	p = (byte_t *)ip6 + IPV6H_LEN;

	while (isv6ext(nexth)) {
		if (len - xlen < 8) {
			prp->error |= PRP_ERR_OPTLEN | PRP_ERR_HLEN;
			return -1;
		}
		/* 
		 * four cases for option lengths
		 *  - AH = p[1] * 4 + 8
		 *  - ESP = > 12 -> we won't parse past this
		 *  - Frag = 8
		 *  - All others = p[1] * 8 + 8
		 */
		if (nexth == IPPROT_AH) {
			/* AH is idiotic and mostly useless */
			olen = (p[1] << 2) + 8;
			setv6opt(prp, PRP_IPV6FLD_AHH, xlen);
		} else if (nexth == IPPROT_ESP) {
			if (len - xlen < 12) {
				prp->error |= PRP_ERR_OPTLEN | PRP_ERR_HLEN;
				return -1;
			}
			setv6opt(prp, PRP_IPV6FLD_ESPH, xlen);
			/* TODO try to decode NULL encryption headers? */
			break;
		} else if (nexth == IPPROT_V6_FRAG_HDR) {
			/* Only one fragment header is allowed */
			if (prp_off_valid(prp, PRP_IPV6FLD_FRAGH)) {
				prp->error |= PRP_ERR_OPTERR | PRP_ERR_HLEN;
				return -1;
			}
			prp->offs[PRP_IPV6FLD_FRAGH] = prp_soff(prp) +
						       IPV6H_LEN + xlen;
			olen = 8;
			
		} else {
			if (parse_reg_v6_opt(prp, xlen, nexth, p) < 0)
				return -1;
			olen = (p[1] << 3) + 8;
		}

		if (len - xlen < olen) {
			prp->error |= PRP_ERR_OPTLEN | PRP_ERR_HLEN;
			return -1;
		}

		nexth = p[0];
		prp->offs[PRP_IPV6FLD_NXTHDR] =
			xlen + IPV6H_LEN + prp_soff(prp);

		xlen += olen;
		p += olen;
	}

	prp_poff(prp) = prp_soff(prp) + IPV6H_LEN + xlen;

	return 0;
}


static struct prparse *ipv6_parse(struct prparse *reg, byte_t *buf,
				  ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newprp(sizeof(struct ipv6_parse), PRID_IPV6, off, 0, maxlen, 0,
		     &ipv6_prparse_ops, reg, PRP_IPV6_NXFIELDS);
	if (!prp)
		return NULL;
	ipv6_update(prp, buf);
	return prp;
}


int ipv6_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
	        uint *prid, ulong *off, ulong *maxlen)
{
	byte_t *p;
	ushort foff;
	uint8_t nexth;

	if (cld != NULL)
		return 0;

	abort_unless(buf);

	/* We treat AH and ESP as their own protocols, not IPv6 options */
	/* ESP we can't parse past since the next header type is encrypted. */
	/* But we can parse past AH, and there may be destination options */
	/* past said header.  In other words, the IPv6 header may extend */
	/* past the start of the next protocol. Did I mention how little */
	/* I like AH's design. */
	if (prp_off_valid(reg, PRP_IPV6FLD_AHH)) {
		*prid = PRID_BUILD(PRID_PF_INET, IPPROT_AH);
		*off = reg->offs[PRP_IPV6FLD_AHH];
		*maxlen = prp_totlen(reg) - reg->offs[PRP_IPV6FLD_AHH];
	} else {
		ulong nhoff = reg->offs[PRP_IPV6FLD_NXTHDR];
		abort_unless(nhoff != PRP_OFF_INVALID);
		abort_unless(nhoff >= prp_soff(reg));
		abort_unless(nhoff < prp_eoff(reg));
		nexth = buf[nhoff];
		*prid = PRID_BUILD(PRID_PF_INET, nexth);
		if (prp_off_valid(reg, PRP_IPV6FLD_FRAGH)) {
			/* we can't parse the next header if we aren't the */
			/* first fragment. */
			p = buf + reg->offs[PRP_IPV6FLD_FRAGH] + 2;
			foff = ntoh16x(p);
			foff &= ~7;
			if (foff > 0)
				return 0;
		}
		*off = prp_poff(reg);
		*maxlen = prp_plen(reg);
	}
	return 1;
}


static int ipv6_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_IPV6, IPV6H_LEN, 0, enclose);
}


static int ipv6_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		    int enclose)
{
	struct prparse *prp, *cld;
	struct ipv6h *ip6;

	if (ps->hlen < IPV6H_LEN || ps->plen > 65535) {
		errno = EINVAL;
		return -1;
	}

	prp = newprp(sizeof(struct ipv6_parse), PRID_IPV6, ps->off, ps->hlen,
		     ps->plen, ps->tlen, &ipv6_prparse_ops, reg,
		     PRP_IPV6_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf) {
		memset(prp_header(prp, buf, void), 0, prp_hlen(prp));
		ip6 = prp_header(prp, buf, struct ipv6h);
		prp->offs[PRP_IPV6FLD_NXTHDR] = prp_soff(prp) + 6;
		*(byte_t *)ip6 = 0x60;
		ip6->len = hton16(prp_plen(prp));
		ip6->nxthdr = IPPROT_RESERVED;
		if (enclose) {
			cld = prp_next_in_region(prp, prp);
			if (cld != NULL)
				ip6->nxthdr = pridtoiptype(cld->prid);
		}
	}

	return 0;
}


static void ipv6_update(struct prparse *prp, byte_t *buf)
{
	struct ipv6h *ip6;
	ushort paylen;
	ulong len, jlen, extra, hbhlen;
	byte_t *p;
	int rv;

	prp->error = 0;
	prp_reset_xfields(prp);
	ip6 = prp_header(prp, buf, struct ipv6h);
	prp->offs[PRP_IPV6FLD_NXTHDR] = prp_soff(prp) + 6;

	len = prp_totlen(prp);
	if (len < IPV6H_LEN) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}

	if (IPV6H_PVERSION(ip6) != 6)
		prp->error |= PRP_ERR_INVALID;

	paylen = ntoh16x(&ip6->len);
	if (paylen > len - IPV6H_LEN)
		prp->error |= PRP_ERR_TRUNC;

	prp_poff(prp) = prp_soff(prp) + IPV6H_LEN;
	if (paylen == 0 && ip6->nxthdr == IPPROT_V6_HOPOPT) {
		if (len < 48) {
			prp->error |= PRP_ERR_OPTERR | PRP_ERR_HLEN |
				      PRP_ERR_TRUNC;
			return;
		}
		p = buf + prp_poff(prp);
		hbhlen = p[1] * 8;
		if (hbhlen > prp_plen(prp)) {
			prp->error |= PRP_ERR_OPTERR | PRP_ERR_HLEN |
				      PRP_ERR_TRUNC;
			return;
		}
		rv = parse_ipv6_hopopt(prp, ip6, (byte_t *)(ip6+1), hbhlen);
		if (rv < 0 || !prp_off_valid(prp, PRP_IPV6FLD_JLEN)) {
			prp->error |= PRP_ERR_TRUNC;
			return;
		}
		jlen = ntoh32x(buf + prp->offs[PRP_IPV6FLD_JLEN]);
		if (jlen > len - IPV6H_LEN) {
			prp->error |= PRP_ERR_OPTERR | PRP_ERR_TRUNC;
			return;
		}
		if (jlen < len - IPV6H_LEN) {
			extra = len - jlen - IPV6H_LEN;
			prp_eoff(prp) = prp_toff(prp) = 
				prp_soff(prp) + IPV6H_LEN + jlen;
			len -= extra;
		}
	} else if (paylen < len - IPV6H_LEN) {
		extra = len - paylen - IPV6H_LEN;
		prp_eoff(prp) = prp_toff(prp) = prp_soff(prp) + IPV6H_LEN +
						paylen;
		len -= extra;
	}

	/* sets hlen */
	parse_ipv6_opt(prp, ip6, len - IPV6H_LEN);
}


static int ipv6_fixnxt(struct prparse *prp, byte_t *buf)
{
	struct prparse *next;

	next = prp_next(prp);
	if (!prp_list_end(next) && prp_off_valid(prp, PRP_IPV6FLD_NXTHDR))
		*(buf + prp->offs[PRP_IPV6FLD_NXTHDR]) =
			pridtoiptype(next->prid);
	return 0;
}


static int ipv6_fixlen(struct prparse *prp, byte_t *buf)
{
	struct ipv6h *ip6 = prp_header(prp, buf, struct ipv6h);
	ushort plen;

	abort_unless(prp && buf);
	if (prp_hlen(prp) < 40)
		return -1;
	if (!prp_off_valid(prp, PRP_IPV6FLD_JLEN)) {
		if (prp_plen(prp) > 65535)
			return -1;
		plen = prp_plen(prp);
		hton16i(plen, &ip6->len);
	} else {
		if (prp->offs[PRP_IPV6FLD_JLEN] > prp_totlen(prp) - 2)
			return -1;
		hton16i(0, &ip6->len);
		hton32i(prp_plen(prp), buf + prp->offs[PRP_IPV6FLD_JLEN]);
	}
	prp->error &= ~(PRP_ERR_TRUNC | PRP_ERR_HLEN | PRP_ERR_TOOSMALL);

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
static void icmp6_update(struct prparse *prp, byte_t *buf);

static struct prparse *icmp6_parse(struct prparse *reg, byte_t *buf,
				   ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newprp(sizeof(struct icmp6_parse), PRID_ICMP6, off, 0, maxlen, 0,
		     &icmpv6_prparse_ops, reg, PRP_ICMP6_NXFIELDS);
	if (!prp)
		return NULL;
	icmp6_update(prp, buf);
	return prp;
}


static int icmp6_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
		        uint *prid, ulong *off, ulong *maxlen)
{
	struct icmp6h *icmp6;

	if (cld != NULL)
		return 0;

	icmp6 = prp_header(reg, buf, struct icmp6h);
	if (ICMP6T_IS_ERR(icmp6->type)) {
		*prid = PRID_IPV6;
		*off = prp_poff(reg);
		*maxlen = prp_plen(reg);
		return 1;
	} else if (prp_off_valid(reg, PRP_ICMP6FLD_RDRHDR)) { 
		*prid = PRID_IPV6;
		*off = reg->offs[PRP_ICMP6FLD_RDRHDR] + 8;
		*maxlen = reg->offs[PRP_ICMP6FLD_RDRHDR_EOFF] - *off;
		return 1;
	} else {
		return 0;
	}
}


static int icmp6_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_ICMP6, ICMP6H_LEN, 0, enclose);
}


static int icmp6_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		     int enclose)
{
	struct prparse *prp, *ipprp;
	struct icmp6h *icmp6;

	prp = newprp(sizeof(struct icmp6_parse), PRID_ICMP6, ps->off, ps->hlen,
		     ps->plen, ps->tlen, &icmpv6_prparse_ops, reg,
		     PRP_ICMP6_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf) {
		memset(prp_header(prp, buf, void), 0, prp_hlen(prp));
		icmp6 = prp_header(prp, buf, struct icmp6h);
		icmp6->type = ICMP6T_ECHO_REQUEST;
		ipprp = find_ipprp(reg);
		if (ipprp == NULL)  {
			prp->error |= PRP_ERR_CKSUM;
		} else {
			icmp6->cksum = pseudo_cksum(prp, ipprp, buf, 
						    IPPROT_ICMPV6);
		}
	}

	return 0;
}


static void parse_icmp6_nd_opt(struct prparse *prp, byte_t *buf, int optoff)
{
	struct icmp6_nd_opt *opt;
	ulong off;

	off = prp_soff(prp) + optoff;
	if (prp_eoff(prp) - off >= ICMP6_ND_OPT_MINLEN)
		prp->offs[PRP_ICMP6FLD_NDPOPT] = off;

	while (off < prp_eoff(prp)) {
		if (prp_eoff(prp) - off < ICMP6_ND_OPT_MINLEN) {
			prp->error |= PRP_ERR_OPTLEN | PRP_ERR_OPTERR;
			break;
		}
		opt = (struct icmp6_nd_opt *)(buf + off);
		/* check for malformed length */
		if ((opt->len == 0) || (opt->len * 8 > prp_eoff(prp) - off)) {
			prp->error |= PRP_ERR_OPTLEN;
			return;
		}
		switch (opt->type) {
		case ICMP6_ND_OPT_SRCLLA:
			prp->offs[PRP_ICMP6FLD_SRCLLA] = off;
			prp->offs[PRP_ICMP6FLD_SRCLLA_EOFF] = off + opt->len*8;
			break;
                case ICMP6_ND_OPT_TGTLLA:
			prp->offs[PRP_ICMP6FLD_TGTLLA] = off;
			prp->offs[PRP_ICMP6FLD_TGTLLA_EOFF] = off + opt->len*8;
			break;
		case ICMP6_ND_OPT_PFXINFO:
			prp->offs[PRP_ICMP6FLD_PFXINFO] = off;
			if ((prp_eoff(prp) - off < ICMP6_ND_PFXINFO_OLEN) ||
			    (opt->len != ICMP6_ND_PFXINFO_OLEN / 8))
				prp->error |= PRP_ERR_OPTLEN;
			break;
                case ICMP6_ND_OPT_RDRHDR:
			prp->offs[PRP_ICMP6FLD_RDRHDR] = off;
			prp->offs[PRP_ICMP6FLD_RDRHDR_EOFF] = off + opt->len*8;
			break;
		case ICMP6_ND_OPT_MTU:
			prp->offs[PRP_ICMP6FLD_MTU] = off;
			if (opt->len != ICMP6_ND_MTU_OLEN / 8)
				prp->error |= PRP_ERR_OPTLEN;
			break;
		case ICMP6_ND_OPT_RADVIVL:
			prp->offs[PRP_ICMP6FLD_RADVIVL] = off;
			if (opt->len != ICMP6_ND_RADVIVL_OLEN / 8)
				prp->error |= PRP_ERR_OPTLEN;
			break;
		case ICMP6_ND_OPT_AGTINFO:
			prp->offs[PRP_ICMP6FLD_AGTINFO] = off;
			if (opt->len != ICMP6_ND_AGTINFO_OLEN / 8)
				prp->error |= PRP_ERR_OPTLEN;
			break;
		default:
			prp->error |= PRP_ERR_OPTERR;
			break;
		}

		off += opt->len * 8;
	}

	prp_poff(prp) = off;
}


static void icmp6_update(struct prparse *prp, byte_t *buf)
{
	struct prparse *ip6prp;
	struct icmp6h *icmp6;
	int oidx;
	int hlen;

	prp->error = 0;
	prp_reset_xfields(prp);

	if (prp_totlen(prp) < ICMP6H_LEN) {
		prp->error = PRP_ERR_TOOSMALL;
		return;
	}
	
	ip6prp = find_ipprp(prp->region);
	if ((ip6prp == NULL) ||
	    ((pseudo_cksum(prp, ip6prp, buf, IPPROT_ICMPV6) & 0xFFFF) != 0)) {
		prp->error |= PRP_ERR_CKSUM;
	}

	icmp6 = prp_header(prp, buf, struct icmp6h);
	if (ICMP6T_IS_ERR(icmp6->type)) {

		/* error types */
		prp_poff(prp) = prp_soff(prp) + ICMP6H_LEN;
		if (icmp6->type == ICMP6T_PARAM_PROB)
			prp->offs[PRP_ICMP6FLD_PPTR] = prp_soff(prp) + 4;
		else
			prp->offs[PRP_ICMP6FLD_ERESV] = prp_soff(prp) + 4;

	} else if (ICMP6T_IS_ECHO(icmp6->type)) {

		/* echo request/reply */
		prp_poff(prp) = prp_soff(prp) + ICMP6H_LEN;
		prp->offs[PRP_ICMP6FLD_ECHO] = prp_soff(prp) + 4;

	} else if (ICMP6T_IS_NDP(icmp6->type)) {

		/* NDP packets */
		switch(icmp6->type) {
		case ICMP6T_RSOLICIT:
			hlen = ICMP6_ND_RSOL_HLEN;
			oidx = PRP_ICMP6FLD_RSOL;
			break;
		case ICMP6T_RADVERT:
			hlen = ICMP6_ND_RADV_HLEN;
			oidx = PRP_ICMP6FLD_RADV;
			break;
		case ICMP6T_NSOLICIT:
		case ICMP6T_NADVERT:
			hlen = ICMP6_ND_NEIGH_HLEN;
			oidx = PRP_ICMP6FLD_NEIGH;
			break;
		case ICMP6T_NREDIR:
			hlen = ICMP6_ND_RDR_HLEN;
			oidx = PRP_ICMP6FLD_REDIR;
			break;
		default:
			abort_unless(0);
		}

		if (prp_totlen(prp) < hlen) {
			prp_poff(prp) = prp_soff(prp) + ICMP6H_LEN;
			prp->error = PRP_ERR_TOOSMALL;
		} else {
			prp->offs[oidx] = prp_soff(prp) + 4;
			parse_icmp6_nd_opt(prp, buf, hlen);
		}

	} else {
		/* catch all */
		prp_poff(prp) = prp_soff(prp) + ICMP6H_LEN;

	}
}


static int icmp6_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct prparse *ipprp;
	struct icmp6h *icmp6 = prp_header(prp, buf, struct icmp6h);
	ipprp = find_ipprp(prp->region);
	if (ipprp == NULL) 
		return -1;
	icmp6->cksum = 0;
	icmp6->cksum = pseudo_cksum(prp, ipprp, buf, IPPROT_ICMPV6);
	prp->error &= ~PRP_ERR_CKSUM;
	return 0;
}


/* -- ops for GRE type -- */
static void gre_update(struct prparse *prp, byte_t *buf);

static struct prparse *gre_parse(struct prparse *reg, byte_t *buf,
				 ulong off, ulong maxlen)
{
	struct prparse *prp;
	struct greh *gre;
	uint prid = PRID_GRE;
	ushort proto;

	if (maxlen >= NVGRE_HLEN) {
		gre = (struct greh *)(buf + off);
		proto = ntoh16x(&gre->proto);
		if (GRE_VERSION(gre) == 0 && proto == ETHTYPE_TEB &&
		    GRE_FLAGS(gre) == GRE_FLAG_KEY)
			prid = PRID_NVGRE;
	}

	prp = newprp(sizeof(struct gre_parse), prid, off, 0, maxlen, 0,
		     &gre_prparse_ops, reg, PRP_GRE_NXFIELDS);
	if (!prp)
		return NULL;

	gre_update(prp, buf);

	return prp;
}


int gre_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
	       uint *prid, ulong *off, ulong *maxlen)
{
	struct greh *gre;
	uint x;

	if (cld != NULL)
		return 0;

	gre = prp_header(reg, buf, struct greh);
	x = etypetoprid(ntoh16x(&gre->proto));
	if (x == PRID_NONE)
		return 0;
	*prid = x;
	*off = prp_poff(reg);
	*maxlen = prp_plen(reg);
	return 1;
}


static int gre_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_GRE, GRE_BASE_HLEN, 0, enclose);
}


static int gre_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		   int enclose)
{
	struct prparse *prp, *cld;
	uint16_t etype;
	struct greh *gre;

	abort_unless(reg && ps && ps->prid == PRID_GRE);
	if (ps->hlen < GRE_BASE_HLEN) {
		errno = EINVAL;
		return -1;
	}

	prp = newprp(sizeof(struct gre_parse), PRID_GRE, ps->off, ps->hlen,
		     ps->plen, ps->tlen, &gre_prparse_ops, reg,
		     PRP_GRE_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf && prp_hlen(prp) >= GRE_BASE_HLEN) {
		memset(prp_header(prp, buf, void), 0, prp_hlen(prp));
		if (enclose) {
			cld = prp_next_in_region(prp, prp);
			if (cld != NULL) {
				gre = prp_header(prp, buf, struct greh);
				etype = pridtoetype(cld->prid);
				hton16i(etype, &gre->proto);
			}
		}
	}

	return 0;
}


static void gre_update(struct prparse *prp, byte_t *buf)
{
	uint hlen;
	struct greh *gre;
	uint off;
	ushort sum;
	ulong len;
	ushort proto;

	prp->error = 0;
	prp_reset_xfields(prp);

	prp->prid = PRID_GRE;
	len = prp_totlen(prp);
	if (len < GRE_BASE_HLEN) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}

	gre = prp_header(prp, buf, struct greh);
	hlen = GRE_HLEN(gre);
	if (len < hlen) {
		prp->error |= PRP_ERR_HLEN;
		return;
	}
	prp_poff(prp) = prp_soff(prp) + hlen;

	off = GRE_BASE_HLEN;
	if ((gre->flags & GRE_FLAG_CKSUM) != 0) {
		prp->offs[PRP_GREFLD_CKSUM] = prp_soff(prp) + off;
		off += 4;
		sum = ~ones_sum(gre, prp_totlen(prp), 0) & 0xFFFF;
		if (sum != 0)
			prp->error |= PRP_ERR_CKSUM;
	}

	if ((gre->flags & GRE_FLAG_KEY) != 0) {
		prp->offs[PRP_GREFLD_KEY] = prp_soff(prp) + off;
		off += 4;
	}

	if ((gre->flags & GRE_FLAG_SEQ) != 0)
		prp->offs[PRP_GREFLD_SEQ] = prp_soff(prp) + off;

	if (GRE_VERSION(gre) != 0) {
		prp->error |= PRP_ERR_INVALID;
	} else {
		/* check for NVGRE */
		proto = ntoh16x(&gre->proto);
		if (proto == ETHTYPE_TEB && GRE_FLAGS(gre) == GRE_FLAG_KEY)
			prp->prid = PRID_NVGRE;
	}
}


static int gre_fixnxt(struct prparse *prp, byte_t *buf)
{
	struct prparse *next;
	struct greh *gre;
	next = prp_next(prp);
	if (!prp_list_end(next)) {
		gre = prp_header(prp, buf, struct greh);
		hton16i(pridtoetype(next->prid), &gre->proto);
	}
	return 0;
}


static int gre_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct greh *gre;
	uint16_t *sump;

	abort_unless(prp);
	gre = prp_header(prp, buf, struct greh);
	if (prp_hlen(prp) < GRE_HLEN(gre))
		return -1;
	if ((gre->flags & GRE_FLAG_CKSUM) != 0) {
		sump = (uint16_t *)(gre + 1);
		*sump = 0;
		*sump = ~ones_sum(gre, prp_totlen(prp), 0);
	}
	prp->error &= ~PRP_ERR_CKSUM;

	return 0;
}


static int nvgre_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_NVGRE, NVGRE_HLEN, 0, enclose);
}


static int nvgre_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		     int enclose)
{
	struct prparse *prp, *cld;
	uint16_t etype;
	struct nvgreh *nvgre;

	abort_unless(reg && ps && ps->prid == PRID_NVGRE);
	if (ps->hlen != NVGRE_HLEN) {
		errno = EINVAL;
		return -1;
	}

	prp = newprp(sizeof(struct gre_parse), PRID_NVGRE, ps->off, ps->hlen,
		     ps->plen, ps->tlen, &gre_prparse_ops, reg,
		     PRP_GRE_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf && prp_hlen(prp) == NVGRE_HLEN) {
		nvgre = prp_header(prp, buf, struct nvgreh);
		memset(nvgre, 0, NVGRE_HLEN);
		nvgre->flags = GRE_FLAG_KEY;
		if (enclose) {
			cld = prp_next_in_region(prp, prp);
			if (cld != NULL) {
				etype = pridtoetype(cld->prid);
				hton16i(etype, &nvgre->proto);
			}
		}
	}

	return 0;
}


/* -- ops for VXLAN type -- */
static void vxlan_update(struct prparse *prp, byte_t *buf);

static struct prparse *vxlan_parse(struct prparse *reg, byte_t *buf,
				   ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newprp(sizeof(struct prparse), PRID_VXLAN, off, 0, maxlen, 0,
		     &vxlan_prparse_ops, reg, 0);
	if (!prp)
		return NULL;
	vxlan_update(prp, buf);
	return prp;
}


int vxlan_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
	         uint *prid, ulong *off, ulong *maxlen)
{
	if (cld != NULL || prp_plen(reg) < ETHHLEN)
		return 0;
	*prid = PRID_ETHERNET2;
	*off = prp_poff(reg);
	*maxlen = prp_plen(reg);
	return 1;
}


static int vxlan_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_VXLAN, VXLAN_HLEN, 0, enclose);
}


static int vxlan_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		     int enclose)
{
	struct prparse *prp;
	struct vxlanh *vxh;

	abort_unless(reg && ps && ps->prid == PRID_VXLAN);
	if (ps->hlen < VXLAN_HLEN) {
		errno = EINVAL;
		return -1;
	}

	prp = newprp(sizeof(struct prparse), PRID_VXLAN, ps->off, ps->hlen,
		     ps->plen, ps->tlen, &vxlan_prparse_ops, reg, 0);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf) {
		vxh = prp_header(prp, buf, struct vxlanh);
		memset(vxh, 0, VXLAN_HLEN);
		hton32i(VXLAN_FLAG_VNI, &vxh->flags);
	}

	return 0;
}


static void vxlan_update(struct prparse *prp, byte_t *buf)
{
	uint len;
	struct vxlanh *vxh;
	ulong flags;

	prp->error = 0;
	prp_reset_xfields(prp);

	len = prp_totlen(prp);
	if (len < VXLAN_HLEN) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}

	prp_poff(prp) = prp_soff(prp) + VXLAN_HLEN;
	vxh = prp_header(prp, buf, struct vxlanh);
	flags = hton32(vxh->flags);
	if ((flags & VXLAN_FLAG_MSK) != VXLAN_FLAG_VNI)
		prp->error |= PRP_ERR_INVALID;
}


/* -- ops for MPLS type -- */
static void mpls_update(struct prparse *prp, byte_t *buf);

static struct prparse *mpls_parse(struct prparse *reg, byte_t *buf,
				  ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newprp(sizeof(struct mpls_parse), PRID_MPLS, off, 0,
		     maxlen, 0, &mpls_prparse_ops, reg, PRP_MPLS_NXFIELDS);
	if (!prp)
		return NULL;
	mpls_update(prp, buf);
	return prp;
}


int mpls_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
	        uint *prid, ulong *off, ulong *maxlen)
{
	byte_t *p;
	struct ipv4h *ip;
	struct ipv6h *ip6;

	if (cld != NULL || prp_plen(reg) < IPH_MINLEN)
		return 0;

	abort_unless(buf);

	p = prp_payload(reg, buf);
	if ((*p & 0xF0) == 0x40) {
		ip = (struct ipv4h *)p;
		if (IPH_HLEN(*ip) >= IPH_MINLEN && 
		    IPH_HLEN(*ip) <= prp_plen(reg) &&
		    ntoh16(ip->len) <= prp_plen(reg)) {
			*prid = PRID_IPV4;
			*off = prp_poff(reg);
			*maxlen = prp_plen(reg);
			return 1;
		}
	} else if ((*p & 0xF0) == 0x60 && prp_plen(reg) >= IPV6H_LEN) {
		ip6 = (struct ipv6h *)p;
		if (ntoh16(ip6->len) <= prp_plen(reg) - IPV6H_LEN) {
			*prid = PRID_IPV6;
			*off = prp_poff(reg);
			*maxlen = prp_plen(reg);
			return 1;
		}
	}
	return 0;
}


static int mpls_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, PRID_MPLS, MPLS_HLEN, 0, enclose);
}


static int mpls_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		    int enclose)
{
	struct prparse *prp;
	struct mpls_label *mpls;
	uint i;
	uint nlabels;

	abort_unless(reg && ps && ps->prid == PRID_MPLS);
	if (ps->hlen < MPLS_HLEN || (ps->hlen % MPLS_HLEN) != 0) {
		errno = EINVAL;
		return -1;
	}

	prp = newprp(sizeof(struct mpls_parse), PRID_MPLS, 
		     ps->off, ps->hlen, ps->plen, ps->tlen,
		     &eth_prparse_ops, reg, PRP_MPLS_NXFIELDS);
	if (!prp)
		return -1;

	prp_add_insert(reg, prp, enclose);
	if (buf && prp_hlen(prp) >= MPLS_HLEN) {
		mpls = prp_header(prp, buf, struct mpls_label);
		memset(mpls, 0, prp_hlen(prp));
		nlabels = prp_hlen(prp) / MPLS_HLEN;
		for (i = 0; i < nlabels; ++i)
			mpls[i].label = hton32(64 << MPLS_TTL_SHF);
		mpls[nlabels-1].label |= hton32(1 << MPLS_BOS_SHF);
	}

	return 0;
}


static void mpls_update(struct prparse *prp, byte_t *buf)
{
	ulong max;
	ulong i;
	struct mpls_label *mpls;

	prp->error = 0;
	prp_reset_xfields(prp);

	if (prp_totlen(prp) < MPLS_HLEN) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}

	prp_poff(prp) = prp_soff(prp);
	max = prp_totlen(prp) / MPLS_HLEN;
	mpls = prp_header(prp, buf, struct mpls_label);
	i = 0;
	while (i < max) {
		if (i > 0 && i < PRP_MPLS_NXFIELDS)
			prp->offs[PRP_OI_EXTRA + i] = prp_poff(prp);
		prp_poff(prp) += MPLS_HLEN;
		if (MPLS_BOS(ntoh32(mpls->label)))
			return;
		++i;
		++mpls;
	}
	prp->error |= PRP_ERR_INVALID;
}


/* -- op structures for default initialization -- */
struct proto_parser_ops eth_proto_parser_ops = {
	eth_parse,
	eth_nxtcld,
	eth_getspec,
	eth_add
};

struct prparse_ops eth_prparse_ops = {
	eth_update,
	eth_fixnxt,
	prp_nop_fixlen,
	prp_nop_fixcksum,
	stdpr_copy,
	stdpr_free
};

struct proto_parser_ops arp_proto_parser_ops = {
	arp_parse,
	stdpr_nxtcld,
	arp_getspec,
	arp_add
};

struct prparse_ops arp_prparse_ops = {
	arp_update,
	prp_nop_fixnxt,
	arp_fixlen,
	prp_nop_fixcksum,
	arp_copy,
	stdpr_free
};

struct proto_parser_ops ipv4_proto_parser_ops = {
	ipv4_parse,
	ipv4_nxtcld,
	ipv4_getspec,
	ipv4_add
};

struct prparse_ops ipv4_prparse_ops = {
	ipv4_update,
	ipv4_fixnxt,
	ipv4_fixlen,
	ipv4_fixcksum,
	ipv4_copy,
	ipv4_free
};

struct proto_parser_ops ipv6_proto_parser_ops = {
	ipv6_parse,
	ipv6_nxtcld,
	ipv6_getspec,
	ipv6_add
};

struct prparse_ops ipv6_prparse_ops = {
	ipv6_update,
	ipv6_fixnxt,
	ipv6_fixlen,
	prp_nop_fixcksum,
	ipv6_copy,
	ipv6_free
};

struct proto_parser_ops icmp_proto_parser_ops = {
	icmp_parse,
	icmp_nxtcld,
	icmp_getspec,
	icmp_add
};

struct prparse_ops icmp_prparse_ops = {
	icmp_update,
	prp_nop_fixnxt,
	prp_nop_fixlen,
	icmp_fixcksum,
	stdpr_copy,
	stdpr_free
};

struct proto_parser_ops icmpv6_proto_parser_ops = {
	icmp6_parse,
	icmp6_nxtcld,
	icmp6_getspec,
	icmp6_add
};

struct prparse_ops icmpv6_prparse_ops = {
	icmp6_update,
	prp_nop_fixnxt,
	prp_nop_fixlen,
	icmp6_fixcksum,
	stdpr_copy,
	stdpr_free
};

struct proto_parser_ops udp_proto_parser_ops = {
	udp_parse,
	udp_nxtcld,
	udp_getspec,
	udp_add
};

struct prparse_ops udp_prparse_ops = {
	udp_update,
	udp_fixnxt,
	udp_fixlen,
	udp_fixcksum,
	stdpr_copy,
	stdpr_free
};

struct proto_parser_ops tcp_proto_parser_ops = {
	tcp_parse,
	stdpr_nxtcld,
	tcp_getspec,
	tcp_add
};

struct prparse_ops tcp_prparse_ops = {
	tcp_update,
	prp_nop_fixnxt,
	tcp_fixlen,
	tcp_fixcksum,
	tcp_copy,
	tcp_free
};

struct proto_parser_ops gre_proto_parser_ops = {
	gre_parse,
	gre_nxtcld,
	gre_getspec,
	gre_add
};

struct prparse_ops gre_prparse_ops = {
	gre_update,
	gre_fixnxt,
	prp_nop_fixlen,
	gre_fixcksum,
	stdpr_copy,
	stdpr_free
};

struct proto_parser_ops nvgre_proto_parser_ops = {
	gre_parse,
	gre_nxtcld,
	nvgre_getspec,
	nvgre_add
};

struct proto_parser_ops vxlan_proto_parser_ops = {
	vxlan_parse,
	vxlan_nxtcld,
	vxlan_getspec,
	vxlan_add
};

struct prparse_ops vxlan_prparse_ops = {
	vxlan_update,
	prp_nop_fixnxt,
	prp_nop_fixlen,
	prp_nop_fixcksum,
	stdpr_copy,
	stdpr_free
};

struct proto_parser_ops mpls_proto_parser_ops = {
	mpls_parse,
	mpls_nxtcld,
	mpls_getspec,
	mpls_add
};

struct prparse_ops mpls_prparse_ops = {
	mpls_update,
	prp_nop_fixnxt,
	prp_nop_fixlen,
	prp_nop_fixcksum,
	stdpr_copy,
	stdpr_free
};


/* --------- Namespaces ---------- */

#define STDPROTO_NS_ELEN	64
#define STDPROTO_NS_SUB_ELEN	16

/* Packet Namespace */
extern struct ns_elem *stdproto_pkt_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace pkt_ns =
	NS_NAMESPACE_I("pkt", NULL, PRID_NONE, PRID_NONE, "Packet Data", NULL,
		stdproto_pkt_ns_elems, array_length(stdproto_pkt_ns_elems));
struct ns_elem *stdproto_pkt_ns_elems[STDPROTO_NS_ELEN];

/* Header Namespace */
extern struct ns_elem *stdproto_pdu_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace pdu_ns =
	NS_NAMESPACE_I("pdu", NULL, PRID_ANY, PRID_NONE,
		"Protocol Data Unit", NULL, stdproto_pdu_ns_elems,
		array_length(stdproto_pdu_ns_elems));
struct ns_elem *stdproto_pdu_ns_elems[STDPROTO_NS_ELEN];

/* Ethernet Namespace */
extern struct ns_elem *stdproto_eth2_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace eth2_ns = 
	NS_NAMESPACE_I("eth", NULL, PRID_ETHERNET2, PRID_PCLASS_LINK,
		"Ethernet II", NULL,
		stdproto_eth2_ns_elems, array_length(stdproto_eth2_ns_elems));

static struct ns_pktfld eth2_ns_dst =
	NS_BYTEFIELD_I("dst", &eth2_ns, PRID_ETHERNET2, 0, 6,
		       "Destination Address", &ns_fmt_etha);
static struct ns_pktfld eth2_ns_src =
	NS_BYTEFIELD_I("src", &eth2_ns, PRID_ETHERNET2, 6, 6,
		       "Source Address", &ns_fmt_etha);
static struct ns_pktfld eth2_ns_ethtype =
	NS_BYTEFIELD_IDX_I("ethtype", &eth2_ns, PRID_ETHERNET2, 
			PRP_ETHFLD_ETYPE, 0, 2,
		       "Ethernet Type", &ns_fmt_hex);

extern struct ns_elem *stdproto_eth2_vlan0_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_eth2_vlan1_ns_elems[STDPROTO_NS_SUB_ELEN];

static struct ns_namespace eth2_vlan0_ns = 
	NS_NAMESPACE_IDX_I("vlan0", &eth2_ns, PRID_ETHERNET2, PRID_NONE,
		PRP_ETHFLD_VLAN0, 4,
		"Ethernet VLAN 0", NULL,
		stdproto_eth2_vlan0_ns_elems,
		array_length(stdproto_eth2_vlan0_ns_elems));
static struct ns_pktfld eth2_vlan0_tpid =
	NS_BYTEFIELD_IDX_I("tpid", &eth2_vlan0_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN0, 0, 2,
	       "Tag Proto ID", &ns_fmt_hex);
static struct ns_pktfld eth2_vlan0_pri =
	NS_BITFIELD_IDX_I("pri", &eth2_vlan0_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN0, 2, 0, 3,
	       "Priority", &ns_fmt_dec);
static struct ns_pktfld eth2_vlan0_cfi =
	NS_BITFIELD_IDX_I("cfi", &eth2_vlan0_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN0, 2, 3, 1,
	       "Canonical Field Ind", &ns_fmt_dec);
static struct ns_pktfld eth2_vlan0_vid =
	NS_BITFIELD_IDX_I("vid", &eth2_vlan0_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN0, 2, 4, 12,
	       "VLAN ID", &ns_fmt_dec);
struct ns_elem *stdproto_eth2_vlan0_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&eth2_vlan0_tpid, (struct ns_elem *)&eth2_vlan0_pri, 
	(struct ns_elem *)&eth2_vlan0_cfi, (struct ns_elem *)&eth2_vlan0_vid, 
};

static struct ns_namespace eth2_vlan1_ns = 
	NS_NAMESPACE_IDX_I("vlan1", &eth2_ns, PRID_ETHERNET2, PRID_NONE,
		PRP_ETHFLD_VLAN1, 4,
		"Ethernet VLAN 1", NULL,
		stdproto_eth2_vlan1_ns_elems,
		array_length(stdproto_eth2_vlan1_ns_elems));
static struct ns_pktfld eth2_vlan1_tpid =
	NS_BYTEFIELD_IDX_I("tpid", &eth2_vlan1_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN1, 0, 2,
	       "Tag Proto ID", &ns_fmt_hex);
static struct ns_pktfld eth2_vlan1_pri =
	NS_BITFIELD_IDX_I("pri", &eth2_vlan1_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN1, 2, 0, 3,
	       "Priority", &ns_fmt_dec);
static struct ns_pktfld eth2_vlan1_cfi =
	NS_BITFIELD_IDX_I("cfi", &eth2_vlan1_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN1, 2, 3, 1,
	       "Canonical Field Ind", &ns_fmt_dec);
static struct ns_pktfld eth2_vlan1_vid =
	NS_BITFIELD_IDX_I("vid", &eth2_vlan1_ns, PRID_ETHERNET2,
		PRP_ETHFLD_VLAN1, 2, 4, 12,
	       "VLAN ID", &ns_fmt_dec);
struct ns_elem *stdproto_eth2_vlan1_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&eth2_vlan1_tpid, (struct ns_elem *)&eth2_vlan1_pri, 
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
	       "Address Resolution Protocol", NULL,
	       stdproto_arp_ns_elems, array_length(stdproto_arp_ns_elems));

static struct ns_pktfld arp_ns_hwfmt =
	NS_BYTEFIELD_I("hwfmt", &arp_ns, PRID_ARP, 0, 2,
		"HW Address Format", &ns_fmt_hex);
static struct ns_pktfld arp_ns_prfmt =
	NS_BYTEFIELD_I("prfmt", &arp_ns, PRID_ARP, 2, 2,
		"Proto Address Format", &ns_fmt_hex);
static struct ns_pktfld arp_ns_hwlen =
	NS_BYTEFIELD_I("hwlen", &arp_ns, PRID_ARP, 4, 1,
		"HW Address length", &ns_fmt_dec);
static struct ns_pktfld arp_ns_prlen =
	NS_BYTEFIELD_I("prlen", &arp_ns, PRID_ARP, 5, 1,
		"Proto Address length", &ns_fmt_dec);
static struct ns_pktfld arp_ns_op =
	NS_BYTEFIELD_I("op", &arp_ns, PRID_ARP, 6, 2,
		"Operation", &ns_fmt_dec);
static struct ns_pktfld arp_ns_sndhwaddr =
	NS_BYTEFIELD_IDX_I("sndhwaddr", &arp_ns, PRID_ARP,
		PRP_ARPFLD_ETHARP, 8, 6, 
		"Sender HW Address", &ns_fmt_etha);
static struct ns_pktfld arp_ns_sndpraddr =
	NS_BYTEFIELD_IDX_I("sndpraddr", &arp_ns, PRID_ARP,
		PRP_ARPFLD_ETHARP, 14, 4, 
		"Sender IP Address", &ns_fmt_ipv4a);
static struct ns_pktfld arp_ns_trghwaddr =
	NS_BYTEFIELD_IDX_I("trghwaddr", &arp_ns, PRID_ARP,
		PRP_ARPFLD_ETHARP, 18, 6, 
		"Target HW Address", &ns_fmt_etha);
static struct ns_pktfld arp_ns_trgpraddr =
	NS_BYTEFIELD_IDX_I("trgpraddr", &arp_ns, PRID_ARP,
		PRP_ARPFLD_ETHARP, 24, 4, 
		"Target IP Address", &ns_fmt_ipv4a);

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
		"Internet Protocol Version 4", NULL,
		stdproto_ipv4_ns_elems, array_length(stdproto_ipv4_ns_elems));

static struct ns_pktfld ipv4_ns_vers =
	NS_BITFIELD_I("vers", &ipv4_ns, PRID_IPV4, 0, 0, 4,
		"Version", &ns_fmt_dec);
static struct ns_pktfld ipv4_ns_ihl =
	NS_BITFIELD_I("ihl", &ipv4_ns, PRID_IPV4, 0, 4, 4,
		"Header Length", &ns_fmt_wlen);
static struct ns_pktfld ipv4_ns_diffsrv =
	NS_BITFIELD_I("diffsrv", &ipv4_ns, PRID_IPV4, 1, 0, 6,
		"Diffserv", &ns_fmt_hex);
static struct ns_pktfld ipv4_ns_ecn =
	NS_BITFIELD_I("ecn", &ipv4_ns, PRID_IPV4, 1, 6, 2,
		"ECN", &ns_fmt_hex);
static struct ns_pktfld ipv4_ns_len =
	NS_BYTEFIELD_I("len", &ipv4_ns, PRID_IPV4, 2, 2,
		"Total Length", &ns_fmt_dec);
static struct ns_pktfld ipv4_ns_id =
	NS_BYTEFIELD_I("id", &ipv4_ns, PRID_IPV4, 4, 2,
		"Identifier", &ns_fmt_hex);
static struct ns_pktfld ipv4_ns_rf =
	NS_FBITFIELD_I("rf", &ipv4_ns, PRID_IPV4, 6, 0, 1,
		"Reserved Frag Bit", &ns_fmt_fbf, 0, 3);
static struct ns_pktfld ipv4_ns_df =
	NS_FBITFIELD_I("df", &ipv4_ns, PRID_IPV4, 6, 1, 1,
		"Don't Fragment Bit", &ns_fmt_fbf, 1, 3);
static struct ns_pktfld ipv4_ns_mf =
	NS_FBITFIELD_I("mf", &ipv4_ns, PRID_IPV4, 6, 2, 1,
		"More Fragments Bit", &ns_fmt_fbf, 2, 3);
static struct ns_pktfld ipv4_ns_fragoff =
	NS_BITFIELD_I("fragoff", &ipv4_ns, PRID_IPV4, 6, 3, 13,
		"Fragment Offset", &ns_fmt_qlen);
static struct ns_pktfld ipv4_ns_ttl =
	NS_BYTEFIELD_I("ttl", &ipv4_ns, PRID_IPV4, 8, 1,
		"Time to Live", &ns_fmt_dec);
static struct ns_pktfld ipv4_ns_proto =
	NS_BYTEFIELD_I("proto", &ipv4_ns, PRID_IPV4, 9, 1,
		"IP Protocol", &ns_fmt_dec);
static struct ns_pktfld ipv4_ns_cksum =
	NS_BYTEFIELD_I("cksum", &ipv4_ns, PRID_IPV4, 10, 2,
		"Header Checksum", &ns_fmt_hex);
static struct ns_pktfld ipv4_ns_saddr =
	NS_BYTEFIELD_I("saddr", &ipv4_ns, PRID_IPV4, 12, 4,
		"Source Address", &ns_fmt_ipv4a);
static struct ns_pktfld ipv4_ns_daddr =
	NS_BYTEFIELD_I("daddr", &ipv4_ns, PRID_IPV4, 16, 4,
		"Destination Address", &ns_fmt_ipv4a);
static struct ns_pktfld ipv4_ns_opt =
	NS_BYTEFIELD_VARLEN_I("opt", &ipv4_ns, PRID_IPV4, PRP_IPFLD_OPT, 0,
		PRP_OI_POFF, "IP Options", &ns_fmt_raw);

extern struct ns_elem *stdproto_ipv4_addr_ns_elems[STDPROTO_NS_SUB_ELEN];
static struct ns_namespace ipv4_addr_ns = 
	NS_NAMESPACE_NOFLD("addr", &ipv4_ns, PRID_INVALID, PRID_NONE,
		"Reserved IP addresses and address masks", NULL,
		stdproto_ipv4_addr_ns_elems, 
		array_length(stdproto_ipv4_addr_ns_elems));
static struct ns_bytestr ipv4_addr_broadcast =
	NS_BYTESTR_I_LEN("broadcast", &ipv4_addr_ns, PRID_NONE,
			 "\xFF\xFF\xFF\xFF", 4);
static struct ns_bytestr ipv4_addr_localhost =
	NS_BYTESTR_I_LEN("localhost", &ipv4_addr_ns, PRID_NONE,
			 "\x7F\x00\x00\x01", 4);
static struct ns_bytestr ipv4_addr_any =
	NS_BYTESTR_I_LEN("any", &ipv4_addr_ns, PRID_NONE,
			 "\x00\x00\x00\x00", 4);
static struct ns_maskstr ipv4_addr_localnet =
	NS_MASKSTR_I_LEN("localnet", &ipv4_addr_ns, PRID_NONE,
			 "\x7F\x00\x00\x00", "\xFF\x00\x00\x00", 4);

struct ns_elem *stdproto_ipv4_addr_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&ipv4_addr_broadcast,
	(struct ns_elem *)&ipv4_addr_localhost,
	(struct ns_elem *)&ipv4_addr_any,
	(struct ns_elem *)&ipv4_addr_localnet,
};


struct ns_elem *stdproto_ipv4_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&ipv4_ns_vers, (struct ns_elem *)&ipv4_ns_ihl,
	(struct ns_elem *)&ipv4_ns_diffsrv, (struct ns_elem *)&ipv4_ns_ecn,
	(struct ns_elem *)&ipv4_ns_len, (struct ns_elem *)&ipv4_ns_id, 
	(struct ns_elem *)&ipv4_ns_rf, (struct ns_elem *)&ipv4_ns_df,
	(struct ns_elem *)&ipv4_ns_mf, (struct ns_elem *)&ipv4_ns_fragoff,
	(struct ns_elem *)&ipv4_ns_ttl, (struct ns_elem *)&ipv4_ns_proto,
	(struct ns_elem *)&ipv4_ns_cksum, (struct ns_elem *)&ipv4_ns_saddr,
	(struct ns_elem *)&ipv4_ns_daddr, (struct ns_elem *)&ipv4_ns_opt,

	/* constants */
	(struct ns_elem *)&ipv4_addr_ns,
};


extern struct ns_elem *stdproto_ipv6_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace ipv6_ns = 
	NS_NAMESPACE_I("ip6", NULL, PRID_IPV6, PRID_PCLASS_NET,
		"Internet Protocol Version 6", NULL,
	       	stdproto_ipv6_ns_elems, array_length(stdproto_ipv6_ns_elems));

static struct ns_pktfld ipv6_ns_vers =
	NS_BITFIELD_I("vers", &ipv6_ns, PRID_IPV6, 0, 0, 4,
		"Version", &ns_fmt_dec);
static struct ns_pktfld ipv6_ns_class =
	NS_BITFIELD_I("class", &ipv6_ns, PRID_IPV6, 0, 4, 8,
		"Traffic Class", &ns_fmt_dec);
static struct ns_pktfld ipv6_ns_flowid =
	NS_BITFIELD_I("flowid", &ipv6_ns, PRID_IPV6, 0, 12, 20,
		"Flow ID", &ns_fmt_dec);
static struct ns_pktfld ipv6_ns_len =
	NS_BYTEFIELD_I("len", &ipv6_ns, PRID_IPV6, 4, 2,
		"Total Length", &ns_fmt_dec);
static struct ns_pktfld ipv6_ns_nxthdr =
	NS_BYTEFIELD_I("nxthdr", &ipv6_ns, PRID_IPV6, 6, 1,
		"Next Header", &ns_fmt_dec);
static struct ns_pktfld ipv6_ns_hoplim =
	NS_BYTEFIELD_I("hoplim", &ipv6_ns, PRID_IPV6, 7, 1,
		"Hop Limit", &ns_fmt_dec);
static struct ns_pktfld ipv6_ns_saddr =
	NS_BYTEFIELD_I("saddr", &ipv6_ns, PRID_IPV6, 8, 16,
		"Source Address", &ns_fmt_ipv6a);
static struct ns_pktfld ipv6_ns_daddr =
	NS_BYTEFIELD_I("daddr", &ipv6_ns, PRID_IPV6, 24, 16,
		"Destination Address", &ns_fmt_ipv6a);
static struct ns_pktfld ipv6_ns_xnxthdr =
	NS_BYTEFIELD_IDX_I("xnxthdr", &ipv6_ns, PRID_IPV6,
		PRP_IPV6FLD_NXTHDR, 0, 1, "Final Next Header", &ns_fmt_dec);
static struct ns_pktfld ipv6_ns_exth =
	NS_BYTEFIELD_VARLEN_I("exth", &ipv6_ns, PRID_IPV6, PRP_OI_SOFF, 40,
		PRP_OI_POFF,
		"Extension Headers", &ns_fmt_raw);

struct ns_elem *stdproto_ipv6_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&ipv6_ns_vers, (struct ns_elem *)&ipv6_ns_class,
	(struct ns_elem *)&ipv6_ns_flowid, (struct ns_elem *)&ipv6_ns_len,
	(struct ns_elem *)&ipv6_ns_nxthdr, (struct ns_elem *)&ipv6_ns_hoplim,
	(struct ns_elem *)&ipv6_ns_saddr, (struct ns_elem *)&ipv6_ns_daddr,
	(struct ns_elem *)&ipv6_ns_xnxthdr, (struct ns_elem *)&ipv6_ns_exth, 
};


extern struct ns_elem *stdproto_icmp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace icmp_ns = 
	NS_NAMESPACE_I("icmp", NULL, PRID_ICMP, PRID_PCLASS_XPORT,
		"Internet Control Message Protocol", NULL,
	       	stdproto_icmp_ns_elems, array_length(stdproto_icmp_ns_elems));

static struct ns_pktfld icmp_ns_type =
	NS_BYTEFIELD_I("type", &icmp_ns, PRID_ICMP, 0, 1,
		"Type", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_code =
	NS_BYTEFIELD_I("code", &icmp_ns, PRID_ICMP, 1, 1,
		"Code", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_cksum =
	NS_BYTEFIELD_I("cksum", &icmp_ns, PRID_ICMP, 2, 2,
		"Checksum", &ns_fmt_hex);
static struct ns_pktfld icmp_ns_id =
	NS_BYTEFIELD_IDX_I("id", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_QUERY, 0, 2, "Identifier", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_seq =
	NS_BYTEFIELD_IDX_I("seq", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_QUERY, 2, 2, "Sequence Number", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_mtu_resv =
	NS_BYTEFIELD_IDX_I("mtu_resv", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_MTU, 0, 2, "MTU Reserved", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_mtu =
	NS_BYTEFIELD_IDX_I("mtu", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_MTU, 2, 2, "MTU", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_ptr =
	NS_BYTEFIELD_IDX_I("ptr", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_PPTR, 0, 1, "Pointer", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_ptr_resv =
	NS_BYTEFIELD_IDX_I("ptr_resv", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_PPTR, 1, 3, "Param Prob Reserved", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_ots =
	NS_BYTEFIELD_IDX_I("ots", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_TS, 0, 4, "Originate Timestamp", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_rts =
	NS_BYTEFIELD_IDX_I("rts", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_TS, 4, 4, "Receive Timestamp", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_tts =
	NS_BYTEFIELD_IDX_I("tts", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_TS, 8, 4, "Transmit Timestamp", &ns_fmt_dec);
static struct ns_pktfld icmp_ns_gw =
	NS_BYTEFIELD_IDX_I("gw", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_GW, 0, 4, "Gateway", &ns_fmt_ipv4a);
static struct ns_pktfld icmp_ns_reserved =
	NS_BYTEFIELD_IDX_I("resv", &icmp_ns, PRID_ICMP, 
		PRP_ICMPFLD_RESERVED, 0, 4, "Reserved", &ns_fmt_hex);

struct ns_elem *stdproto_icmp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&icmp_ns_type, (struct ns_elem *)&icmp_ns_code,
	(struct ns_elem *)&icmp_ns_cksum, (struct ns_elem *)&icmp_ns_id,
	(struct ns_elem *)&icmp_ns_seq, (struct ns_elem *)&icmp_ns_mtu_resv,
	(struct ns_elem *)&icmp_ns_mtu, (struct ns_elem *)&icmp_ns_ptr,
	(struct ns_elem *)&icmp_ns_ptr_resv, (struct ns_elem *)&icmp_ns_ots,
	(struct ns_elem *)&icmp_ns_rts, (struct ns_elem *)&icmp_ns_tts,
	(struct ns_elem *)&icmp_ns_gw, (struct ns_elem *)&icmp_ns_reserved,
};


/* ICMPv6 */
extern struct ns_elem *stdproto_icmp6_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace icmp6_ns = 
	NS_NAMESPACE_I("icmp6", NULL, PRID_ICMP6, PRID_PCLASS_XPORT,
		"Internet Control Message Protocol v6", NULL,
		stdproto_icmp6_ns_elems, array_length(stdproto_icmp6_ns_elems));

extern struct ns_elem *stdproto_icmp6_echo_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_icmp6_rsol_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_icmp6_radv_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_icmp6_neigh_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_icmp6_nrdr_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_icmp6_ndo_srclla_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_icmp6_ndo_tgtlla_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *
	stdproto_icmp6_ndo_pfxinfo_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_icmp6_ndo_rdrhdr_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_icmp6_ndo_mtu_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *
	stdproto_icmp6_ndo_radvivl_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *
	stdproto_icmp6_ndo_agtinfo_ns_elems[STDPROTO_NS_SUB_ELEN];


/* ICMPv6 echo request/reply packet fields */
struct ns_namespace icmp6_echo_ns =
	NS_NAMESPACE_IDX_I("echo", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			   PRP_ICMP6FLD_ECHO, 4, "ICMPv6 Echo Info", NULL,
			   stdproto_icmp6_echo_ns_elems,
			   array_length(stdproto_icmp6_echo_ns_elems));
static struct ns_pktfld icmp6_echo_id =
	NS_BYTEFIELD_IDX_I("id", &icmp6_echo_ns, PRID_ICMP6, PRP_ICMP6FLD_ECHO,
			   0, 2, "Identifier", &ns_fmt_dec);
static struct ns_pktfld icmp6_echo_seq =
	NS_BYTEFIELD_IDX_I("seq", &icmp6_echo_ns, PRID_ICMP6, PRP_ICMP6FLD_ECHO,
			   2, 2, "Sequence Number", &ns_fmt_dec);
struct ns_elem *stdproto_icmp6_echo_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_echo_id, (struct ns_elem *)&icmp6_echo_seq, 
};

/* ICMPv6 Router Solicitation packet fields */
struct ns_namespace icmp6_rsol_ns =
	NS_NAMESPACE_IDX_I("rsol", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			   PRP_ICMP6FLD_RSOL, 4, "NDP Router Solicit", 
			   NULL, stdproto_icmp6_rsol_ns_elems,
			   array_length(stdproto_icmp6_rsol_ns_elems));
static struct ns_pktfld icmp6_rsol_resv =
	NS_BYTEFIELD_IDX_I("resv", &icmp6_rsol_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_NEIGH, 0, 4, "Reserved",
			   &ns_fmt_hex);
static struct ns_pktfld icmp6_rsol_opts =
	NS_BYTEFIELD_VARLEN_I("opts", &icmp6_rsol_ns, PRID_ICMP6,
			      PRP_ICMP6FLD_NDPOPT, 0, PRP_OI_POFF,
			      "NDP Options", &ns_fmt_summary);
struct ns_elem *stdproto_icmp6_rsol_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_rsol_resv,
	(struct ns_elem *)&icmp6_rsol_opts,
};

/* ICMPv6 Router Advertisement packet fields */
struct ns_namespace icmp6_radv_ns =
	NS_NAMESPACE_IDX_I("radv", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			   PRP_ICMP6FLD_RADV, 12, "NDP Router Advert", NULL,
			   stdproto_icmp6_radv_ns_elems,
			   array_length(stdproto_icmp6_radv_ns_elems));
static struct ns_pktfld icmp6_radv_hoplim =
	NS_BYTEFIELD_IDX_I("hoplim", &icmp6_radv_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RADV, 0, 1, "Current Hop Limit",
			   &ns_fmt_dec);
static struct ns_pktfld icmp6_radv_mcfg =
	NS_BITFIELD_IDX_I("mcfg", &icmp6_radv_ns, PRID_ICMP6, 
			  PRP_ICMP6FLD_RADV, 1, 0, 1, "Managed Addr Cfg",
			  &ns_fmt_dec);
static struct ns_pktfld icmp6_radv_ocfg =
	NS_BITFIELD_IDX_I("ocfg", &icmp6_radv_ns, PRID_ICMP6, 
			  PRP_ICMP6FLD_RADV, 1, 1, 1, "Other Cfg",
			  &ns_fmt_dec);
static struct ns_pktfld icmp6_radv_resv =
	NS_BITFIELD_IDX_I("resv", &icmp6_radv_ns, PRID_ICMP6, 
			  PRP_ICMP6FLD_RADV, 1, 2, 6, "Reserved",
			  &ns_fmt_dec);
static struct ns_pktfld icmp6_radv_tlife =
	NS_BYTEFIELD_IDX_I("tlife", &icmp6_radv_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RADV, 2, 2, "Router Lifetime",
			   &ns_fmt_dec);
static struct ns_pktfld icmp6_radv_treach =
	NS_BYTEFIELD_IDX_I("treach", &icmp6_radv_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RADV, 4, 4, "Reachable Time",
			   &ns_fmt_dec);
static struct ns_pktfld icmp6_radv_tretry =
	NS_BYTEFIELD_IDX_I("tretry", &icmp6_radv_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RADV, 8, 4, "Retrans Timer",
			   &ns_fmt_dec);
static struct ns_pktfld icmp6_radv_opts =
	NS_BYTEFIELD_VARLEN_I("opts", &icmp6_radv_ns, PRID_ICMP6,
			      PRP_ICMP6FLD_NDPOPT, 0, PRP_OI_POFF,
			      "NDP Options", &ns_fmt_summary);
struct ns_elem *stdproto_icmp6_radv_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_radv_hoplim,
	(struct ns_elem *)&icmp6_radv_mcfg,
	(struct ns_elem *)&icmp6_radv_ocfg,
	(struct ns_elem *)&icmp6_radv_resv,
	(struct ns_elem *)&icmp6_radv_tlife,
	(struct ns_elem *)&icmp6_radv_treach,
	(struct ns_elem *)&icmp6_radv_tretry,
	(struct ns_elem *)&icmp6_radv_opts,
};

/* ICMPv6 NDP packet fields */
struct ns_namespace icmp6_neigh_ns =
	NS_NAMESPACE_IDX_I("neigh", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			   PRP_ICMP6FLD_NEIGH, 20, "ICMPv6 NDP Neighbor Msg",
			   NULL, stdproto_icmp6_neigh_ns_elems,
			   array_length(stdproto_icmp6_neigh_ns_elems));
static struct ns_pktfld icmp6_neigh_rtr =
	NS_BITFIELD_IDX_I("rtr", &icmp6_neigh_ns, PRID_ICMP6, 
			  PRP_ICMP6FLD_NEIGH, 0, 0, 1, "Router flag",
			  &ns_fmt_dec);
static struct ns_pktfld icmp6_neigh_sol =
	NS_BITFIELD_IDX_I("sol", &icmp6_neigh_ns, PRID_ICMP6,
			  PRP_ICMP6FLD_NEIGH, 0, 1, 1, "Solicited flag",
			  &ns_fmt_dec);
static struct ns_pktfld icmp6_neigh_ovd =
	NS_BITFIELD_IDX_I("ovd", &icmp6_neigh_ns, PRID_ICMP6,
			  PRP_ICMP6FLD_NEIGH, 0, 2, 1, "Override flag",
			  &ns_fmt_dec);
static struct ns_pktfld icmp6_neigh_resv =
	NS_BITFIELD_IDX_I("resv", &icmp6_neigh_ns, PRID_ICMP6,
			  PRP_ICMP6FLD_NEIGH, 0, 3, 29, "Reserved",
			  &ns_fmt_dec);
static struct ns_pktfld icmp6_neigh_ip6a =
	NS_BYTEFIELD_IDX_I("ip6a", &icmp6_neigh_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_NEIGH, 4, 16, "IPv6 Address",
			   &ns_fmt_ipv6a);
static struct ns_pktfld icmp6_neigh_opts =
	NS_BYTEFIELD_VARLEN_I("opts", &icmp6_neigh_ns, PRID_ICMP6,
			      PRP_ICMP6FLD_NDPOPT, 0, PRP_OI_POFF,
			      "NDP Options", &ns_fmt_summary);
struct ns_elem *stdproto_icmp6_neigh_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_neigh_rtr, (struct ns_elem *)&icmp6_neigh_sol,
	(struct ns_elem *)&icmp6_neigh_ovd, (struct ns_elem *)&icmp6_neigh_resv,
	(struct ns_elem *)&icmp6_neigh_ip6a,
	(struct ns_elem *)&icmp6_neigh_opts,
};

/* ICMPv6 Router Advertisement packet fields */
struct ns_namespace icmp6_nrdr_ns =
	NS_NAMESPACE_IDX_I("nrdr", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			   PRP_ICMP6FLD_REDIR, 36, "NDP Neighbor Redirect",
			   NULL, stdproto_icmp6_nrdr_ns_elems,
			   array_length(stdproto_icmp6_nrdr_ns_elems));
static struct ns_pktfld icmp6_nrdr_tgtaddr =
	NS_BYTEFIELD_IDX_I("tgtaddr", &icmp6_nrdr_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_REDIR, 4, 16, "Target Address",
			   &ns_fmt_ipv6a);
static struct ns_pktfld icmp6_nrdr_dstaddr =
	NS_BYTEFIELD_IDX_I("dstaddr", &icmp6_nrdr_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_REDIR, 20, 16, "Destination Address",
			   &ns_fmt_ipv6a);
static struct ns_pktfld icmp6_nrdr_opts =
	NS_BYTEFIELD_VARLEN_I("opts", &icmp6_nrdr_ns, PRID_ICMP6,
			      PRP_ICMP6FLD_NDPOPT, 0, PRP_OI_POFF,
			      "NDP Options", &ns_fmt_summary);
struct ns_elem *stdproto_icmp6_nrdr_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_nrdr_tgtaddr,
	(struct ns_elem *)&icmp6_nrdr_dstaddr,
	(struct ns_elem *)&icmp6_nrdr_opts,
};

/* ICMP6 Neighbor Discovery options */

/* ICMPv6 NDP Source Link Level Address Option fields */
struct ns_namespace icmp6_ndo_srclla_ns =
	NS_NAMESPACE_VARLEN_I("srclla", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			      PRP_ICMP6FLD_SRCLLA, PRP_ICMP6FLD_SRCLLA_EOFF,
			      "Source Link Layer Address",
			      NULL, stdproto_icmp6_ndo_srclla_ns_elems,
			      array_length(stdproto_icmp6_ndo_srclla_ns_elems));
static struct ns_pktfld icmp6_ndo_srclla_type =
	NS_BYTEFIELD_IDX_I("type", &icmp6_ndo_srclla_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_SRCLLA, 0, 1, "Type", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_srclla_len =
	NS_BYTEFIELD_IDX_I("len", &icmp6_ndo_srclla_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_SRCLLA, 1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_srclla_addr =
	NS_BYTEFIELD_VARLEN_I("addr", &icmp6_ndo_srclla_ns, PRID_ICMP6, 
			      PRP_ICMP6FLD_SRCLLA, 2, PRP_ICMP6FLD_SRCLLA_EOFF,
			      "Link Layer Address", &ns_fmt_etha);
struct ns_elem *stdproto_icmp6_ndo_srclla_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_ndo_srclla_type,
	(struct ns_elem *)&icmp6_ndo_srclla_len,
	(struct ns_elem *)&icmp6_ndo_srclla_addr,
};

/* ICMPv6 NDP Target Link Level Address Option fields */
struct ns_namespace icmp6_ndo_tgtlla_ns =
	NS_NAMESPACE_VARLEN_I("tgtlla", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			      PRP_ICMP6FLD_TGTLLA, PRP_ICMP6FLD_TGTLLA_EOFF,
			      "Dest Link Layer Address",
			      NULL, stdproto_icmp6_ndo_tgtlla_ns_elems,
			      array_length(stdproto_icmp6_ndo_tgtlla_ns_elems));
static struct ns_pktfld icmp6_ndo_tgtlla_type =
	NS_BYTEFIELD_IDX_I("type", &icmp6_ndo_tgtlla_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_TGTLLA, 0, 1, "Type", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_tgtlla_len =
	NS_BYTEFIELD_IDX_I("len", &icmp6_ndo_tgtlla_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_TGTLLA, 1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_tgtlla_addr =
	NS_BYTEFIELD_VARLEN_I("addr", &icmp6_ndo_tgtlla_ns, PRID_ICMP6,
			      PRP_ICMP6FLD_TGTLLA, 2, PRP_ICMP6FLD_TGTLLA_EOFF,
			      "Link Layer Address", &ns_fmt_etha);
struct ns_elem *stdproto_icmp6_ndo_tgtlla_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_ndo_tgtlla_type,
	(struct ns_elem *)&icmp6_ndo_tgtlla_len,
	(struct ns_elem *)&icmp6_ndo_tgtlla_addr,
};

/* ICMPv6 NDP Prefix Information Option fields */
struct ns_namespace icmp6_ndo_pfxinfo_ns =
	NS_NAMESPACE_IDX_I("pfxinfo", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			   PRP_ICMP6FLD_PFXINFO, ICMP6_ND_PFXINFO_OLEN, 
			   "Dest Link Layer Address",
			   NULL, stdproto_icmp6_ndo_pfxinfo_ns_elems,
			   array_length(stdproto_icmp6_ndo_pfxinfo_ns_elems));
static struct ns_pktfld icmp6_ndo_pfxinfo_type =
	NS_BYTEFIELD_IDX_I("type", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_PFXINFO, 0, 1, "Type", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_pfxinfo_len =
	NS_BYTEFIELD_IDX_I("len", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_PFXINFO, 1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_pfxinfo_pfxlen =
	NS_BYTEFIELD_IDX_I("pfxlen", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_PFXINFO, 2, 1, "Prefix Length",
			   &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_pfxinfo_onlink =
	NS_BITFIELD_IDX_I("onlink", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			  PRP_ICMP6FLD_PFXINFO, 3, 0, 1, "On-link Flag",
			  &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_pfxinfo_auto =
	NS_BITFIELD_IDX_I("auto", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			  PRP_ICMP6FLD_PFXINFO, 3, 1, 1, "Auto Config Flag",
			  &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_pfxinfo_resv =
	NS_BITFIELD_IDX_I("resv", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			  PRP_ICMP6FLD_PFXINFO, 3, 2, 6, "Reserved", 
			  &ns_fmt_hex);
static struct ns_pktfld icmp6_ndo_pfxinfo_vlife =
	NS_BYTEFIELD_IDX_I("vlife", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_PFXINFO, 4, 4, "Valid Lifetime",
			   &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_pfxinfo_plife =
	NS_BYTEFIELD_IDX_I("plife", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_PFXINFO, 8, 4, "Preferred Lifetime",
			   &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_pfxinfo_resv2 =
	NS_BYTEFIELD_IDX_I("resv2", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_PFXINFO, 12, 4, "Reserved2",
			   &ns_fmt_hex);
static struct ns_pktfld icmp6_ndo_pfxinfo_pfx =
	NS_BYTEFIELD_IDX_I("pfx", &icmp6_ndo_pfxinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_PFXINFO,
			   16, 16, "Prefix", &ns_fmt_ipv6a);
struct ns_elem *stdproto_icmp6_ndo_pfxinfo_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_ndo_pfxinfo_type,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_len,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_pfxlen,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_onlink,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_auto,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_resv,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_vlife,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_plife,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_resv2,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_pfx,
};

/* ICMPv6 NDP Redirect Option fields */
struct ns_namespace icmp6_ndo_rdrhdr_ns =
	NS_NAMESPACE_VARLEN_I("rdrhdr", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			      PRP_ICMP6FLD_RDRHDR, PRP_ICMP6FLD_RDRHDR_EOFF,
			      "Redirect Header",
			      NULL, stdproto_icmp6_ndo_rdrhdr_ns_elems,
			      array_length(stdproto_icmp6_ndo_rdrhdr_ns_elems));
static struct ns_pktfld icmp6_ndo_rdrhdr_type =
	NS_BYTEFIELD_IDX_I("type", &icmp6_ndo_rdrhdr_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RDRHDR, 0, 1, "Type", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_rdrhdr_len =
	NS_BYTEFIELD_IDX_I("len", &icmp6_ndo_rdrhdr_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RDRHDR, 1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_rdrhdr_resv =
	NS_BYTEFIELD_IDX_I("resv", &icmp6_ndo_rdrhdr_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RDRHDR, 2, 6, "Reserved", &ns_fmt_hex);
static struct ns_pktfld icmp6_ndo_rdrhdr_opkt =
	NS_BYTEFIELD_VARLEN_I("opkt", &icmp6_ndo_rdrhdr_ns, PRID_ICMP6,
			      PRP_ICMP6FLD_RDRHDR, 8, PRP_ICMP6FLD_RDRHDR_EOFF,
			      "Original Packet", &ns_fmt_summary);
struct ns_elem *stdproto_icmp6_ndo_rdrhdr_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_ndo_rdrhdr_type,
	(struct ns_elem *)&icmp6_ndo_rdrhdr_len,
	(struct ns_elem *)&icmp6_ndo_rdrhdr_resv,
	(struct ns_elem *)&icmp6_ndo_rdrhdr_opkt,
};

/* ICMPv6 NDP MTU Option fields */
struct ns_namespace icmp6_ndo_mtu_ns =
	NS_NAMESPACE_IDX_I("omtu", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			   PRP_ICMP6FLD_MTU, ICMP6_ND_MTU_OLEN, 
			   "Maximum Transmission Unit Option",
			   NULL, stdproto_icmp6_ndo_mtu_ns_elems,
			   array_length(stdproto_icmp6_ndo_mtu_ns_elems));
static struct ns_pktfld icmp6_ndo_mtu_type =
	NS_BYTEFIELD_IDX_I("type", &icmp6_ndo_mtu_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_MTU, 0, 1, "Type", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_mtu_len =
	NS_BYTEFIELD_IDX_I("len", &icmp6_ndo_mtu_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_MTU, 1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_mtu_resv =
	NS_BYTEFIELD_IDX_I("resv", &icmp6_ndo_mtu_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_MTU, 2, 2, "Reserved", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_mtu_mtu =
	NS_BYTEFIELD_IDX_I("mtu", &icmp6_ndo_mtu_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_MTU, 4, 4, "Reserved", &ns_fmt_dec);
struct ns_elem *stdproto_icmp6_ndo_mtu_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_ndo_mtu_type,
	(struct ns_elem *)&icmp6_ndo_mtu_len,
	(struct ns_elem *)&icmp6_ndo_mtu_resv,
	(struct ns_elem *)&icmp6_ndo_mtu_mtu,
};

/* ICMPv6 NDP Router Advertisement Interval Option fields */
struct ns_namespace icmp6_ndo_radvivl_ns =
	NS_NAMESPACE_IDX_I("radvivl", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			   PRP_ICMP6FLD_MTU, ICMP6_ND_RADVIVL_OLEN, 
			   "Router Advertisement Interval Option",
			   NULL, stdproto_icmp6_ndo_radvivl_ns_elems,
			   array_length(stdproto_icmp6_ndo_radvivl_ns_elems));
static struct ns_pktfld icmp6_ndo_radvivl_type =
	NS_BYTEFIELD_IDX_I("type", &icmp6_ndo_radvivl_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RADVIVL, 0, 1, "Type", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_radvivl_len =
	NS_BYTEFIELD_IDX_I("len", &icmp6_ndo_radvivl_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RADVIVL, 1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_radvivl_resv =
	NS_BYTEFIELD_IDX_I("resv", &icmp6_ndo_radvivl_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RADVIVL, 2, 2, "Reserved", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_radvivl_interval =
	NS_BYTEFIELD_IDX_I("ival", &icmp6_ndo_radvivl_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_RADVIVL, 4, 4, "Interval", &ns_fmt_dec);
struct ns_elem *stdproto_icmp6_ndo_radvivl_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_ndo_radvivl_type,
	(struct ns_elem *)&icmp6_ndo_radvivl_len,
	(struct ns_elem *)&icmp6_ndo_radvivl_resv,
	(struct ns_elem *)&icmp6_ndo_radvivl_interval,
};

/* ICMPv6 NDP Home Agent Info Option fields */
struct ns_namespace icmp6_ndo_agtinfo_ns =
	NS_NAMESPACE_IDX_I("agtinfo", &icmp6_ns, PRID_ICMP6, PRID_NONE, 
			   PRP_ICMP6FLD_AGTINFO, ICMP6_ND_AGTINFO_OLEN, 
			   "Home Agent Information Option",
			   NULL, stdproto_icmp6_ndo_agtinfo_ns_elems,
			   array_length(stdproto_icmp6_ndo_agtinfo_ns_elems));
static struct ns_pktfld icmp6_ndo_agtinfo_type =
	NS_BYTEFIELD_IDX_I("type", &icmp6_ndo_agtinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_AGTINFO, 0, 1, "Type", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_agtinfo_len =
	NS_BYTEFIELD_IDX_I("len", &icmp6_ndo_agtinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_AGTINFO, 1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_agtinfo_resv =
	NS_BYTEFIELD_IDX_I("resv", &icmp6_ndo_agtinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_AGTINFO, 2, 2, "Reserved", &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_agtinfo_hapref =
	NS_BYTEFIELD_IDX_I("pref", &icmp6_ndo_agtinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_AGTINFO, 4, 2, "Preference",
			   &ns_fmt_dec);
static struct ns_pktfld icmp6_ndo_agtinfo_halife =
	NS_BYTEFIELD_IDX_I("life", &icmp6_ndo_agtinfo_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_AGTINFO, 6, 2, "Lifetime", &ns_fmt_dec);
struct ns_elem *stdproto_icmp6_ndo_agtinfo_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&icmp6_ndo_agtinfo_type,
	(struct ns_elem *)&icmp6_ndo_agtinfo_len,
	(struct ns_elem *)&icmp6_ndo_agtinfo_resv,
	(struct ns_elem *)&icmp6_ndo_agtinfo_hapref,
	(struct ns_elem *)&icmp6_ndo_agtinfo_halife,
};

static struct ns_pktfld icmp6_type =
	NS_BYTEFIELD_I("type", &icmp6_ns, PRID_ICMP6, 0, 1,
		"Type", &ns_fmt_dec);
static struct ns_pktfld icmp6_code =
	NS_BYTEFIELD_I("code", &icmp6_ns, PRID_ICMP6, 1, 1,
		"Code", &ns_fmt_dec);
static struct ns_pktfld icmp6_cksum =
	NS_BYTEFIELD_I("cksum", &icmp6_ns, PRID_ICMP6, 2, 2,
		"Checksum", &ns_fmt_hex);
static struct ns_pktfld icmp6_eresv =
	NS_BYTEFIELD_IDX_I("eresv", &icmp6_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_ERESV, 0, 4, 
			   "Error Reserved", &ns_fmt_hex);
static struct ns_pktfld icmp6_pptr =
	NS_BYTEFIELD_IDX_I("pptr", &icmp6_ns, PRID_ICMP6,
			   PRP_ICMP6FLD_PPTR, 0, 4, 
			   "Param Prob Ptr", &ns_fmt_dec);

struct ns_elem *stdproto_icmp6_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&icmp6_type, (struct ns_elem *)&icmp6_code, 
	(struct ns_elem *)&icmp6_cksum, (struct ns_elem *)&icmp6_eresv,
	(struct ns_elem *)&icmp6_pptr,
	(struct ns_elem *)&icmp6_echo_ns,
	(struct ns_elem *)&icmp6_rsol_ns,
	(struct ns_elem *)&icmp6_radv_ns,
	(struct ns_elem *)&icmp6_neigh_ns,
	(struct ns_elem *)&icmp6_nrdr_ns,
	(struct ns_elem *)&icmp6_ndo_srclla_ns,
	(struct ns_elem *)&icmp6_ndo_tgtlla_ns,
	(struct ns_elem *)&icmp6_ndo_pfxinfo_ns,
	(struct ns_elem *)&icmp6_ndo_rdrhdr_ns,
	(struct ns_elem *)&icmp6_ndo_mtu_ns,
	(struct ns_elem *)&icmp6_ndo_radvivl_ns,
	(struct ns_elem *)&icmp6_ndo_agtinfo_ns,
};


extern struct ns_elem *stdproto_udp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace udp_ns = 
	NS_NAMESPACE_I("udp", NULL, PRID_UDP, PRID_PCLASS_XPORT,
		"User Datagram Protocol", NULL,
	       	stdproto_udp_ns_elems, array_length(stdproto_udp_ns_elems));

static struct ns_pktfld udp_ns_sport =
	NS_BYTEFIELD_I("sport", &udp_ns, PRID_UDP, 0, 2,
		"Source Port", &ns_fmt_dec);
static struct ns_pktfld udp_ns_dport =
	NS_BYTEFIELD_I("dport", &udp_ns, PRID_UDP, 2, 2,
		"Destination Port", &ns_fmt_dec);
static struct ns_pktfld udp_ns_len =
	NS_BYTEFIELD_I("len", &udp_ns, PRID_UDP, 4, 2,
		"Length", &ns_fmt_dec);
static struct ns_pktfld udp_ns_cksum =
	NS_BYTEFIELD_I("cksum", &udp_ns, PRID_UDP, 6, 2,
		"Checksum", &ns_fmt_hex);

struct ns_elem *stdproto_udp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&udp_ns_sport, (struct ns_elem *)&udp_ns_dport, 
	(struct ns_elem *)&udp_ns_len, (struct ns_elem *)&udp_ns_cksum
};


extern struct ns_elem *stdproto_tcp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace tcp_ns = 
	NS_NAMESPACE_I("tcp", NULL, PRID_TCP, PRID_PCLASS_XPORT,
		"Transmission Control Protocol", NULL,
	       	stdproto_tcp_ns_elems, array_length(stdproto_tcp_ns_elems));

static struct ns_pktfld tcp_ns_sport =
	NS_BYTEFIELD_I("sport", &tcp_ns, PRID_TCP, 0, 2,
		"Source Port", &ns_fmt_dec);
static struct ns_pktfld tcp_ns_dport =
	NS_BYTEFIELD_I("dport", &tcp_ns, PRID_TCP, 2, 2,
		"Destination Port", &ns_fmt_dec);
static struct ns_pktfld tcp_ns_seqn =
	NS_BYTEFIELD_I("seqn", &tcp_ns, PRID_TCP, 4, 4,
		"Sequence Number", &ns_fmt_dec);
static struct ns_pktfld tcp_ns_ackn =
	NS_BYTEFIELD_I("ackn", &tcp_ns, PRID_TCP, 8, 4,
		"Acknowlege Number", &ns_fmt_dec);
static struct ns_pktfld tcp_ns_doff =
	NS_BITFIELD_I("doff", &tcp_ns, PRID_TCP, 12, 0, 4,
		"Data Offset", &ns_fmt_wlen);
static struct ns_pktfld tcp_ns_resv =
	NS_BITFIELD_I("resv", &tcp_ns, PRID_TCP, 12, 4, 4,
		"Reserved Bits", &ns_fmt_hex);
static struct ns_pktfld tcp_ns_cwr =
	NS_FBITFIELD_I("cwr", &tcp_ns, PRID_TCP, 13, 0, 1,
		"Congest Win Reduced", &ns_fmt_fbf, 0, 8);
static struct ns_pktfld tcp_ns_ece =
	NS_FBITFIELD_I("ece", &tcp_ns, PRID_TCP, 13, 1, 1,
		"ECN Enabled", &ns_fmt_fbf, 1, 8);
static struct ns_pktfld tcp_ns_urg =
	NS_FBITFIELD_I("urg", &tcp_ns, PRID_TCP, 13, 2, 1,
		"Urgent", &ns_fmt_fbf, 2, 8);
static struct ns_pktfld tcp_ns_ack =
	NS_FBITFIELD_I("ack", &tcp_ns, PRID_TCP, 13, 3, 1,
		"Acknowledgement", &ns_fmt_fbf, 3, 8);
static struct ns_pktfld tcp_ns_psh =
	NS_FBITFIELD_I("psh", &tcp_ns, PRID_TCP, 13, 4, 1,
		"Push", &ns_fmt_fbf, 4, 8);
static struct ns_pktfld tcp_ns_rst =
	NS_FBITFIELD_I("rst", &tcp_ns, PRID_TCP, 13, 5, 1,
		"Reset", &ns_fmt_fbf, 5, 8);
static struct ns_pktfld tcp_ns_syn =
	NS_FBITFIELD_I("syn", &tcp_ns, PRID_TCP, 13, 6, 1,
		"Synchronize", &ns_fmt_fbf, 6, 8);
static struct ns_pktfld tcp_ns_fin =
	NS_FBITFIELD_I("fin", &tcp_ns, PRID_TCP, 13, 7, 1,
		"Finalize", &ns_fmt_fbf, 7, 8);
static struct ns_pktfld tcp_ns_win =
	NS_BYTEFIELD_I("win", &tcp_ns, PRID_TCP, 14, 2,
		"Window", &ns_fmt_dec);
static struct ns_pktfld tcp_ns_cksum =
	NS_BYTEFIELD_I("cksum", &tcp_ns, PRID_TCP, 16, 2,
		"Checksum", &ns_fmt_hex);
static struct ns_pktfld tcp_ns_urgp =
	NS_BYTEFIELD_I("urgp", &tcp_ns, PRID_TCP, 18, 2,
		"Urgent Pointer", &ns_fmt_dec);
static struct ns_pktfld tcp_ns_opt =
	NS_BYTEFIELD_VARLEN_I("opt", &tcp_ns, PRID_TCP, PRP_TCPFLD_OPT, 0,
		PRP_OI_POFF,
		"TCP Options", &ns_fmt_summary);

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
		"TCP Maximum Segment Size Option", NULL,
		stdproto_tcp_mss_ns_elems,
		array_length(stdproto_tcp_mss_ns_elems));
static struct ns_pktfld tcp_mss_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_mss_ns, PRID_TCP, PRP_TCPFLD_MSS, 0, 1,
		"Kind", &ns_fmt_dec);
static struct ns_pktfld tcp_mss_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_mss_ns, PRID_TCP, PRP_TCPFLD_MSS, 1, 1,
		"Length", &ns_fmt_dec);
static struct ns_pktfld tcp_mss_mss =
	NS_BYTEFIELD_IDX_I("mss", &tcp_mss_ns, PRID_TCP, PRP_TCPFLD_MSS, 2, 2,
		"Max Segment Size", &ns_fmt_dec);
struct ns_elem *stdproto_tcp_mss_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_mss_kind, (struct ns_elem *)&tcp_mss_len,
	(struct ns_elem *)&tcp_mss_mss,
};

/* TCP Window Scale Option */
static struct ns_namespace tcp_wscale_ns = 
	NS_NAMESPACE_IDX_I("wscale", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_WSCALE, 4,
		"TCP Window Scale Option", NULL,
		stdproto_tcp_wscale_ns_elems,
		array_length(stdproto_tcp_wscale_ns_elems));
static struct ns_pktfld tcp_wscale_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_wscale_ns, PRID_TCP, PRP_TCPFLD_WSCALE,
		0, 1, "Kind", &ns_fmt_dec);
static struct ns_pktfld tcp_wscale_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_wscale_ns, PRID_TCP, PRP_TCPFLD_WSCALE,
		1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld tcp_wscale_scale =
	NS_BYTEFIELD_IDX_I("scale", &tcp_wscale_ns, PRID_TCP, PRP_TCPFLD_WSCALE,
		2, 1, "Window Scale", &ns_fmt_dec);
struct ns_elem *stdproto_tcp_wscale_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_wscale_kind, (struct ns_elem *)&tcp_wscale_len,
	(struct ns_elem *)&tcp_wscale_scale,
};

/* TCP Selective Acknowledgement Permitted Option */
static struct ns_namespace tcp_sackok_ns = 
	NS_NAMESPACE_IDX_I("sackok", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_SACKOK, 2,
		"TCP Window Scale Option", NULL,
		stdproto_tcp_sackok_ns_elems,
		array_length(stdproto_tcp_sackok_ns_elems));
static struct ns_pktfld tcp_sackok_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_sackok_ns, PRID_TCP, PRP_TCPFLD_SACKOK,
		0, 1, "Kind", &ns_fmt_dec);
static struct ns_pktfld tcp_sackok_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_sackok_ns, PRID_TCP, PRP_TCPFLD_SACKOK,
		1, 1, "Length", &ns_fmt_dec);
struct ns_elem *stdproto_tcp_sackok_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_sackok_kind, (struct ns_elem *)&tcp_sackok_len,
};

/* TCP Selective Acknowledgement Option */
static struct ns_namespace tcp_sack_ns = 
	NS_NAMESPACE_VARLEN_I("sack", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_SACK,
		PRP_TCPFLD_SACK_END,
		"TCP Selective Acknowledgement Option", NULL,
		stdproto_tcp_sack_ns_elems,
		array_length(stdproto_tcp_sack_ns_elems));
static struct ns_pktfld tcp_sack_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_sack_ns, PRID_TCP, PRP_TCPFLD_SACK, 
		0, 1, "Kind", &ns_fmt_dec);
static struct ns_pktfld tcp_sack_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_sack_ns, PRID_TCP, PRP_TCPFLD_SACK,
		1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld tcp_sack_blocks =
	NS_BYTEFIELD_VARLEN_I("blocks", &tcp_sack_ns, PRID_TCP, PRP_TCPFLD_SACK,
		2, PRP_TCPFLD_SACK_END, 
		"Selective Acknowledgements", &ns_fmt_raw);
struct ns_elem *stdproto_tcp_sack_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_sack_kind, (struct ns_elem *)&tcp_sack_len,
	(struct ns_elem *)&tcp_sack_blocks,
};


/* TCP Timestamp Option */
static struct ns_namespace tcp_ts_ns = 
	NS_NAMESPACE_IDX_I("ts", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_TSTAMP, 10,
		"TCP Timestamp Option", NULL,
		stdproto_tcp_ts_ns_elems,
		array_length(stdproto_tcp_ts_ns_elems));
static struct ns_pktfld tcp_ts_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_ts_ns, PRID_TCP, PRP_TCPFLD_TSTAMP,
		0, 1, "Kind", &ns_fmt_dec);
static struct ns_pktfld tcp_ts_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_ts_ns, PRID_TCP, PRP_TCPFLD_TSTAMP,
		1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld tcp_ts_val =
	NS_BYTEFIELD_IDX_I("val", &tcp_ts_ns, PRID_TCP, PRP_TCPFLD_TSTAMP, 
		2, 4, "Value", &ns_fmt_dec);
static struct ns_pktfld tcp_ts_echo =
	NS_BYTEFIELD_IDX_I("echo", &tcp_ts_ns, PRID_TCP, PRP_TCPFLD_TSTAMP,
		6, 4, "Echoed Value", &ns_fmt_dec);
struct ns_elem *stdproto_tcp_ts_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_ts_kind, (struct ns_elem *)&tcp_ts_len,
	(struct ns_elem *)&tcp_ts_val, (struct ns_elem *)&tcp_ts_echo,
};


/* TCP MD5 Signature Option */
static struct ns_namespace tcp_md5_ns = 
	NS_NAMESPACE_IDX_I("md5", &tcp_ns, PRID_TCP, PRID_NONE,
		PRP_TCPFLD_MD5, 18,
		"TCP MD5 Signature Option", NULL,
		stdproto_tcp_md5_ns_elems,
		array_length(stdproto_tcp_md5_ns_elems));
static struct ns_pktfld tcp_md5_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_md5_ns, PRID_TCP, PRP_TCPFLD_MD5,
		0, 1, "Kind", &ns_fmt_dec);
static struct ns_pktfld tcp_md5_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_md5_ns, PRID_TCP, PRP_TCPFLD_MD5,
		1, 1, "Length", &ns_fmt_dec);
static struct ns_pktfld tcp_md5_sig =
	NS_BYTEFIELD_IDX_I("sig", &tcp_md5_ns, PRID_TCP, PRP_TCPFLD_MD5,
		2, 16, "Signature", &ns_fmt_raw);
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


/* GRE Namespace */
extern struct ns_elem *stdproto_gre_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace gre_ns = 
	NS_NAMESPACE_I("gre", NULL, PRID_GRE, PRID_PCLASS_TUNNEL,
		"Generic Routing Encapsulation", NULL,
	       	stdproto_gre_ns_elems, array_length(stdproto_gre_ns_elems));

static struct ns_pktfld gre_ns_c_flag =
	NS_FBITFIELD_I("c_flag", &gre_ns, PRID_GRE, 0, 0, 1,
		"Checksum Present", &ns_fmt_fbf, 0, 4);
static struct ns_pktfld gre_ns_r_flag =
	NS_FBITFIELD_I("r_flag", &gre_ns, PRID_GRE, 0, 1, 1,
		"Reserved", &ns_fmt_fbf, 1, 4);
static struct ns_pktfld gre_ns_k_flag =
	NS_FBITFIELD_I("k_flag", &gre_ns, PRID_GRE, 0, 2, 1,
		"Key Present", &ns_fmt_fbf, 2, 4);
static struct ns_pktfld gre_ns_s_flag =
	NS_FBITFIELD_I("s_flag", &gre_ns, PRID_GRE, 0, 3, 1,
		"Seq Present", &ns_fmt_fbf, 3, 4);
static struct ns_pktfld gre_ns_version =
	NS_BITFIELD_I("vers", &gre_ns, PRID_GRE, 1, 5, 3,
		"Version", &ns_fmt_dec);
static struct ns_pktfld gre_ns_proto =
	NS_BYTEFIELD_I("proto", &gre_ns, PRID_GRE, 2, 2,
		"Protocol Type", &ns_fmt_hex);
static struct ns_pktfld gre_ns_cksum =
	NS_BYTEFIELD_IDX_I("cksum", &gre_ns, PRID_GRE, PRP_GREFLD_CKSUM, 0, 2,
		"Checksum", &ns_fmt_hex);
static struct ns_pktfld gre_ns_key =
	NS_BYTEFIELD_IDX_I("key", &gre_ns, PRID_GRE, PRP_GREFLD_KEY, 0, 4,
		"Key", &ns_fmt_dec);
static struct ns_pktfld gre_ns_seq =
	NS_BYTEFIELD_IDX_I("seq", &gre_ns, PRID_GRE, PRP_GREFLD_SEQ, 0, 4,
		"Sequence Number", &ns_fmt_dec);


struct ns_elem *stdproto_gre_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&gre_ns_c_flag, (struct ns_elem *)&gre_ns_r_flag, 
	(struct ns_elem *)&gre_ns_k_flag, (struct ns_elem *)&gre_ns_s_flag, 
	(struct ns_elem *)&gre_ns_version, (struct ns_elem *)&gre_ns_proto, 
	(struct ns_elem *)&gre_ns_cksum, (struct ns_elem *)&gre_ns_key, 
	(struct ns_elem *)&gre_ns_seq
};


/* NVGRE Namespace */
extern struct ns_elem *stdproto_nvgre_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace nvgre_ns = 
	NS_NAMESPACE_I("nvgre", NULL, PRID_NVGRE, PRID_PCLASS_TUNNEL,
		"Network Virtualization Generic Routing Encapsulation", NULL,
	       	stdproto_nvgre_ns_elems, array_length(stdproto_nvgre_ns_elems));

static struct ns_pktfld nvgre_ns_c_flag =
	NS_FBITFIELD_I("c_flag", &nvgre_ns, PRID_NVGRE, 0, 0, 1,
	      "Checksum Present", &ns_fmt_fbf, 0, 4);
static struct ns_pktfld nvgre_ns_r_flag =
	NS_FBITFIELD_I("r_flag", &nvgre_ns, PRID_NVGRE, 0, 1, 1, "Reserved",
		&ns_fmt_fbf, 1, 4);
static struct ns_pktfld nvgre_ns_k_flag =
	NS_FBITFIELD_I("k_flag", &nvgre_ns, PRID_NVGRE, 0, 2, 1, "Key Present",
		&ns_fmt_fbf, 2, 4);
static struct ns_pktfld nvgre_ns_s_flag =
	NS_FBITFIELD_I("s_flag", &nvgre_ns, PRID_NVGRE, 0, 3, 1, "Seq Present",
		&ns_fmt_fbf, 3, 4);
static struct ns_pktfld nvgre_ns_version =
	NS_BITFIELD_I("vers", &nvgre_ns, PRID_NVGRE, 1, 5, 3, "Version",
		&ns_fmt_dec);
static struct ns_pktfld nvgre_ns_proto =
	NS_BYTEFIELD_I("proto", &nvgre_ns, PRID_NVGRE, 2, 2, "Protocol Type",
		&ns_fmt_hex);
static struct ns_pktfld nvgre_ns_vsid =
	NS_BYTEFIELD_I("vsid", &nvgre_ns, PRID_NVGRE, 4, 3, "Virtual Subnet ID",
		&ns_fmt_dec);
static struct ns_pktfld nvgre_ns_flowid =
	NS_BYTEFIELD_I("flowid", &nvgre_ns, PRID_NVGRE, 7, 1, "Flow ID",
		&ns_fmt_dec);


struct ns_elem *stdproto_nvgre_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&nvgre_ns_c_flag, (struct ns_elem *)&nvgre_ns_r_flag,
	(struct ns_elem *)&nvgre_ns_k_flag, (struct ns_elem *)&nvgre_ns_s_flag,
	(struct ns_elem *)&nvgre_ns_version, (struct ns_elem *)&nvgre_ns_proto,
	(struct ns_elem *)&nvgre_ns_vsid, (struct ns_elem *)&nvgre_ns_flowid, 
};


/* VXLAN Namespace */
extern struct ns_elem *stdproto_vxlan_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace vxlan_ns = 
	NS_NAMESPACE_I("vxlan", NULL, PRID_VXLAN, PRID_PCLASS_TUNNEL,
		"Virtual Extensible LAN", NULL,
	       	stdproto_vxlan_ns_elems, array_length(stdproto_vxlan_ns_elems));

static struct ns_pktfld vxlan_ns_vni_flag =
	NS_BITFIELD_I("vni_flag", &vxlan_ns, PRID_VXLAN, 0, 4, 1, "VNI Present",
		&ns_fmt_dec);
static struct ns_pktfld vxlan_ns_vni =
	NS_BYTEFIELD_I("vsid", &vxlan_ns, PRID_VXLAN, 4, 3, "Virtual Network ID",
		&ns_fmt_dec);


struct ns_elem *stdproto_vxlan_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&vxlan_ns_vni_flag, (struct ns_elem *)&vxlan_ns_vni,
};


/* MPLS Namespace */
extern struct ns_elem *stdproto_mpls_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace mpls_ns = 
	NS_NAMESPACE_I("mpls", NULL, PRID_MPLS, PRID_PCLASS_TUNNEL,
		"Multi-Protocol Label Switching", NULL,
		stdproto_mpls_ns_elems, array_length(stdproto_mpls_ns_elems));

static struct ns_pktfld mpls_ns_label =
	NS_BITFIELD_I("label", &mpls_ns, PRID_MPLS, 0, 0, 20, "Label",
		&ns_fmt_dec);
static struct ns_pktfld mpls_ns_tc =
	NS_BITFIELD_I("tc", &mpls_ns, PRID_MPLS, 2, 4, 3,
		"Traffic Class", &ns_fmt_dec);
static struct ns_pktfld mpls_ns_bos =
	NS_BITFIELD_I("bos", &mpls_ns, PRID_MPLS, 2, 7, 1,
		"Bottom of Stack", &ns_fmt_dec);
static struct ns_pktfld mpls_ns_ttl =
	NS_BYTEFIELD_I("ttl", &mpls_ns, PRID_MPLS, 3, 1, "Time to Live",
		&ns_fmt_dec);

extern struct ns_elem *stdproto_mpls_lbl1_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_mpls_lbl2_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_mpls_lbl3_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_mpls_lbl4_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_mpls_lbl5_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_mpls_lbl6_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_mpls_lbl7_ns_elems[STDPROTO_NS_SUB_ELEN];

static struct ns_namespace mpls_lbl1_ns = 
	NS_NAMESPACE_IDX_I("mpls1", &mpls_ns, PRID_MPLS, PRID_NONE,
		PRP_MPLSFLD_LBL1, 4, "MPLS Label 1", NULL,
		stdproto_mpls_lbl1_ns_elems,
		array_length(stdproto_mpls_lbl1_ns_elems));
static struct ns_pktfld mpls_lbl1_label =
	NS_BITFIELD_IDX_I("label", &mpls_lbl1_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 0, 0, 20, "Label", &ns_fmt_dec);
static struct ns_pktfld mpls_lbl1_tc =
	NS_BITFIELD_IDX_I("tc", &mpls_lbl1_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 2, 4, 3, "Traffic Class", &ns_fmt_dec);
static struct ns_pktfld mpls_lbl1_bos =
	NS_BITFIELD_IDX_I("bos", &mpls_lbl1_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 2, 7, 1, "Bottom of Stack", &ns_fmt_dec);
static struct ns_pktfld mpls_lbl1_ttl =
	NS_BYTEFIELD_IDX_I("ttl", &mpls_lbl1_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 3, 1, "Time to Live", &ns_fmt_dec);

struct ns_elem *stdproto_mpls_lbl1_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&mpls_lbl1_label, (struct ns_elem *)&mpls_lbl1_tc,
	(struct ns_elem *)&mpls_lbl1_bos, (struct ns_elem *)&mpls_lbl1_ttl,
};


static struct ns_namespace mpls_lbl2_ns = 
	NS_NAMESPACE_IDX_I("mpls2", &mpls_ns, PRID_MPLS, PRID_NONE,
		PRP_MPLSFLD_LBL1, 4, "MPLS Label 1", NULL,
		stdproto_mpls_lbl2_ns_elems,
		array_length(stdproto_mpls_lbl2_ns_elems));
static struct ns_pktfld mpls_lbl2_label =
	NS_BITFIELD_IDX_I("label", &mpls_lbl2_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 0, 0, 20, "Label", &ns_fmt_dec);
static struct ns_pktfld mpls_lbl2_tc =
	NS_BITFIELD_IDX_I("tc", &mpls_lbl2_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 2, 4, 3, "Traffic Class", &ns_fmt_dec);
static struct ns_pktfld mpls_lbl2_bos =
	NS_BITFIELD_IDX_I("bos", &mpls_lbl2_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 2, 7, 1, "Bottom of Stack", &ns_fmt_dec);
static struct ns_pktfld mpls_lbl2_ttl =
	NS_BYTEFIELD_IDX_I("ttl", &mpls_lbl2_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 3, 1, "Time to Live", &ns_fmt_dec);

struct ns_elem *stdproto_mpls_lbl2_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&mpls_lbl2_label, (struct ns_elem *)&mpls_lbl2_tc,
	(struct ns_elem *)&mpls_lbl2_bos, (struct ns_elem *)&mpls_lbl2_ttl,
};


static struct ns_namespace mpls_lbl3_ns = 
	NS_NAMESPACE_IDX_I("mpls3", &mpls_ns, PRID_MPLS, PRID_NONE,
		PRP_MPLSFLD_LBL1, 4, "MPLS Label 1", NULL,
		stdproto_mpls_lbl3_ns_elems,
		array_length(stdproto_mpls_lbl3_ns_elems));
static struct ns_pktfld mpls_lbl3_label =
	NS_BITFIELD_IDX_I("label", &mpls_lbl3_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 0, 0, 20, "Label", &ns_fmt_dec);
static struct ns_pktfld mpls_lbl3_tc =
	NS_BITFIELD_IDX_I("tc", &mpls_lbl3_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 2, 4, 3, "Traffic Class", &ns_fmt_dec);
static struct ns_pktfld mpls_lbl3_bos =
	NS_BITFIELD_IDX_I("bos", &mpls_lbl3_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 2, 7, 1, "Bottom of Stack", &ns_fmt_dec);
static struct ns_pktfld mpls_lbl3_ttl =
	NS_BYTEFIELD_IDX_I("ttl", &mpls_lbl3_ns, PRID_MPLS,
		PRP_MPLSFLD_LBL1, 3, 1, "Time to Live", &ns_fmt_dec);

struct ns_elem *stdproto_mpls_lbl3_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&mpls_lbl3_label, (struct ns_elem *)&mpls_lbl3_tc,
	(struct ns_elem *)&mpls_lbl3_bos, (struct ns_elem *)&mpls_lbl3_ttl,
};


struct ns_elem *stdproto_mpls_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&mpls_ns_label, (struct ns_elem *)&mpls_ns_tc,
	(struct ns_elem *)&mpls_ns_bos, (struct ns_elem *)&mpls_ns_ttl,
	(struct ns_elem *)&mpls_lbl1_ns, (struct ns_elem *)&mpls_lbl2_ns,
	(struct ns_elem *)&mpls_lbl3_ns, 
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
	if (pp_register(PRID_GRE, &gre_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_NVGRE, &nvgre_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_VXLAN, &vxlan_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PRID_MPLS, &mpls_proto_parser_ops) < 0)
		goto fail;

	if (ns_add_elem(NULL, (struct ns_elem *)&pkt_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&pdu_ns) < 0)
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
	if (ns_add_elem(NULL, (struct ns_elem *)&gre_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&nvgre_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&vxlan_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&mpls_ns) < 0)
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
	pp_unregister(PRID_GRE);
	pp_unregister(PRID_NVGRE);
	pp_unregister(PRID_VXLAN);
	pp_unregister(PRID_MPLS);

	ns_rem_elem((struct ns_elem *)&pkt_ns);
	ns_rem_elem((struct ns_elem *)&pdu_ns);
	ns_rem_elem((struct ns_elem *)&eth2_ns);
	ns_rem_elem((struct ns_elem *)&arp_ns);
	ns_rem_elem((struct ns_elem *)&ipv4_ns);
	ns_rem_elem((struct ns_elem *)&ipv6_ns);
	ns_rem_elem((struct ns_elem *)&icmp_ns);
	ns_rem_elem((struct ns_elem *)&icmp6_ns);
	ns_rem_elem((struct ns_elem *)&udp_ns);
	ns_rem_elem((struct ns_elem *)&tcp_ns);
	ns_rem_elem((struct ns_elem *)&gre_ns);
	ns_rem_elem((struct ns_elem *)&nvgre_ns);
	ns_rem_elem((struct ns_elem *)&vxlan_ns);
	ns_rem_elem((struct ns_elem *)&mpls_ns);
}
