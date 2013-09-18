/*
 * ONICS
 * Copyright 2013 
 * Christopher Adam Telfer
 *
 * nft.c -- Network Flow Tracker
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
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <cat/err.h>
#include <cat/optparse.h>
#include <cat/stduse.h>
#include <cat/pack.h>

#include "pktbuf.h"
#include "util.h"
#include "tcpip_hdrs.h"
#include "stdproto.h"


union addr {
	uint32_t		ip;
	struct ipv6addr		ip6;
	struct ethaddr		eth;
};


enum {
	FEVT_START,
	FEVT_UPDATE,
	FEVT_END,
};


const char *fevt_strs[] = {
	"START",
	"UPDATE",
	"END",
};


struct flow_key {
	union addr		saddr;
	union addr		daddr;
	uint16_t		sport;
	uint16_t		dport;
	uint16_t		etype;
	uint8_t			netproto;
	uint8_t			flags;
};


struct flow {
	struct flow_key		key;
	struct dlist		toevt;
	uint64_t		flowid;
	ulong			cnpkts;
	ulong			cnbytes;
	ulong			snpkts;
	ulong			snbytes;
	cat_time_t		start;
	cat_time_t		end;
};


struct flowtab {
	struct splay *		flows;
	struct dlist 		events;
};


uint64_t next_flowid = 1;


static const cat_time_t tm_interval = TM_LONG_INITIALIZER(0, 200000000);
static cat_time_t tm_flow_timeout = TM_LONG_INITIALIZER(60, 0);
static cat_time_t tm_update = TM_LONG_INITIALIZER(10, 0);
static cat_time_t tm_base = TM_LONG_INITIALIZER(0, 0);
struct dlist update_event;
int realtime = 1;
FILE *evtfile;

void build_key_ipv4(struct pktbuf *pkb, struct prparse *dlprp, 
		    struct flow_key *key, struct flow_key *rkey);
void build_key_ipv6(struct pktbuf *pkb, struct prparse *dlprp, 
		    struct flow_key *key, struct flow_key *rkey);
void build_key_arp(struct pktbuf *pkb, struct prparse *dlprp, 
		   struct flow_key *key, struct flow_key *rkey);
void build_key_eth(struct pktbuf *pkb, struct prparse *dlprp, 
		   struct flow_key *key, struct flow_key *rkey);

struct clopt g_optarr[] = {
	CLOPT_I_NOARG('r', NULL, "run in realtime mode (default)"),
	CLOPT_I_NOARG('R', NULL, "report timestamps relative to program start "
		   		 "(realtime mode only)"),
	CLOPT_I_NOARG('t', NULL, "run in timestamp mode"),
	CLOPT_I_STRING('f', NULL, "FLOWFILE", "file to output flow info to"),
	CLOPT_I_DOUBLE('u', NULL, "INTERVAL",
		       "set the interval at which to generate updates"),
	CLOPT_I_NOARG('h', NULL, "print help"),
};

struct clopt_parser g_oparser =
			CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));


void usage(const char *estr)
{
	char ubuf[4096];
	if (estr != NULL)
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	fprintf(stderr, "usage: %s [options] [INFILE [OUTFILE]]\n%s", 
		g_oparser.argv[0], ubuf);
	exit(1);
}


void parse_args(int argc, char *argv[], int *ifd, int *ofd)
{
	int rv;
	struct clopt *opt;
	const char *fn;

	evtfile = stderr;
	optparse_reset(&g_oparser, argc, argv);
	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'r':
			realtime = 1;
			break;
		case 'R':
			tm_base = tm_uget();
			break;
		case 't':
			realtime = 0;
			break;
		case 'f':
			evtfile = fopen(opt->val.str_val, "w");
			if (evtfile == NULL)
				errsys("fopen(%s): ", opt->val.str_val);
			break;
		case 'u':
			tm_update = tm_dset(opt->val.dbl_val);
			break;
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);

	if (rv < argc) {
		fn = argv[rv++];
		*ifd = open(fn, O_RDONLY);
		if (*ifd < 0)
			errsys("unable to open file '%s'", fn);
	}

	if (rv < argc) {
		fn = argv[rv++];
		*ofd = open(fn, O_WRONLY);
		if (*ofd < 0)
			errsys("unable to open file '%s'", fn);
	}

	if (rv < argc)
		usage("Too many arguments");
}


static void reset_flow_key(struct flow_key *key)
{
	memset(key, 0, sizeof(*key));
}


void build_key_tcp(struct pktbuf *pkb, struct prparse *tcpprp, 
		   struct flow_key *key, struct flow_key *rkey)
{
	struct tcph *tcp = prp_header(tcpprp, pkb->buf, struct tcph);
	key->sport  = ntoh16(tcp->sport);
	key->dport  = ntoh16(tcp->dport);
	rkey->sport = ntoh16(tcp->dport);
	rkey->dport = ntoh16(tcp->sport);
}


void build_key_udp(struct pktbuf *pkb, struct prparse *udpprp, 
		   struct flow_key *key, struct flow_key *rkey)
{
	struct udph *udp = prp_header(udpprp, pkb->buf, struct udph);
	key->sport  = ntoh16(udp->sport);
	key->dport  = ntoh16(udp->dport);
	rkey->sport = ntoh16(udp->dport);
	rkey->dport = ntoh16(udp->sport);
}


void build_key_ipv4(struct pktbuf *pkb, struct prparse *ipprp, 
		    struct flow_key *key, struct flow_key *rkey)
{
	struct ipv4h *ip;
	struct icmph *icmp;
	struct prparse *xpprp;
	struct prparse *eipprp;

	ip = prp_header(ipprp, pkb->buf, struct ipv4h);

	key->saddr.ip = ip->saddr;
	key->daddr.ip = ip->daddr;
	key->etype = ETHTYPE_IP;
	key->netproto = ip->proto;

	rkey->saddr.ip = ip->daddr;
	rkey->daddr.ip = ip->saddr;
	rkey->etype = ETHTYPE_IP;
	rkey->netproto = ip->proto;

	xpprp = prp_next(ipprp);
	if (xpprp->prid == PRID_TCP) {
		build_key_tcp(pkb, xpprp, key, rkey);
	} else if (xpprp->prid == PRID_UDP) {
		build_key_udp(pkb, xpprp, key, rkey);
	} else if (xpprp->prid == PRID_ICMP) {
		icmp = prp_header(xpprp, pkb->buf, struct icmph);
		if (ICMPT_IS_ERR(icmp->type)) {
			eipprp = prp_next(ipprp);
			if (eipprp->prid != PRID_IPV4)
				return;
			reset_flow_key(key);
			reset_flow_key(rkey);
			build_key_ipv4(pkb, eipprp, key, rkey);
		} else if (ICMPT_IS_QUERY(icmp->type)) {
			key->sport = ntoh16(icmp->u.echo.id);
			rkey->sport = ntoh16(icmp->u.echo.id);
		}
	} 
}



void build_key_ipv6(struct pktbuf *pkb, struct prparse *ip6prp, 
		    struct flow_key *key, struct flow_key *rkey)
{
	struct ipv6h *ip6;
	struct icmp6h *icmp6;
	struct icmp6_echo *i6echo;
	struct prparse *xpprp;
	struct prparse *eip6prp;

	ip6 = prp_header(ip6prp, pkb->buf, struct ipv6h);

	key->saddr.ip6 = ip6->saddr;
	key->daddr.ip6 = ip6->daddr;
	key->etype = ETHTYPE_IPV6;
	key->netproto = PRP_IPV6_NXDHDR(ip6prp, pkb->buf);

	rkey->saddr.ip6 = ip6->daddr;
	rkey->daddr.ip6 = ip6->saddr;
	rkey->etype = ETHTYPE_IPV6;
	rkey->netproto = PRP_IPV6_NXDHDR(ip6prp, pkb->buf);

	xpprp = prp_next(ip6prp);
	if (xpprp->prid == PRID_TCP) {
		build_key_tcp(pkb, xpprp, key, rkey);
	} else if (xpprp->prid == PRID_UDP) {
		build_key_udp(pkb, xpprp, key, rkey);
	} else if (xpprp->prid == PRID_ICMP6) {
		icmp6 = prp_header(xpprp, pkb->buf, struct icmp6h);
		if (ICMP6T_IS_ERR(icmp6->type)) {
			eip6prp = prp_next(ip6prp);
			if (eip6prp->prid != PRID_IPV6)
				return;
			reset_flow_key(key);
			reset_flow_key(rkey);
			build_key_ipv6(pkb, eip6prp, key, rkey);
		} else if (ICMP6T_IS_ECHO(icmp6->type)) {
			i6echo = (struct icmp6_echo *)icmp6;
			key->sport = ntoh16(i6echo->id);
			rkey->sport = ntoh16(i6echo->id);
		}
	} 
}


void build_key_arp(struct pktbuf *pkb, struct prparse *arpprp, 
		   struct flow_key *key, struct flow_key *rkey)
{
	struct arph *arp;
	struct eth_arph *earp;

	arp = prp_header(arpprp, pkb->buf, struct arph);
	if ((ntoh16(arp->hwfmt) != ARPT_ETHERNET) || 
	    (ntoh16(arp->prfmt) != ETHTYPE_IP) || 
	    (arp->hwlen != 6) || (arp->prlen != 4)) {
		build_key_eth(pkb, prp_prev(arpprp), key, rkey);
		return;
	}

	earp = (struct eth_arph *)arp;

	key->etype = ETHTYPE_ARP;
	memmove(&key->saddr.ip, earp->sndpraddr, 4);
	memmove(&key->daddr.ip, earp->trgpraddr, 4);

	rkey->etype = ETHTYPE_ARP;
	memmove(&rkey->saddr.ip, earp->trgpraddr, 4);
	memmove(&rkey->daddr.ip, earp->sndpraddr, 4);
}


void build_key_eth(struct pktbuf *pkb, struct prparse *dlprp, 
		   struct flow_key *key, struct flow_key *rkey)
{
	struct eth2h *eh;

	eh = prp_header(dlprp, pkb->buf, struct eth2h);

	key->etype = ntoh16(eh->ethtype);
	key->saddr.eth = eh->src;
	key->daddr.eth = eh->dst;

	rkey->etype = ntoh16(eh->ethtype);
	key->saddr.eth = eh->dst;
	key->daddr.eth = eh->src;
}


int build_flow_key(struct pktbuf *pkb, struct flow_key *key,
		   struct flow_key *rkey)
{
	struct prparse *dlprp;
	struct prparse *netprp;

	reset_flow_key(key);
	reset_flow_key(rkey);

	dlprp = prp_next(&pkb->prp);
	if (dlprp->prid != PRID_ETHERNET2)
		return -1;

	netprp = prp_next(dlprp);
	if (netprp->prid == PRID_IPV4) {
		build_key_ipv4(pkb, netprp, key, rkey);
	} else if (netprp->prid == PRID_IPV6) {
		build_key_ipv6(pkb, netprp, key, rkey);
	} else if (netprp->prid == PRID_ARP) {
		build_key_arp(pkb, netprp, key, rkey);
	} else {
		build_key_eth(pkb, dlprp, key, rkey);
	}

	return 0;
}


void flow_key_to_str(struct flow_key *key, char *ks, size_t kslen)
{
	int n;
	char sa[64];
	char da[64];

	if (key->etype == ETHTYPE_IP) {
		iptostr(sa, &key->saddr.ip, sizeof(sa));
		iptostr(da, &key->daddr.ip, sizeof(da));
		n = snprintf(ks, kslen, "IP:ca=%s,sa=%s,proto=%u", sa, da,
			     key->netproto);
	} else if (key->etype == ETHTYPE_IPV6) {
		ip6tostr(sa, &key->saddr.ip6, sizeof(sa));
		ip6tostr(da, &key->daddr.ip6, sizeof(da));
		n = snprintf(ks, kslen, "IP6:ca=%s,sa=%s,proto=%u", sa, da,
			     key->netproto);
	} else if (key->etype == ETHTYPE_ARP) {
		iptostr(sa, &key->saddr.ip, sizeof(sa));
		iptostr(da, &key->daddr.ip, sizeof(da));
		n = snprintf(ks, kslen, "ARP:ca=%s,sa=%s", sa, da);
		return;
	} else {
		ethtostr(sa, &key->saddr.eth, sizeof(sa));
		ethtostr(da, &key->daddr.eth, sizeof(da));
		n = snprintf(ks, kslen, "ETH:ca=%s,sa=%s,etype=%04x", sa, da,
			     key->etype);
		return;
	}

	abort_unless(n < kslen && n > 0);
	ks += n;
	kslen -=n;

	if ((key->netproto == IPPROT_TCP) || (key->netproto == IPPROT_UDP)) {
		snprintf(ks, kslen, ",cpt=%u,spt=%u", key->sport, key->dport);
	}
}


double dbtime(cat_time_t t)
{
	if (realtime)
		t = tm_sub(t, tm_base);
	return tm_2dbl(t);
}


void gen_flow_event(struct flow *f, int evtype)
{
	char keystr[256];
	char tstr[64] = "";
	cat_time_t dur;

	flow_key_to_str(&f->key, keystr, sizeof(keystr));
	if (evtype == FEVT_START) {
		snprintf(tstr, sizeof(tstr), "Start=%.3lf", 
			 dbtime(f->start));
	} else if (evtype == FEVT_UPDATE) {
		dur = tm_sub(tm_uget(), f->start);
		snprintf(tstr, sizeof(tstr), "Start=%.3lf,Dur=%.3lf", 
			 dbtime(f->start), dbtime(dur));
	} else if (evtype == FEVT_END) {
		dur = tm_sub(f->end, f->start);
		snprintf(tstr, sizeof(tstr), 
			 "Start=%.3lf,End=%.3lf,Dur=%.3lf", 
			 dbtime(f->start), dbtime(f->end), dbtime(dur));
	}
	fprintf(evtfile, "|FLOW %s|%s|%s|C2S:%lu,%lu|S2C:%lu,%lu|\n", 
		fevt_strs[evtype], keystr, tstr, 
		f->cnpkts, f->cnbytes, f->snpkts, f->snbytes);
}


void track_flows(struct flowtab *ft, struct pktbuf *pkb)
{
	struct xpkt_tag_flowid xf, *xfp;
	struct flow_key key, rkey;
	struct flow *f;
	int swap = 0;
	int create = 0;

	if (build_flow_key(pkb, &key, &rkey) < 0)
		return;

	/* lookup and create flow */
	f = st_get_dptr(ft->flows, &key);
	if (f == NULL) {
		swap = 1;
		f = st_get_dptr(ft->flows, &rkey);
	}

	if (f != NULL) {

		dl_update(&ft->events, &f->toevt, tm_flow_timeout);

	} else {

		f = ecalloc(sizeof(*f), 1);
		f->key = key;
		f->flowid = next_flowid++;
		dl_init(&f->toevt, tm_flow_timeout);
		dl_ins(&ft->events, &f->toevt);
		f->start = tm_uget();
		st_put(ft->flows, &f->key, f);
		create = 1;
		swap = 0;

	}

	/* update stats for the flow */
	if (!swap) {
		++f->cnpkts;
		f->cnbytes += pkb_get_len(pkb);
	} else {
		++f->snpkts;
		f->snbytes += pkb_get_len(pkb);
	}

	xfp = (struct xpkt_tag_flowid *)pkb_find_tag(pkb, XPKT_TAG_FLOW, 0);
	if (xfp != NULL) {
		xfp->flowid = f->flowid;
	} else {
		xpkt_tag_flowid_init(&xf, f->flowid);
		pkb_add_tag(pkb, (struct xpkt_tag_hdr *)&xf);
	}

	if (create) {
		gen_flow_event(f, FEVT_START);
		fflush(evtfile);
	}
}


static void gen_flow_updates(struct flowtab *ft)
{
	struct flow *f;
	struct list *le;

	l_for_each(le, &ft->events.entry) {
		f = container(l_to_dl(le), struct flow, toevt);
		gen_flow_event(f, FEVT_UPDATE);
	}
	fflush(evtfile);

	dl_init(&update_event, tm_update);
	dl_ins(&ft->events, &update_event);
}


static void timeout_flow(struct flowtab *ft, struct flow *f)
{
	st_clr(ft->flows, &f->key);
	f->end = tm_uget();
	gen_flow_event(f, FEVT_END);
	fflush(evtfile);
	free(f);
}


void dispatch_time_events(struct flowtab *ft, cat_time_t elapsed)
{
	struct list evlst, *le;
	struct dlist *evt;
	struct flow *f;

	dl_adv(&ft->events, elapsed, &evlst);
	while ((le = l_deq(&evlst)) != NULL) {
		evt = l_to_dl(le);
		if (evt == &update_event) {
			gen_flow_updates(ft);
		} else {
			f = container(l_to_dl(le), struct flow, toevt);
			timeout_flow(ft, f);
		}
	}
}


static void ft_init(struct flowtab *ft)
{
	ft->flows = st_new(&estdmm, CAT_KT_BIN, sizeof(struct flow_key), 0);
	dl_init(&ft->events, tm_zero);
	dl_init(&update_event, tm_update);
	dl_ins(&ft->events, &update_event);
}


static void live_timeouts(fd_set *rset, int maxfd, cat_time_t *ntick,
			  struct flowtab *ft)
{
	cat_time_t now, delta;
	struct timeval timeout;
	int rv;

	now = tm_uget();
	if (tm_cmp(now, *ntick) >= 0) {
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;
	} else {
		delta = tm_sub(*ntick, now);
		timeout.tv_sec = delta.sec;
		timeout.tv_usec = delta.nsec / 1000;
	}

	rv = select(maxfd, rset, NULL, NULL, &timeout);
	if (rv < 0)
		errsys("select(): ");

	for (now = tm_uget(); tm_cmp(*ntick, now) <= 0; 
	     *ntick = tm_add(*ntick, tm_interval))
		dispatch_time_events(ft, tm_interval);
}


static void offline_timeouts(struct pktbuf *pkb, cat_time_t *ntick, 
			     struct flowtab *ft)
{
	struct xpkt_tag_ts *xts = 
		(struct xpkt_tag_ts *)pkb_find_tag(pkb, XPKT_TAG_TIMESTAMP, 0);
	cat_time_t tm_ts;
	cat_time_t delta;

	if (xts == NULL)
		return;
	tm_ts = tm_lset(xts->sec, xts->nsec);
	if (tm_cmp(*ntick, tm_ts) >= 0)
		return;
	delta = tm_sub(tm_ts, *ntick);
	dispatch_time_events(ft, delta);
	*ntick = tm_ts;
}


static void drain_offline_timeouts(struct flowtab *ft)
{
	struct dlist *dle;
	struct flow *f;

	while ((dle = dl_deq(&ft->events)) != NULL) {
		if (dle == &update_event)
			continue;
		f = container(dle, struct flow, toevt);
		timeout_flow(ft, f);
	}
}


int main(int argc, char *argv[])
{
	int rv;
	struct pktbuf *pkb;
	int ifd = 0;
	int ofd = 1;
	ulong npkts = 0;
	struct flowtab ft;
	fd_set rset, rset_save;
	cat_time_t ntick;

	parse_args(argc, argv, &ifd, &ofd);
	pkb_init_pools(1);
	register_std_proto();
	ft_init(&ft);

	if (realtime) {
		ntick = tm_add(tm_uget(), tm_interval);
		FD_ZERO(&rset_save);
		FD_SET(ifd, &rset_save);
	} else {
		ntick = tm_zero;
	}

	while (1) {
		if (realtime) {
			rset = rset_save;
			live_timeouts(&rset, ifd+1, &ntick, &ft);
			if (!FD_ISSET(ifd, &rset))
				continue;
		}

		rv = pkb_fd_read(&pkb, ifd);
		if (rv <= 0)
			break;

		if (!realtime)
			offline_timeouts(pkb, &ntick, &ft);

		++npkts;
		if (pkb_parse(pkb) == 0)
			track_flows(&ft, pkb);

		rv = pkb_pack(pkb);
		abort_unless(rv == 0);
		if (pkb_fd_write(pkb, ofd) < 0)
			errsys("Error writing packet %lu", npkts);
		pkb_free(pkb);
	}
	if (rv < 0)
		errsys("Error reading packet %lu: ", npkts + 1);

	if (!realtime)
		drain_offline_timeouts(&ft);

	return 0;
}
