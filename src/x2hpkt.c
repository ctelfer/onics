#include <stdio.h>
#include <ctype.h>
#include <limits.h>
#include <cat/optparse.h>
#include <cat/err.h>
#include "util.h"
#include "pktbuf.h"
#include "ns.h"
#include "stdproto.h"

FILE *g_file = NULL;
int g_keep_xhdr = 0;
ulong g_pktnum;
ulong g_ioff;
ulong g_pbase;
ulong g_len;
byte_t *g_p;

struct clopt g_optarr[] = {
	CLOPT_INIT(CLOPT_NOARG, 'x', "--keep-xhdr", "keep xpkt hdr in dump"),
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help")
};

struct clopt_parser g_oparser =
	CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));



void usage(const char *estr)
{
	char ubuf[4096];
	if (estr != NULL)
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	err("usage: %s [options]\n%s\n", g_oparser.argv[0], ubuf);
}


void parse_options()
{
	int rv;
	struct clopt *opt;
	const char *pktfile = NULL;
	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'x':
			g_keep_xhdr = 1;
			break;
		case 'f':
			pktfile = opt->val.str_val;
			break;
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);
	if (rv < g_oparser.argc) {
		if ((g_file = fopen(g_oparser.argv[rv], "r")) == NULL)
			errsys("fopen: ");
	} else {
		g_file = stdin;
	}
}


void printsep()
{
	printf("#####\n");
}


void print_unparsed(ulong soff, ulong eoff, const char *pfx)
{
	if (soff < eoff) {
		printf("%s Data -- %lu bytes [%lu, %lu]\n", pfx, 
		       eoff - soff, soff - g_pbase + g_ioff, 
		       eoff - g_pbase + g_ioff);
		hexdump(stdout, soff - g_pbase + g_ioff, g_p + soff, 
			eoff - soff);
	}
}


int getpfx(char *pfx, const char *in, uint plen)
{
	char const *end = in + plen - 3;
	char *pp = pfx;
	*pp++ = '#'; *pp++ = ' ';
	while ((*in != '\0') && (in < end))
		*pp++ = toupper(*in++);
	*pp++ = ':';
	*pp++ = ' ';
	*pp = '\0';
	return pp - pfx;
}


ulong get_offset(struct ns_pktfld *pf, struct prparse *prp)
{
	if ((pf->oidx >= prp->noff) || (prp->offs[pf->oidx] == PRP_OFF_INVALID))
		return PRP_OFF_INVALID;
	return prp->offs[pf->oidx] + pf->off;
}


#define MAXLINE		256
#define MAXPFX		16
void print_ns(struct ns_namespace *ns, struct prparse *prp, ulong soff,
	      ulong eoff, char line[MAXLINE])
{
	ulong foff;
	struct ns_pktfld *pf;
	struct raw r;
	int rv;
	int plen;
	int i;

	plen = getpfx(line, ns->name, 16);
	r.data = line + plen;
	r.len = MAXLINE - plen;

	if (ns->oidx == PRP_OI_SOFF) {
		printsep();
		rv = (*ns->fmt)((struct ns_elem *)ns, g_p, prp, &r);
		if (rv >= 0) {
			fputs(line, stdout);
			fputc('\n', stdout);
		}
		printsep();
	}

	for (i = 0; i < ns->nelem; ++i) {
		if (ns->elems[i] == NULL)
			break;
		if (ns->elems[i]->type == NST_NAMESPACE) {
			print_ns((struct ns_namespace *)ns->elems[i], prp, 
				 soff, eoff, line);
		} else if (ns->elems[i]->type == NST_PKTFLD) {
			pf = (struct ns_pktfld *)ns->elems[i];
			foff = get_offset(pf, prp);
			if ((foff >= soff) && (foff < eoff)) {
				rv = (*pf->fmt)(ns->elems[i], g_p, prp, &r);
				if (rv >= 0) {
					fputs(line, stdout);
					fputc('\n', stdout);
				}
			}
		}
	}
}



/* 
 * Print fields between soff and feoff.  Print data between soff and
 * deoff.
 */
void print_parse(struct prparse *prp, ulong soff, ulong feoff, ulong deoff,
		 int print_fields)
{
	char line[MAXLINE];
	struct ns_namespace *ns;

	ns = ns_lookup_by_type(NULL, prp->type);
	if (ns == NULL) {
		if ( prp->type == PPT_NONE )
			snprintf(line, MAXPFX, "# DATA: ");
		else
			snprintf(line, MAXPFX, "# PPT-%u: ", prp->type);
		print_unparsed(soff, deoff, line);
	} else if (print_fields) {
		print_ns(ns, prp, soff, feoff, line);
		hexdump(stdout, soff - g_pbase + g_ioff, g_p + soff, 
			deoff - soff);
	} else {
		getpfx(line, ns->name, 16);
		print_unparsed(soff, deoff, line);
	}
}



ulong walk_parse(struct prparse *from, struct prparse *region, ulong off)
{
	struct prparse *next;

	if ((next = prp_next_in_region(from, region)) != NULL) {
		if (off < prp_soff(next))
			print_parse(region, off, prp_soff(next),
				    prp_soff(next), 0);

		print_parse(next, prp_soff(next), prp_toff(next), 
			    prp_poff(next), 1);

		off = walk_parse(next, next, prp_poff(next));

		if (off < prp_eoff(next)) {
			print_parse(next, off, prp_eoff(next), prp_eoff(next), 
				    1);
			off = prp_eoff(next);
		}

		return walk_parse(next, region, off);
	} else { 
		ulong eoff = prp_list_head(region) ? 
				prp_toff(region) : 
				prp_eoff(region);
		if (off < eoff)
			print_parse(region, off, eoff, eoff, 0);
		return eoff;
	}
}


void dump_to_hex_packet(struct pktbuf *pkb)
{
	struct prparse *prp;
	int rv;

	g_len = pkb_get_len(pkb);
	g_p = pkb->buf;
	prp = &pkb->prp;
	g_pbase = prp_poff(prp);

	if (g_keep_xhdr) {
		struct xpkt *xp = pkb_get_xpkt(pkb);
		g_ioff = xpkt_doff(xp);
		abort_unless(prp_toff(prp) + g_ioff > g_ioff);
		printsep();
		printf("# Packet %lu -- %lu bytes\n", g_pktnum, g_len + g_ioff);
		printsep();
		printf("# eX-Packet Header %lu bytes\n", g_ioff);
		printsep();

		/* TODO: write up parsing for tags */

		if ((rv = pkb_pack(pkb)) < 0)
			err("Error packing packet %lu: %d\n", g_pktnum, rv);
		hexdump(stdout, 0, (byte_t *)xp, g_ioff);
		pkb_unpack(pkb);
	} else {
		g_ioff = 0;
		printsep();
		printf("# Packet %lu -- %lu bytes\n", g_pktnum, g_len);
		printsep();
	}

	walk_parse(prp, prp, prp_poff(prp));

	printf("\n\n");
}


int main(int argc, char *argv[])
{
	int rv;
	struct pktbuf *pkb;

	optparse_reset(&g_oparser, argc, argv);
	parse_options();
	register_std_proto();

	pkb_init(1);

	while ((rv = pkb_file_read(&pkb, g_file)) > 0) {
		++g_pktnum;
		pkb_parse(pkb);
		dump_to_hex_packet(pkb);
		pkb_free(pkb);
	}

	return 0;
}
