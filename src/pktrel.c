#include "pktbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <cat/err.h>
#include <cat/optparse.h>
#include <cat/time.h>

ulong g_npkts = 0;
double g_start_delay = 0.0;
double g_interval = 0.0;

struct clopt g_optarr[] = {
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help"),
	CLOPT_INIT(CLOPT_DOUBLE, 'd', "--delay", "delay start by <x> seconds"),
	CLOPT_INIT(CLOPT_DOUBLE, 'i', "--interval", "delay <x> seconds ")
};

struct clopt_parser g_oparser =
CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));


void usage(const char *estr)
{
	char ubuf[4096];
	if (estr != NULL)
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	err("usage: %s [options]\n" "%s", g_oparser.argv[0], ubuf);
}


void parse_options()
{
	int rv;
	struct clopt *opt;

	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'd':
			g_start_delay = opt->val.dbl_val;
			break;
		case 'i':
			g_interval = opt->val.dbl_val;
			break;
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);
	if (g_oparser.argc - rv != 0)
		usage("Extra arguments present");
}


void alarm_handler(int sig)
{
}


void sleepfor(struct cat_time *amt)
{
	struct itimerval it;
	it.it_interval.tv_sec = 0;
	it.it_interval.tv_usec = 0;
	it.it_value.tv_sec = amt->sec;
	it.it_value.tv_usec = amt->nsec / 1000;
	setitimer(ITIMER_REAL, &it, NULL);
	pause();
}


int main(int argc, char *argv[])
{
	int rv;
	struct pktbuf *p;
	struct cat_time cur = { 0, 0 }, next, diff;
	struct xpkt_tag_ts *ts;

	pkb_init(1);

	signal(SIGALRM, alarm_handler);
	if (g_start_delay > 0) {
		struct cat_time t;
		sleepfor(tm_dset(&t, g_start_delay));
	}

	while ((rv = pkb_fd_read(0, &p)) > 0) {
		ts = (struct xpkt_tag_ts *)pkb_find_tag(p, XPKT_TAG_TIMESTAMP, 0);
		if (ts) {
			tm_lset(&next, ts->sec, ts->nsec);
		} else {
			/* free all packets that lack timestamp fields */
			pkb_free(p);
			continue;
		}

		if (next.sec < 0 || next.nsec < 0) {
			fprintf(stderr,
				"Invalid timestamp on packet %lu (%ld.%09ld)",
				g_npkts + 1, next.sec, next.nsec);
			continue;
		}
		if (++g_npkts == 1)
			cur = next;

		if (g_interval > 0.0) {
			sleepfor(tm_dset(&diff, g_interval));
		} else if (tm_cmp(&next, &cur) > 0) {
			diff = next;
			sleepfor(tm_sub(&diff, &cur));
			cur = next;
		}

		rv = pkb_pack(p);
		abort_unless(rv == 0);
		if (pkb_fd_write(1, p) < 0)
			errsys("Error writing packet %lu", g_npkts);
		pkb_free(p);
	}
	if (rv < 0)
		errsys("Error reading packet %lu", g_npkts + 1);

	return 0;
}
