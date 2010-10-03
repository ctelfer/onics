#include "pktbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <cat/err.h>
#include <cat/optparse.h>
#include <cat/bitset.h>

#define MAX_FDS      256

int g_nfd = 0;
ulong g_npkts = 0;
DECLARE_BITSET(g_fdseen, MAX_FDS);
DECLARE_BITSET(g_fdok, MAX_FDS);

struct clopt g_optarr[] = {
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
	err("usage: %s [options]\n" "%s", g_oparser.argv[0], ubuf);
}


void parse_options()
{
	int rv;
	struct clopt *opt;

	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);

	if (g_oparser.argc - rv != 0)
		usage("Extra arguments present");
}


/* determine if an FD is open for writing */
int fdok(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	return (flags != -1) &&
	    ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR);
}


int main(int argc, char *argv[])
{
	int rv, fd;
	struct pktbuf *p;

	bset_set(g_fdseen, 0);
	bset_set(g_fdseen, 1);
	bset_set(g_fdseen, 2);

	pkb_init(1);

	while ((rv = pkb_fd_read(0, &p)) > 0) {
		++g_npkts;
		/* TODO META */
		fd = 1;

		if (!bset_test(g_fdseen, fd)) {
			bset_set(g_fdseen, fd);
			bset_set_to(g_fdok, fd, fdok(fd));
		}

		if (bset_test(g_fdok, fd)) {
			if (pkb_fd_write(fd, p) < 0)
				errsys("Error writing packet %lu to %u\n",
				       g_npkts, fd);
		}
		pkb_free(p);
	}

	if (rv < 0)
		errsys("Error reading from fd 0\n");

	return 0;
}
