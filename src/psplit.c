/*
 * ONICS
 * Copyright 2013-2015
 * Christopher Adam Telfer
 *
 * psplit.c -- Split an XPKT stream into separate files by flow ID.
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
#include <errno.h>
#include <cat/list.h>
#include <cat/splay.h>
#include <cat/optparse.h>
#include <cat/err.h>
#include <cat/str.h>
#include "pktbuf.h"

/*
 * This program tries to be sensible about file managemnet.  It keeps no
 * more than MAXLIVE files open at a time.  To make sure that it can
 * still track more flows than that, it keeps a list of the open files
 * in LRU order.  If there are more than MAXLIVE flows (including
 * packets without any flow ID, which go in a single trace file) then 
 * the application closes the LRU file before opening a new one.  It
 * keeps track of all the flows that it has seen whether the file handle
 * for it is open or not in a splay tree.
 */


#define MAXFNAME 256
#define MAXLIVE	256
#define INVALID_FID (uint64_t)-1
struct flowfile {
	struct stnode	stn;
	struct list	le;
	char 		filename[MAXFNAME];
	FILE *		fp;
	ulong		npkts;
	uint64_t	flowid;
};

#define stn_to_ff(_stnp) container((_stnp), struct flowfile, stn)
#define le_to_ff(_lep) container((_lep), struct flowfile, le)


const char *prefix = "flow.";
const char *suffix = ".xpkt";
FILE *infile;
struct list lrulist;
struct sptree ffdict;
ulong nlive = 0;
int append_mode = 0;
int remove_fid = 0;
const char *progname;

struct clopt options[] = {
	CLOPT_I_NOARG('a', NULL, "Don't warn if flow file exists"),
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_STRING('p', NULL, "PREFIX",
		       "Prefix to use for each file"),
	CLOPT_I_NOARG('r', NULL,
		      "Remove flow ID tag from packet before writing"),
	CLOPT_I_STRING('s', NULL, "SUFFIX",
		       "Suffix to use for each file"),
};
struct clopt_parser oparse =
CLOPTPARSER_INIT(options, array_length(options));


void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] [INFILE]\nOptions:\n%s\n",
		progname, str);
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;
	const char *fn;

	infile = stdin;
	progname = argv[0];

	optparse_reset(&oparse, argc, argv);
	while (!(rv = optparse_next(&oparse, &opt))) {
		switch (opt->ch) {
		case 'a':
			append_mode = 1;
			break;
		case 'h':
			usage(NULL);
			break;
		case 'p':
			prefix = opt->val.str_val;
			break;
		case 'r':
			remove_fid = 1;
			break;
		case 's':
			suffix = opt->val.str_val;
			break;
		}
	}
	if (rv < 0)
		usage(oparse.errbuf);

	if (rv < argc) {
		fn = argv[rv++];
		infile = fopen(fn, "r");
		if (infile == NULL)
			errsys("Error opening file %s: ", fn);
	}
}


int fidcmp(const void *fid1p, const void *fid2p)
{
	uint64_t *fid1 = (uint64_t *)fid1p;
	uint64_t *fid2 = (uint64_t *)fid2p;

	if (*fid1 == *fid2)
		return 0;
	else if (*fid1 < *fid2)
		return -1;
	else
		return 1;
}


static void ffenq(void *ffp, void *lp)
{
	struct flowfile *ff = ffp;
	struct list *list = lp;
	l_rem(&ff->le);
	l_ins(list, &ff->le);
}


static void cleanup()
{
	struct list allff, *le;
	struct flowfile *ff;

	l_init(&allff);
	st_apply(&ffdict, &ffenq, &allff);
	while ((le = l_deq(&allff)) != NULL) {
		ff = le_to_ff(le);
		if (ff->fp != NULL) {
			fclose(ff->fp);
			ff->fp = NULL;
		}
		free(ff);
	}
}


struct flowfile *new_flowfile(uint64_t flowid)
{
	struct flowfile *ff;
	FILE *ckfp;
	int rv;

	/* create a new FF node in the tree */
	ff = calloc(sizeof(struct flowfile), 1);
	if (ff == NULL) {
		cleanup();
		err("out of memory: exiting");
	}
	ff->flowid = flowid;
	ff->fp = NULL;
	ff->npkts = 0;
	if (flowid != INVALID_FID)
		rv = str_fmt(ff->filename, MAXFNAME, "%s%lu%s", prefix, 
			     (ulong)flowid, suffix);
	else
		rv = str_fmt(ff->filename, MAXFNAME, "%snofid%s", prefix,
			     suffix);
	if (rv < 0 || rv >= MAXFNAME) {
		cleanup();
		err("filename too long!");
	}
	st_ninit(&ff->stn, &ff->flowid);
	l_init(&ff->le);
	st_ins(&ffdict, &ff->stn);

	/* if we are not append mode then sanity check that the */
	/* file does not already exist for sanity sake.  */
	if (!append_mode) {
		ckfp = fopen(ff->filename, "r");
		if (ckfp != NULL) {
			cleanup();
			err("File %s already exists! Exiting\n", ff->filename);
		}
	}

	return ff;
}


struct flowfile *find_flowfile(uint64_t flowid)
{
	struct stnode *stn;
	struct flowfile *ff, *ffc;
	struct list *le;
	int esave;

	stn = st_lkup(&ffdict, &flowid);
	if (stn != NULL)
		ff = stn_to_ff(stn);
	else
		ff = new_flowfile(flowid);

	if (ff->fp != NULL) {
		/* already open: move it to the back of the LRU list */
		l_rem(&ff->le);
		l_enq(&lrulist, &ff->le);
	} else {
		/*
		 * if the file is not open then open it for appending
		 * if there are too many open, dequeue the LRU and close 
		 * it before opening a new one.
		 */
		if (nlive >= MAXLIVE) {
			le = l_deq(&lrulist);
			abort_unless(le);
			ffc = le_to_ff(le);
			fclose(ffc->fp);
			ffc->fp = NULL;
			--nlive;
		}

		ff->fp = fopen(ff->filename, "a");
		if (ff->fp == NULL) {
			esave = errno;
			cleanup();
			errno = esave;
			errsys("fopen(\"%s\", \"a\"): ", ff->filename);
		}
		l_enq(&lrulist, &ff->le);
		++nlive;
	}

	return ff;
}


void split_packets()
{
	int rv;
	struct pktbuf *p;
	ulong pn = 0;
	struct xpkt_tag_flowid *xf;
	struct flowfile *ff;
	uint64_t fid;

	while ((rv = pkb_file_read_a(&p, infile, NULL, NULL)) > 0) {
		++pn;

		fid = INVALID_FID;
		xf = (struct xpkt_tag_flowid *)
			pkb_find_tag(p, XPKT_TAG_FLOW, 0);
		if (xf != NULL)
			fid = xf->flowid;
		ff = find_flowfile(fid);

		ff->npkts++;
		if (remove_fid)
			pkb_del_tag(p, XPKT_TAG_FLOW, 0);

		pkb_pack(p);
		if (pkb_file_write(p, ff->fp) < 0)
			errsys("pkb_file_write() of packet %lu: ", pn);
		pkb_free(p);
	}
	if (rv < 0)
		errsys("pkb_file_read_a() of packet %lu: ", pn);
}


int main(int argc, char *argv[])
{
	l_init(&lrulist);
	st_init(&ffdict, &fidcmp);
	pkb_init_pools(1);
	parse_args(argc, argv);
	split_packets();
	cleanup();	/* unnecessary but hygenic */

	return 0;
}
