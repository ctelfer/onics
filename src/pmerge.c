/*
 * ONICS
 * Copyright 2016
 * Christopher Adam Telfer
 *
 * pmerge.c -- Merge a set of packet streams
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

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <cat/optparse.h>
#include <cat/err.h>

#include "pktbuf.h"


/* Globals */

#define MAXSTREAMS	256
#define BYTETHRESH	65536


struct pktstream {
	FILE *fp;
	const char *name;
	int eof;
	ulong weight;
	ulong credits;
};


struct pktstream streams[MAXSTREAMS];


enum {
	ROUND_ROBIN,
	PROP_PKTS,
	PROP_BYTES,
};

int mode = ROUND_ROBIN;
int used_stdin = 0;
int nstreams = 0;
int randomize = 0;
int last_stream;
int seeded = 0;
int continuous = 0;
ulong total_weight;
ulong threshold;
long nwritten = 0;
long maxwrite = -1;
const char *progname;
uchar pdata[65536];
uchar xdata[4096];
struct pktbuf pkb;


struct clopt g_options[] = {
	CLOPT_I_NOARG('B', NULL,
		       "Schedule proportional to # of bytes"),
	CLOPT_I_NOARG('c', NULL,
		      "Continuously rewind each file after EOF"),
	CLOPT_I_NOARG('h', NULL, "Print help"),
	CLOPT_I_UINT('n', NULL, "NUM", "Set max number of packets to copy"),
	CLOPT_I_NOARG('P', NULL,
		      "Schedule proportional to # of packets"),
	CLOPT_I_NOARG('r', NULL, "Randomize stream selection"),
	CLOPT_I_NOARG('R', NULL, "Schedule round-robin (default)"),
	CLOPT_I_UINT('s', NULL, "SEED", "Set randomization seed"),
};
struct clopt_parser g_oparse = CLOPTPARSER_INIT_ARR(g_options);



void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&g_oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] FILE [FILE ...]\n%s\n", progname, str);
	exit(1);
}


void read_and_rewind(struct pktstream *ps)
{
	int rv;
	ps->weight = 0;
	while ((rv = pkb_file_read(&pkb, ps->fp)) > 0) {
		if (mode == PROP_PKTS)
			ps->weight += 1;
		else
			ps->weight += pkb_get_len(&pkb);
		pkb_reset(&pkb);
	}
	if (rv < 0)
		errsys("error reading '%s': ", ps->name);
	fseek(ps->fp, 0, SEEK_SET);
}


void open_stream(const char *fn, struct pktstream *ps)
{
	abort_unless(fn && ps);

	ps->name = fn;
	ps->fp = fopen(fn, "r");
	if (ps->fp == NULL)
		errsys("unable to open file '%s': ", fn);
	ps->weight = 1;
	ps->credits = 0;
	if (mode == PROP_PKTS || mode == PROP_BYTES)
		read_and_rewind(ps);
	if (total_weight + ps->weight < total_weight)
		err("overflow in byte/pkt/stream counts");
	total_weight += ps->weight;
}


void init_wrr_params()
{
	int i;
	ulong min;
	ulong quanta;
	double scale;
	struct pktstream *ps;

	switch (mode) {
	case ROUND_ROBIN:
		threshold = 1;
		break;
	case PROP_PKTS:
		/* normalize threshold to minimum stream size in packets */
		min = streams[0].weight;
		for (i = 1; i < nstreams; ++i) {
			ps = &streams[i];
			if (ps->weight > 0 && ps->weight < min)
				min = ps->weight;
		}
		threshold = min;
		break;
	case PROP_BYTES:
		quanta = 512 * nstreams;
		threshold = BYTETHRESH;
		for (i = 0; i < nstreams; ++i) {
			ps = &streams[i];
			scale = (double)ps->weight / total_weight;
			ps->weight = (ulong)(scale * quanta);
			if (ps->weight < 1)
				ps->weight = 1;
			ps->credits = BYTETHRESH;
		}
		break;
	default:
		abort_unless(0);

	}
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;
	
	progname = argv[0];
	optparse_reset(&g_oparse, argc, argv);
	while (!(rv = optparse_next(&g_oparse, &opt))) {
		switch(opt->ch) {
		case 'c':
			continuous = 1;
			break;
		case 'B':
			mode = PROP_BYTES;
			break;
		case 'h':
			usage(NULL);
			break;
		case 'n':
			maxwrite = opt->val.uint_val;
			if (maxwrite < 0)
				err("Number of packets to write too high\n");
		case 'P':
			mode = PROP_PKTS;
			break;
		case 'r':
			randomize = 1;
			break;
		case 'R':
			mode = ROUND_ROBIN;
			break;
		case 's':
			srandom(opt->val.uint_val);
			seeded = 1;
			break;
		}
	}

	if (rv < 0)
		usage(g_oparse.errbuf);
	if (rv > argc - 1)
		usage("Incorrect # of arguments\n");

	while (rv < argc) {
		if (nstreams >= MAXSTREAMS)
			err("Too many streams to merge\n");
		last_stream = nstreams;
		open_stream(argv[rv++], &streams[nstreams++]);
	}

	if (!randomize)
		init_wrr_params();
}


struct pktstream *next_random()
{
	int i;
	if (total_weight == 0)
		return NULL;
	ulong x = (ulong)random() % total_weight; 
	for (i = 0; i < nstreams; ++i) {
		if (x < streams[i].weight)
			return &streams[i];
		else
			x -= streams[i].weight;
	}
	return NULL;
}


struct pktstream *next_wrr()
{
	int i;
	for (i = 0; i < nstreams; ++i) {
		last_stream = last_stream + 1;
		if (last_stream >= nstreams)
			last_stream = 0;
		if (streams[last_stream].credits >= threshold)
			return &streams[last_stream];
	}
	return NULL;
}


int refresh_credits()
{
	int i;
	int all_below = 1;
	int neof;
	struct pktstream *ps;
	while (all_below) {
		neof = 0;
		for (i = 0; i < nstreams; ++i) {
			ps = &streams[i];
			if (ps->eof) {
				++neof;
			} else {
				ps->credits += ps->weight;
				if (ps->credits >= threshold)
					all_below = 0;
			}
		}
		if (neof == nstreams)
			return -1;
	}
	return 0;
}


struct pktstream *next_deterministic()
{
	struct pktstream *ps;
	ps = next_wrr();
	if (ps == NULL) {
		if (refresh_credits() < 0)
			return NULL;
		ps = next_wrr();
	}
	return ps;
}


struct pktstream *next_stream()
{
	if (maxwrite >= 0 && nwritten >= maxwrite)
		return NULL;
	if (randomize) {
		return next_random();
	} else {
		return next_deterministic();
	}
}


void update_credits(struct pktstream *ps, struct pktbuf *p)
{
	if (!randomize) {
		if (mode != PROP_BYTES)
			ps->credits -= threshold;
		else
			ps->credits -= pkb_get_len(&pkb);
	}
}


void copy_next_packet(struct pktstream *ps)
{
	int rv;

	pkb_reset(&pkb);
	rv = pkb_file_read(&pkb, ps->fp);
	if (rv <= 0) {
		if (rv < 0)
			errsys("Error reading from %s: ", ps->name);
		if (continuous) {
			fseek(ps->fp, 0, SEEK_SET);
		} else {
			total_weight -= ps->weight;
			ps->weight = 0;
			ps->credits = 0;
			ps->eof = 1;
		}
	} else {
		++nwritten;
		update_credits(ps, &pkb);
		pkb_pack(&pkb);
		if (pkb_file_write(&pkb, stdout) < 0)
			errsys("Error writing packet %lu: ", nwritten);
	}
}


void close_streams()
{
	int i;
	struct pktstream *ps;
	for (i = 0; i < nstreams; ++i) {
		ps = &streams[i];
		fclose(ps->fp);
		ps->fp = NULL;
		ps->name = NULL;
	}
}


int main(int argc, char *argv[])
{
	struct pktstream *ps;
	struct timeval tv;

	pkb_init(&pkb, pdata, sizeof(pdata), xdata, sizeof(xdata));
	parse_args(argc, argv);
	if (randomize && !seeded) {
		gettimeofday(&tv, NULL);
		srandom(tv.tv_usec);
	}

	while ((ps = next_stream()) != NULL)
		copy_next_packet(ps);

	close_streams();
	return 0;
}
