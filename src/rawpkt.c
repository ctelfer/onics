/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * rawpkt.c -- generate a raw packet from standard input or a data file
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
#include <cat/err.h>
#include "pktbuf.h"


int main(int argc, char *argv[])
{
	struct pktbuf *pkb;
	FILE *in = stdin;
	size_t nr;

	if (argc > 1) {
		in = fopen(argv[1], "r");
		if (in == NULL)
			errsys("error opening input file");
	}

	pkb_init(1);
	pkb = pkb_create(PKB_MAX_PKTLEN);
	if (pkb == NULL)
		errsys("error allocating packet buffer");

	pkb_set_dltype(pkb, PRID_RAWPKT);

	nr = fread(pkb_data(pkb), 1, PKB_MAX_PKTLEN, in);
	if (ferror(in))
		errsys("error reading in packet data");

	pkb_set_len(pkb, nr);
	pkb_pack(pkb);

	if (pkb_file_write(pkb, stdout) < 0)
		errsys("unable to write out packet");

	return 0;
}
