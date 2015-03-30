/*
 * ONICS
 * Copyright 2012-2015
 * Christopher Adam Telfer
 *
 * opcap.c -- Local libpcap implementation
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

#include <cat/err.h>

#include "opcap.h"
#include "util.h"


struct pcap {
	FILE *			file;
	struct opc_fhdr		fhdr;
	int			swapped;
	int			reader;
};


int opc_open_file_rd(const char *fname, opc_h *h)
{
	int esave;
	FILE *fp;

	if (fname == NULL || h == NULL) {
		errno = EINVAL;
		return -1;
	}

	fp = fopen(fname, "r");
	if (fp == NULL)
		errsys("error opc_open_stream_rd() opening '%s': ", fname);

	if (opc_open_stream_rd(fp, h) < 0) {
		esave = errno;
		fclose(fp);
		errno = esave;
		return -1;
	}

	return 0;
}


int opc_open_stream_rd(FILE *fp, opc_h *h)
{
	struct pcap *pc;
	size_t nr;
	struct opc_fhdr *fh;
	int esave;

	if (fp == NULL || h == NULL) {
		errno = EINVAL;
		return -1;
	}

	pc = calloc(sizeof(*pc), 1);
	if (pc == NULL)
		return -1;

	pc->reader = 1;
	pc->file = fp;

	fh = &pc->fhdr;
	nr = fread(fh, OPC_FHSIZE, 1, pc->file);
	if (nr < 1) {
		if (!ferror(pc->file))
			errno = EIO;
		goto errfree;
	}
	
	if (fh->magic == OPC_MAGIC_SWAP) {
		pc->swapped = 1;
		fh->magic = swap32(fh->magic);
		fh->major = swap16(fh->major);
		fh->minor = swap16(fh->minor);
		fh->tz = (int32_t)swap32((uint32_t)fh->tz);
		fh->tssig = swap32(fh->tssig);
		fh->snaplen = swap32(fh->snaplen);
		fh->dltype = swap32(fh->dltype);
	} else if (fh->magic != OPC_MAGIC) {
		errno = EIO;
		goto errfree;
	}

	*h = (opc_h)pc;
	return 0;

errfree:
	esave = errno;
	free(pc);
	errno = esave;
	return -1;

}


int opc_read(opc_h h, void *bp, size_t maxlen, struct opc_phdr *ph)
{
	struct pcap *pc;
	size_t nr, rem;
	byte_t buf[256];

	if ((h == NULL) || (maxlen > 0 && bp == NULL) || (ph == NULL)) {
		errno = EINVAL;
		return -1;
	}

	pc = (struct pcap *)h;
	if (!pc->reader) {
		errno = EINVAL;
		return -1;
	}

	nr = fread(ph, OPC_PHSIZE, 1, pc->file);
	if (nr < 1) {
		if (feof(pc->file))
			return 0;
		if (!ferror(pc->file))
			errno = EIO;
		return -1;
	}

	if (pc->swapped) {
		ph->tssec = swap32(ph->tssec);
		ph->tsusec = swap32(ph->tsusec);
		ph->len = swap32(ph->len);
		ph->caplen = swap32(ph->caplen);
	}

	if (ph->caplen <= maxlen) {
		nr = fread(bp, 1, ph->caplen, pc->file);
		if (nr < ph->caplen) {
			errno = EIO;
			return -1;
		}
	} else {
		if (maxlen > 0) {
			nr = fread(bp, 1, maxlen, pc->file);
			if (nr < maxlen) {
				errno = EIO;
				return -1;
			}
		}

		rem = ph->caplen - maxlen;
		while (rem > sizeof(buf)) {
			nr = fread(bp, 1, sizeof(buf), pc->file);
			if (nr < sizeof(buf)) {
				errno = EIO;
				return -1;
			}
			rem -= sizeof(buf);
		}

		nr = fread(bp, 1, rem, pc->file);
		if (nr < rem) {
			errno = EIO;
			return -1;
		}
	}

	return 1;
}


void opc_close(opc_h h)
{
	struct pcap *pc = (struct pcap *)h;
	if (pc->file != NULL)
		fclose(pc->file);
	pc->file = NULL;
	free(pc);
}


int opc_is_reader(opc_h h)
{
	if (h == NULL) {
		errno = EINVAL;
		return -1;
	}
	return ((struct pcap *)h)->reader;
}


uint32_t opc_get_snaplen(opc_h h)
{
	if (h == NULL) {
		errno = EINVAL;
		return (uint32_t)-1;
	}
	return ((struct pcap *)h)->fhdr.snaplen;
}


uint32_t opc_get_dltype(opc_h h)
{
	if (h == NULL) {
		errno = EINVAL;
		return (uint32_t)-1;
	}
	return ((struct pcap *)h)->fhdr.dltype;
}


int opc_open_file_wr(const char *fname, uint32_t snaplen,
		     uint32_t dltype, opc_h *h)
{
	int esave;
	FILE *fp;

	if (fname == NULL || h == NULL) {
		errno = EINVAL;
		return -1;
	}

	fp = fopen(fname, "w");
	if (fp == NULL)
		errsys("opc_open_file_wr() opening '%s': ", fname);

	if (opc_open_stream_wr(fp, snaplen, dltype, h) < 0) {
		esave = errno;
		fclose(fp);
		errno = esave;
		return -1;
	}


	return 0;
}


int opc_open_stream_wr(FILE *fp, uint32_t snaplen,
		       uint32_t dltype, opc_h *h)
{
	struct pcap *pc;
	struct opc_fhdr *fh;
	size_t nw;
	int esave;

	if (fp == NULL || h == NULL) {
		errno = EINVAL;
		return -1;
	}

	pc = calloc(sizeof(*pc), 1);
	if (pc == NULL)
		return -1;

	pc->swapped = 0;
	pc->reader = 0;
	pc->file = fp;

	fh = &pc->fhdr;
	fh->magic = OPC_MAGIC;
	fh->major = 2;
	fh->minor = 4;
	fh->tz = 0;
	fh->tssig = 0;
	fh->snaplen = snaplen;
	fh->dltype = dltype;

	nw = fwrite(fh, OPC_FHSIZE, 1, pc->file);
	if (nw < 1) {
		errno = EIO;
		goto errfree;
	}

	*h = (opc_h)pc;
	return 0;

errfree:
	esave = errno;
	free(pc);
	errno = esave;
	return -1;
}


int opc_write(opc_h h, void *bp, struct opc_phdr *ph)
{
	size_t nw;
	struct pcap *pc;

	if (h == NULL || ph == NULL || (ph->caplen > 0 && bp == NULL)) {
		errno = EINVAL;
		return -1;
	}

	pc = (struct pcap *)h;
	if (pc->reader) {
		errno = EINVAL;
		return -1;
	}

	nw = fwrite(ph, OPC_PHSIZE, 1, pc->file);
	if (nw < 1) {
		if (!ferror(pc->file))
			errno = EIO;
		return -1;
	}

	if (ph->caplen > 0) {
		nw = fwrite(bp, 1, ph->caplen, pc->file);
		if (nw < ph->caplen) {
			if (!ferror(pc->file))
				errno = EIO;
			return -1;
		}
	}

	return 0;
}
