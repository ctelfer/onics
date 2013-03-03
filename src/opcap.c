/*
 * ONICS
 * Copyright 2013 
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

#include "opcap.h"
#include "util.h"


struct pcap {
	FILE *			file;
	struct opcap_fhdr	fhdr;
	int			swapped;
	int			reader;
};


static void free_pcap(struct pcap *pc)
{
	abort_unless(pc);
	if (pc->file != NULL)
		fclose(pc->file);
	pc->file = NULL;
	free(pc);
}


int opcap_open_reader(const char *fname, opcap_h *h)
{
	struct pcap *pc;
	size_t nr;
	struct opcap_fhdr *fh;
	uint32_t *u32p;
	uint32_t *u16p;
	int esave;

	if (fname == NULL || h == NULL) {
		errno = EINVAL;
		return -1;
	}

	pc = calloc(sizeof(*pc), 1);
	if (pc == NULL)
		return -1;

	pc->reader = 1;

	pc->file = fopen(fname, "r");
	if (pc->file == NULL) {
		goto errfree;
	}

	fh = &pc->fhdr;
	nr = fread(fh, OPCAP_FHSIZE, 1, pc->file);
	if (nr < 1) {
		if (!ferror(pc->file))
			errno = EIO;
		goto errfree;
	}
	
	if (fh->magic == OPCAP_MAGIC_SWAP) {
		pc->swapped = 1;
		fh->magic = swap32(fh->magic);
		fh->major = swap16(fh->major);
		fh->minor = swap16(fh->minor);
		fh->tz = (int32_t)swap32((uint32_t)fh->tz);
		fh->tssig = swap32(fh->tssig);
		fh->snaplen = swap32(fh->snaplen);
		fh->dltype = swap32(fh->dltype);
	} else if (fh->magic != OPCAP_MAGIC) {
		errno = EIO;
		goto errfree;
	}

	*h = (opcap_h)pc;
	return 0;

errfree:
	esave = errno;
	free_pcap(pc);
	errno = esave;
	return -1;

}


int opcap_read(opcap_h h, void *bp, size_t maxlen, struct opcap_phdr *ph)
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

	nr = fread(ph, OPCAP_PHSIZE, 1, pc->file);
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

	if (ph->caplen >= maxlen) {
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

	return 0;
}


void opcap_close(opcap_h h)
{
	struct pcap *pc = (struct pcap *)h;
	free_pcap(pc);
}


int opcap_is_reader(opcap_h h)
{
	if (h == NULL) {
		errno = EINVAL;
		return -1;
	}
	return ((struct pcap *)h)->reader;
}


uint32_t opcap_get_snaplen(opcap_h h)
{
	if (h == NULL) {
		errno = EINVAL;
		return (uint32_t)-1;
	}
	return ((struct pcap *)h)->fhdr.snaplen;
}


uint32_t opcap_get_dltype(opcap_h h)
{
	if (h == NULL) {
		errno = EINVAL;
		return (uint32_t)-1;
	}
	return ((struct pcap *)h)->fhdr.dltype;
}


int opcap_open_writer(const char *fname, uint32_t snaplen,
		      uint32_t dltype, opcap_h *h)
{
	struct pcap *pc;
	struct opcap_fhdr *fh;
	size_t nw;
	int esave;

	if (fname == NULL || h == NULL) {
		errno = EINVAL;
		return -1;
	}

	pc = calloc(sizeof(pc), 1);
	if (pc == NULL)
		return -1;

	pc->swapped = 0;
	pc->reader = 0;

	pc->file = fopen(fname, "w");
	if (pc->file == NULL)
		goto errfree;

	fh = &pc->fhdr;
	fh->magic = OPCAP_MAGIC;
	fh->major = 2;
	fh->minor = 4;
	fh->tz = 0;
	fh->tssig = 0;
	fh->snaplen = snaplen;
	fh->dltype = dltype;

	nw = fwrite(fh, OPCAP_FHSIZE, 1, pc->file);
	if (nw < 1) {
		errno = EIO;
		goto errfree;
	}

	*h = (opcap_h)pc;
	return 0;

errfree:
	esave = errno;
	free_pcap(pc);
	errno = esave;
	return -1;
}


int opcap_write(opcap_h h, void *bp, struct opcap_phdr *ph)
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

	nw = fwrite(ph, OPCAP_PHSIZE, 1, pc->file);
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
