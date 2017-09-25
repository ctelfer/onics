/*
 * ONICS
 * Copyright 2012-2015
 * Christopher Adam Telfer
 *
 * pktbuf.h -- Interface for ONICS packet buffers.
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
#ifndef __pktbuf_h
#define __pktbuf_h

#include <stdio.h>
#include <cat/cat.h>
#include <cat/list.h>
#include "protoparse.h"
#include "xpkt.h"

enum {
	PKB_LAYER_DL = 0,
	PKB_LAYER_TUN = 1,
	PKB_LAYER_NET = 2,
	PKB_LAYER_XPORT = 3,
	PKB_LAYER_NUM = 4,
};


#define PKB_MAX_PKTLEN  (65536 + 256)
#define PKB_F_PACKED	0x1
#define PKB_F_PARSED	0x2
#define PKB_F_RESET_MASK	((ushort)~(PKB_F_PACKED|PKB_F_PARSED))

#define PKB_CB_SIZE	64

struct pktbuf;

typedef struct pktbuf *(*pkb_alloc_f)(void *ctx, size_t xlen, size_t plen);
typedef void (*pkb_free_f)(void *ctx, struct pktbuf *pkb);

struct pktbuf {
	struct list 	entry;
	pkb_free_f	free;
	void *		fctx;
	byte_t *	buf;
	ulong		bufsize;
	struct xpkt *	xpkt;
	ulong		xsize;
	ulong		xhlen;	/* cached when packed */
	struct prparse  prp;
	struct prparse *layers[PKB_LAYER_NUM];
	uint		flags;
	byte_t		cb[PKB_CB_SIZE]; /* app can put what it wants here */
};


/* initialize the packet buffer subsystem */
void pkb_init_pools(uint num_expected);

/* Release memory in packet buffer pools */
void pkb_free_pools(void);

/* Initializes a packet */
void pkb_init(struct pktbuf *pkb, void *buf, ulong bsize,
	      void *xbuf, ulong xbsize);

/* Creates a new packet */
struct pktbuf *pkb_create(ulong bsize);

/* Resets a packet buffer to initialized state */
void pkb_reset(struct pktbuf *pkb);

/* copy an existing packet and all its metadata */
struct pktbuf *pkb_copy(struct pktbuf *old);

/* free a packet buffer */
void pkb_free(struct pktbuf *pkb);

/* Get the offset field in the packet buffer */
ulong pkb_get_off(struct pktbuf *pkb);

/* Get the length field in the packet buffer */
ulong pkb_get_len(struct pktbuf *pkb);

/* get the protocol ID identifying the outermost protocol of the packet */
uint16_t pkb_get_dltype(struct pktbuf *pkb);

/* Get the total size of the buffer */
ulong pkb_get_bufsize(struct pktbuf *pkb);

/* Set the offset field in the packet buffer */
/* Cannot be called for a parsed packet. */
void pkb_set_off(struct pktbuf *pkb, ulong off);

/* Set the offset field in the packet buffer */
/* Cannot be called for a parsed packet. */
void pkb_set_len(struct pktbuf *pkb, ulong len);

/* Set the offset field in the packet buffer */
/* Cannot be called for a packed packet. */
void pkb_set_dltype(struct pktbuf *pkb, uint16_t dltype);

/* Get a pointer to the start of packet data (including starting offset) */
void *pkb_data(struct pktbuf *pkb);

/* 
 * Read a packet from a file into a packet buffer
 *      1 on successful read
 *      0 on EOF
 *     -1 on error
 */
int pkb_file_read(struct pktbuf *pkb, FILE *fp);

/* 
 * Read a packet from a file descriptor into a packet buffer
 *      1 on successful read
 *      0 on EOF
 *     -1 on error
 */
int pkb_fd_read(struct pktbuf *pkb, int fd);

/* 
 * Read a packet from a file and allocate the buffer for it 
 *      1 on successful read
 *      0 on EOF
 *     -1 on error
 */
int pkb_file_read_a(struct pktbuf **pkb, FILE *fp, pkb_alloc_f alloc,
		    void *ctx);

/* 
 * Read a packet from a file and allocate the buffer for it 
 *      1 on successful read
 *      0 on EOF
 *     -1 on error
 */
int pkb_fd_read_a(struct pktbuf **pkb, int fd, pkb_alloc_f alloc, void *ctx);

/* 
 * Pack a pktbuf in preparation for transmission 
 * Returns 
 *    0 on success
 *   -1 if the packet is too big to send
 *   -2 if the xpkt headers are invalid
 */
int pkb_pack(struct pktbuf *pkb);

/* Unpack a pktbuf.  Only validated buffers are packed.  So there should */
/* Be no reason to re-validate */
void pkb_unpack(struct pktbuf *pkb);

/* return whether a packet buffer is packed or not */
int pkb_is_packed(struct pktbuf *pkb);

/* Write a packet buffer to a file. Returns 0 on success, -1 on error */
int pkb_file_write(struct pktbuf *pkb, FILE *fp);

/* Write a packet buffer to a file descriptor. Returns 0 on success, -1 on error */
int pkb_fd_write(struct pktbuf *pkb, int fd);

/* Perform protocol parsing for the packet */
int pkb_parse(struct pktbuf *pkb);

/* Clear the protocol parses for the packet */
void pkb_clear_parse(struct pktbuf *pkb);

/* return whether a packet buffer is packed or not */
int pkb_is_parsed(struct pktbuf *pkb);

/* Set a layer to a protocol parse.  layer == -1 for auto */
void pkb_set_layer(struct pktbuf *pkb, struct prparse *prp, int layer);

/* Clear a layer pointer */
void pkb_clr_layer(struct pktbuf *pkb, int layer);

/* Set the data link type for the packet in the metadata to the first */
/* PRID of the outermost parse type.  Set to PRID_RAWPKT if none. */
void pkb_fix_dltype(struct pktbuf *pkb);

/* Set the data link type for the packet in the metadata to the first */
/* PRID of the outermost parse type.  Don't change if no outermost parse. */
void pkb_fix_dltype_if_parsed(struct pktbuf *pkb);

/* Insert a PRP into a packet after a PDU automatically inserting room */
/* after pprp.  This will work even if pprp == &pkb->prp.  */
int pkb_insert_pdu(struct pktbuf *pkb, struct prparse *pprp, int prid);

/* Delete a PDU from a packet removing its header and trailer from the */
/* packet in the process. */
int pkb_delete_pdu(struct pktbuf *pkb, struct prparse *prp);

/* Obtain the xpkt for a packet buffer to manipulate the tags.  */
/* This will return NULL if the packet buffer is packed.  */
/* Also, one must NOT modify the xpkt header fields (directly). */
struct xpkt *pkb_get_xpkt(struct pktbuf *pkb);

/* Iterate to the next tag in the packet buffer */
struct xpkt_tag_hdr *pkb_next_tag(struct pktbuf *pkb, struct xpkt_tag_hdr *t);

/* Find a specific tag in the packet buffer */
struct xpkt_tag_hdr *pkb_find_tag(struct pktbuf *pkb, byte_t type, int idx);

/* Find the index of a specific tag in the packet buffer (-1 if not found) */
int pkb_find_tag_idx(struct pktbuf *pkb, struct xpkt_tag_hdr *xth);

/* add a tag to a packet buffer */
int pkb_add_tag(struct pktbuf *pkb, struct xpkt_tag_hdr *xth);

/* remove a tag from a packet buffer */
int pkb_del_tag(struct pktbuf *pkb, byte_t type, int idx);

/* convert a protocol class into a packet buffer layer index */
/* returns -1 if no such index */
int pkb_get_lidx(uint prid);

#endif /* __pktbuf_h */
