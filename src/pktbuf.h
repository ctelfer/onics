#ifndef __pktbuf_h
#define __pktbuf_h

#include <stdio.h>
#include <cat/cat.h>
#include <cat/list.h>
#include "protoparse.h"
#include "dltypes.h"
#include "xpkt.h"

enum {
	PKB_LAYER_DL = 0,
	PKB_LAYER_TUN = 1,
	PKB_LAYER_NET = 2,
	PKB_LAYER_XPORT = 3,
	PKB_LAYER_NUM = 4,
};


#define PKB_F_PACKED	0x1
#define PKB_F_PARSED	0x2

struct pktbuf {
	struct list 	pkb_entry;
	byte_t *	pkb_buf;
	long		pkb_bsize;
	struct xpkt *	pkb_xpkt;
	long		pkb_xsize;
	struct prparse  pkb_prp;
	struct prparse *pkb_layers[PKB_LAYER_NUM];
	long		pkb_xhlen;
	ushort		pkb_flags;
};

/* initialize the packet buffer subsystem */
void pkb_init();

/* Creates a new packet */
struct pktbuf *pkb_create(long bsize);

/* copy an existing packet and all its metadata */
struct pktbuf *pkb_copy(struct pktbuf *old);

/* free a packet buffer */
void pkb_free(struct pktbuf *pkb);

/* Set the offset field in the packet buffer */
long pkb_get_off(struct pktbuf *pkb);

/* Set the offset field in the packet buffer */
long pkb_get_len(struct pktbuf *pkb);

/* Set the offset field in the packet buffer */
uint16_t pkb_get_dltype(struct pktbuf *pkb);

/* Set the offset field in the packet buffer */
/* Cannot be called for a parsed packet. */
void pkb_set_off(struct pktbuf *pkb, long off);

/* Set the offset field in the packet buffer */
/* Cannot be called for a parsed packet. */
void pkb_set_len(struct pktbuf *pkb, long off);

/* Set the offset field in the packet buffer */
void pkb_set_dltype(struct pktbuf *pkb, uint16_t dltype);

/* Get the data pointer for the packet buffer */
void *pkb_data(struct pktbuf *pkb);

/* 
 * Read a packet from a file and allocate the buffer for it 
 *      1 on successful read
 *      0 on EOF
 *     -1 on error
 */
int pkb_file_read(FILE *fp, struct pktbuf **pkb);

/* 
 * Read a packet from a file and allocate the buffer for it 
 *      1 on successful read
 *      0 on EOF
 *     -1 on error
 */
int pkb_fd_read(int fd, struct pktbuf **pkb);

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
int pkb_file_write(FILE *fp, struct pktbuf *pkb);

/* Write a packet buffer to a file descriptor. Returns 0 on success, -1 on error */
int pkb_fd_write(int fd, struct pktbuf *pkb);

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

/* set the data link type for the packet in the metadata */
void pkb_fix_dltype(struct pktbuf *pkb);

/* Push a new protocol parse to the innermost region of the packet */
int  pkb_pushprp(struct pktbuf *pkb, int ptype);

/* Push a new protocol parse to the outermost region of the packet */
int  pkb_wrapprp(struct pktbuf *pkb, int ptype);

/* Remove a protocol parse from the beginning or end of the packet */
void pkb_popprp(struct pktbuf *pkb, int fromfront);

/* Obtain the xpkt for a packet buffer to manipulate the tags.  */
/* This will return NULL if the packet buffer is packed.  */
/* Also, one must NOT modify the xpkt header fields (directly). */
struct xpkt *pkb_get_xkpt(struct pktbuf *pkb);

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

#endif /* __pktbuf_h */
