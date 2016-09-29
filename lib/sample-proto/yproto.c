#include <stdlib.h> /* malloc/free */
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h> /* ntohs */
#include <errno.h>
#include <prlib.h>
#include <prid.h>
#include <protoparse.h>
#include <ns.h>
#include <util.h>

#define YPETYPE 0x9999
#define YPPRID  PRID_BUILD(PRID_PF_USER_FIRST, 0)

struct proto_parser_ops yproto_ops;
struct prparse_ops yproto_parse_ops;

struct yphdr {
	uint16_t tag;	/* arbitrary */
	uint16_t len;   /* length of payload */
	uint16_t etype; /* ethertype of next header */
	uint16_t csum;	/* xor of header bytes */
};

#define YPHLEN 8


static void yproto_update(struct prparse *prp, byte_t *buf)
{
	struct yphdr *yph;
	uint16_t len;

	prp->error = 0;
	if (prp_totlen(prp) < YPHLEN) {
		prp->error |= PRP_ERR_TOOSMALL;
		return;
	}
	prp_poff(prp) = prp_soff(prp) + YPHLEN;
	prp_toff(prp) = prp_eoff(prp);

	yph = prp_header(prp, buf, struct yphdr);
	if (yph->tag ^ yph->len ^ yph->etype ^ yph->csum)
		prp->error |= PRP_ERR_CKSUM;
	len = ntohs(yph->len);
	if (len != prp_plen(prp)) {
		if (prp_plen(prp) < len)
			prp->error |= PRP_ERR_TRUNC;
		else
			prp->error |= PRP_ERR_INVALID;
	}
}


static int yproto_fixnxt(struct prparse *prp, byte_t *buf)
{
	struct yphdr *yph = prp_header(prp, buf, struct yphdr);
	struct prparse *next;
	next = prp_next_in_region(prp, prp);
	if (next != NULL) {
		yph->etype = htons(pridtoetype(next->prid));
		if (yph->etype == 0)
			return -1;
	}
	return 0;
}


static struct prparse *yproto_copy(struct prparse *oprp)
{
	struct prparse *prp;
       	prp = calloc(sizeof(struct prparse), 1);
	if (prp == NULL)
		return NULL;
	memcpy(prp, oprp, sizeof(*prp));
	return prp;
}


int yproto_fixlen(struct prparse *prp, byte_t *buf)
{
	struct yphdr *yph = prp_header(prp, buf, struct yphdr);
	yph->len = htons(prp_plen(prp));
	return 0;
}


int yproto_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct yphdr *yph = prp_header(prp, buf, struct yphdr);
	yph->csum = yph->tag ^ yph->len ^ yph->etype;
	return 0;
}


void yproto_free(struct prparse *prp)
{
	free(prp);
}


struct prparse_ops yproto_parse_ops = {
	yproto_update,
	yproto_fixnxt,
	yproto_fixlen,
	yproto_fixcksum,
	yproto_copy,
	yproto_free,
};


static struct prparse *newypprp(struct prparse *reg, ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = calloc(sizeof(struct prparse), 1);
	if (prp == NULL)
		return NULL;
	prp_init_parse(prp, YPPRID, off, 0, maxlen, 0, &yproto_parse_ops,
		       reg, 0);
	return prp;
}

static struct prparse *yproto_parse(struct prparse *reg, byte_t *buf,
				    ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newypprp(reg, off, maxlen);
	if (prp != NULL)
		yproto_update(prp, buf);
	return prp;
}

int yproto_nxtcld(struct prparse *reg, byte_t *buf, struct prparse *cld,
		  uint *prid, ulong *off, ulong *maxlen)
{
	struct yphdr *yph = (struct yphdr *)(buf + prp_soff(reg));
	if (cld != NULL)
		return 0;
	*prid = etypetoprid(ntohs(yph->etype));
	if (*prid == 0)
		return 0;
	*off = prp_poff(reg);
	*maxlen = prp_plen(reg);
	return 1;
}


static int yproto_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, YPPRID, YPHLEN, 0, enclose);
}


static int yproto_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		      int enclose)
{
	struct prparse *prp;
	struct prparse *cld;
	struct yphdr *yph;

	if (ps->hlen != YPHLEN) {
		errno = EINVAL;
		return -1;
	}
	prp = newypprp(reg, ps->off, ps->plen + ps->hlen);
	if (prp == NULL)
		return -1;
	prp_poff(prp) = prp_soff(prp) + ps->hlen;
	prp_add_insert(reg, prp, enclose);
	if (buf) {
		yph = prp_header(prp, buf, struct yphdr);
		memset(yph, 0, sizeof(yph));
		yph->tag = htons(0xdead);
		yph->len = htons(prp_plen(prp));
		cld = prp_next_in_region(prp, prp);
		if (cld != NULL)
			yph->etype = htons(pridtoetype(cld->prid));
		else
			yph->etype = 0;
		yph->csum = yph->tag ^ yph->len ^ yph->etype;
	}

	return 0;
}


struct proto_parser_ops yproto_ops = { 
	yproto_parse,
	yproto_nxtcld,
	yproto_getspec,
	yproto_add
};



#define ALEN(arr) (sizeof(arr) / sizeof(arr[0]))
extern struct ns_elem *yproto_ns_elems[4];
struct ns_namespace yproto_ns =
	NS_NAMESPACE_I("yproto", NULL, YPPRID, PRID_PCLASS_TUNNEL,
		       "YetAnotherProto", NULL, yproto_ns_elems,
		       ALEN(yproto_ns_elems));
struct ns_pktfld yproto_ns_tag =
	NS_BYTEFIELD_I("tag", &yproto_ns, YPPRID, 0, 2, "Tag", &ns_fmt_hex);
struct ns_pktfld yproto_ns_len =
	NS_BYTEFIELD_I("len", &yproto_ns, YPPRID, 2, 2, "Length", &ns_fmt_dec);
struct ns_pktfld yproto_ns_etype =
	NS_BYTEFIELD_I("etype", &yproto_ns, YPPRID, 4, 2, "Ethertype",
		       &ns_fmt_hex);
struct ns_pktfld yproto_ns_csum =
	NS_BYTEFIELD_I("csum", &yproto_ns, YPPRID, 6, 2, "Checksum",
		       &ns_fmt_hex);
struct ns_elem *yproto_ns_elems[] = {
	(struct ns_elem *)&yproto_ns_tag,
	(struct ns_elem *)&yproto_ns_len,
	(struct ns_elem *)&yproto_ns_etype,
	(struct ns_elem *)&yproto_ns_csum
};


BEGIN_EXTERN_PRLIBS_DECL
ETHPROTO("yproto", YPPRID, YPETYPE, yproto_ops, yproto_ns)
END_EXTERN_PRLIBS_DECL
