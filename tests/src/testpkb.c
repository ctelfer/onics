#include <string.h>
#include <cat/err.h>
#include <cat/pack.h>
#include <pktbuf.h>
#include <stdproto.h>
#include <tcpip_hdrs.h>

#define EXPECT(_val, _exp) \
	do {					\
		int _v = (_val);		\
		if (_v != (_exp))		\
			err("FAIL: \"%s\" expected %d but got %d\n", \
			    #_val, _exp, _v);	\
	} while (0)


void fix_all(struct pktbuf *pkb)
{
	int i;
	for (i = 0; i < PKB_LAYER_NUM; ++i)
		if (pkb->layers[i] != NULL)
			EXPECT(prp_fix_len(pkb->layers[i], pkb->buf), 0);
	for (i = 0; i < PKB_LAYER_NUM; ++i)
		if (pkb->layers[i] != NULL)
			EXPECT(prp_fix_cksum(pkb->layers[i], pkb->buf), 0);
}

#define DLEN 128
int main(int argc, char *argv[])
{
	struct pktbuf *pkb;
	struct prparse *eprp;
	struct prparse *mprp;
	struct mpls_label *mpls;

	pkb_init_pools(1);
	EXPECT(register_std_proto(), 0);

	/* create the payload */
	pkb = pkb_create(1024);
	pkb_set_len(pkb, DLEN);
	pkb_set_off(pkb, 128);
	memset(pkb_data(pkb), 0xdd, DLEN);

	/* add eth+ip+tcp headers */
	EXPECT(pkb_insert_pdu(pkb, &pkb->prp, PRID_TCP), 0);
	EXPECT(pkb_insert_pdu(pkb, &pkb->prp, PRID_IPV4), 0);
	EXPECT(pkb_insert_pdu(pkb, &pkb->prp, PRID_ETHERNET2), 0);
	pkb_fix_dltype(pkb);
	fix_all(pkb);

	/* write out */
	EXPECT(pkb_pack(pkb), 0);
	EXPECT(pkb_file_write(pkb, stdout), 0);
	fflush(stdout);

	/* insert MPLS label after Ethernet header */
	pkb_unpack(pkb);
	eprp = prp_next(&pkb->prp);
	EXPECT(eprp->prid, PRID_ETHERNET2);
	EXPECT(pkb_insert_pdu(pkb, eprp, PRID_MPLS), 0);

	mprp = prp_next(eprp);
	EXPECT(mprp->prid, PRID_MPLS);
	mpls = prp_header(mprp, pkb->buf, struct mpls_label);
	mpls->label = hton32(
			(ntoh32(mpls->label) & (1 << MPLS_BOS_SHF)) | 
			(1234 << MPLS_LABEL_SHF) | 
			(1 << MPLS_TC_SHF) | 
			(99 << MPLS_TTL_SHF));
	fix_all(pkb);

	/* send out eth+mpls+ip+tcp packet */
	EXPECT(pkb_pack(pkb), 0);
	EXPECT(pkb_file_write(pkb, stdout), 0);
	fflush(stdout);

	/* Delete the MPLS label */
	pkb_unpack(pkb);
	EXPECT(pkb_delete_pdu(pkb, mprp), 0);
	fix_all(pkb);

	/* Send out eth+ip+tcp packet again */
	EXPECT(pkb_pack(pkb), 0);
	EXPECT(pkb_file_write(pkb, stdout), 0);
	fflush(stdout);

	pkb_free(pkb);

	return 0;
}
