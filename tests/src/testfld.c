#include "pktbuf.h"
#include "protoparse.h"
#include "ns.h"
#include "fld.h"

int main(int argc, char *argv[])
{
	struct pktbuf *p;
	ulong osyn;
	uchar oeth[6];
	uchar oip[6];
	uchar neth[6] = "\x10\x22\x33\x44\x55\x66";
	uchar nip[4] = "\x0b\x0c\x0d\x0e";
	ulong len;
	void *pld;
	
	register_std_proto();
	pkb_init(1);

	while (pkb_file_read(&p, stdin) > 0) {
		if (pkb_parse(p) < 0)
			errsys("Error parsing packet\n");

		if (fld_getbn(p->buf, &p->prp, "eth.src", oeth, 6) < 0)
			fprintf(stderr, "unable to read eth.src\n");
		fprintf(stderr, "old eth src addr\n");
		hexdump(stderr, 0, oeth, 6);

		if (fld_getbn(p->buf, &p->prp, "ip.daddr", oip, 4) < 0)
			fprintf(stderr, "unable to read ip.daddr\n");
		fprintf(stderr, "old ip dest addr\n");
		hexdump(stderr, 0, oip, 4);

		if (fld_getvn(p->buf, &p->prp, "tcp.ack", &osyn) < 0)
			fprintf(stderr, "unable to read tcp.ack\n");
		fprintf(stderr, "old tcp ack flag: %lu\n", (ulong)osyn);
		if (fld_getvn(p->buf, &p->prp, "tcp.syn", &osyn) < 0)
			fprintf(stderr, "unable to read tcp.syn\n");
		fprintf(stderr, "old tcp syn flag: %lu\n", (ulong)osyn);

		if (fld_setbn(p->buf, &p->prp, "eth.src", neth, 6) < 0)
			fprintf(stderr, "unable to set eth.src\n");
		if (fld_setbn(p->buf, &p->prp, "ip.daddr", nip, 4) < 0)
			fprintf(stderr, "unable to set ip.daddr\n");
		if (fld_setvn(p->buf, &p->prp, "tcp.syn", osyn^1) < 0)
			fprintf(stderr, "unable to toggle tcp.syn\n");


		pld = fld_getpldn(p->buf, &p->prp, "tcp", &len);
		if (pld == NULL)
			fprintf(stderr, "unable to get 'tcp' payload\n");
		memmove(pld, "Hello World", (len < 11) ? len : 11);

		/* fixup the network layer to make parse dumping cleaner */
		prp_fix_cksum(p->layers[PKB_LAYER_NET], p->buf);

		pkb_pack(p);
		pkb_file_write(p, stdout);
	}

	return 0;
}
