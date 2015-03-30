# Makefile for ONICS scripts

MAN1_DOCS= \
	h2xpkt.1 ipfrag.1 ipreasm.1 nft.1 nvmas.1 nvmpf.1 oprotowrap.1 \
	mkpkt.1 pc2xpkt.1 pcapin.1 pcapout.1 pcount.1 pdiff.1 pktdemux.1 \
	pktin.1 pktmux.1 pktout.1 pktrel.1 pml.1 pgrep.1 preverse.1 psort.1 \
	psplit.1 ptail.1 rawpkt.1 tcpsess.1 x2hpkt.1 xpkt2pc.1 xtsscale.1

OPROTO_WRAP_DOCS= \
	ethwrap.1 ipwrap.1 ip6wrap.1 icmpwrap.1 icmp6wrap.1 tcpwrap.1 \
	udpwrap.1

MKPKT_WRAP_DOCS= \
	mkarp.1 mkicmp.1 mkicmp6.1 mktcp.1 mktcp6.1 mkudp.1 mkudp6.1

MAN7_DOCS= onics.7 onics_proto.7

ALL_DOCS= $(MAN1_DOCS) $(MAN7_DOCS)


all: $(ALL_DOCS)

onics_proto.7: onics_stdproto_list.txt
	cat onics_proto_pre.7 onics_stdproto_list.txt \
	    onics_proto_post.7 > onics_proto.7

onics_stdproto_list.txt: enum_proto
	./enum_proto > onics_stdproto_list.txt

enum_proto: enum_proto.c
	gcc -o enum_proto enum_proto.c ../src/ns.c ../src/stdproto.c \
		../src/util.c ../src/protoparse.c \
		-I../src -I../../catlib/include \
		-L../../catlib/lib -lcat

clean:
	rm -f onics_stdproto_list.txt onics_proto.7 enum_proto


install: $(ALL_DOCS)
	@( INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	MAN1_INSTALL_DIR=$${INSTALL_PREFIX}/man/man1 ; \
	MAN7_INSTALL_DIR=$${INSTALL_PREFIX}/man/man7 ; \
	mkdir -p $${MAN1_INSTALL_DIR} ; \
	for p in $(MAN1_DOCS) ; do \
		echo Installing $$p to $${MAN1_INSTALL_DIR} ; \
		cp $$p $${MAN1_INSTALL_DIR} ; \
		chmod 644 $${MAN1_INSTALL_DIR}/$$p ; \
	done ; \
	for p in $(OPROTO_WRAP_DOCS) ; do \
		echo Linking $$p to oprotowrap.1 ; \
		ln -sf $${MAN1_INSTALL_DIR}/oprotowrap.1 $${MAN1_INSTALL_DIR}/$$p ; \
	done ; \
	for p in $(MKPKT_WRAP_DOCS) ; do \
		echo Linking $$p to mkpkt.1 ; \
		ln -sf $${MAN1_INSTALL_DIR}/mkpkt.1 $${MAN1_INSTALL_DIR}/$$p ; \
	done ; \
	mkdir -p $${MAN7_INSTALL_DIR} ; \
	for p in $(MAN7_DOCS) ; do \
		echo Installing $$p to $${MAN7_INSTALL_DIR} ; \
		cp $$p $${MAN7_INSTALL_DIR} ; \
		chmod 644 $${MAN7_INSTALL_DIR}/$$p ; \
	done )

uninstall:
	@( INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	MAN1_INSTALL_DIR=$${INSTALL_PREFIX}/man/man1 ; \
	MAN7_INSTALL_DIR=$${INSTALL_PREFIX}/man/man7 ; \
	for p in $(OPROTO_WRAP_DOCS) $(MAN1_DOCS) ; do \
		echo Removing $${MAN1_INSTALL_DIR}/$$p ; \
		rm -f $${MAN1_INSTALL_DIR}/$$p ; \
	done ; \
	for p in $(MAN7_DOCS) ; do \
		echo Removing $${MAN7_INSTALL_DIR}/$$p ; \
		rm -f $${MAN7_INSTALL_DIR}/$$p ; \
	done )

