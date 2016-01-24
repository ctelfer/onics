# Makefile for ONICS scripts

ALL_SCRIPTS = \
	      ethwrap gre-decap gre-encap icmp6wrap icmpwrap ip6wrap \
	      ipwrap mkarp mkicmp mkicmp6 mktcp mktcp6 mkudp mkudp6 \
	      pcount peseq pfind phead ppop preverse ptail pxseq \
	      tcpsess tcpwrap udpwrap vxlan-encap vxlan-decap xpktdump \
	      xtsscale

all:

install: $(ALL_SCRIPTS)
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	INSTALL_DIR=$${INSTALL_PREFIX}/bin ; \
	mkdir -p $${INSTALL_DIR} ; \
	cp $(ALL_SCRIPTS) $${INSTALL_DIR} )

uninstall:
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	INSTALL_DIR=$${INSTALL_PREFIX}/bin ; \
	for p in $(ALL_SCRIPTS) ; do \
	echo "Removing $${INSTALL_DIR}/$$p" ; \
	rm -f $${INSTALL_DIR}/$$p ; done)

