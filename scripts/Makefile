# Makefile for ONICS scripts

ALL_SCRIPTS = \
	      ethwrap icmp6wrap icmpwrap ip6wrap ipwrap pcount \
	      peseq ppick preverse ptail pxseq tcpsess tcpwrap \
	      udpwrap xtsscale

all:

install: $(ALL_SCRIPTS)
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	INSTALL_DIR=$${INSTALL_PREFIX}/bin ; \
	mkdir -p $${INSTALL_DIR} ; \
	cp $(ALL_SCRIPTS) $${INSTALL_DIR} )

uninstall:
	for p in $(ALL_SCRIPTS) ; do rm -f $(INSTALL_DIR)/$$p ; done 

