# Makefile for ONICS scripts

INSTALL_DIR=/usr/local/bin

ALL_SCRIPTS = \
	      ethwrap icmp6wrap icmpwrap ip6wrap ipwrap pcount \
	      peseq ppick pxseq tcpsess tcpwrap udpwrap

all:

install: $(ALL_SCRIPTS)
	cp $(ALL_SCRIPTS) $(INSTALL_DIR)

uninstall:
	for p in $(ALL_SCRIPTS) ; do rm -f $(INSTALL_DIR)/$$p ; done 

