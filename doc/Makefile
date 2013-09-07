# Makefile for ONICS scripts

INSTALL_DIR=/usr/local/share/man/man1

ALL_DOCS= \
	  h2xpkt.1 nft.1 nvmas.1 nvmpf.1 oprotowrap.1 pc2xpkt.1 pcapin.1 \
	  pcapout.1 pcount.1 pdiff.1 pktdemux.1 pktin.1 pktmux.1 pktout.1 \
	  pktrel.1 pml.1 ppick.1 psort.1 rawpkt.1 tcpsess.1 x2hpkt.1 xpkt2pc.1 

WRAP_DOCS=ethwrap.1 ipwrap.1 ip6wrap.1 icmpwrap.1 icmp6wrap.1 tcpwrap.1 \
	  udpwrap.1

all:

install: $(ALL_DOCS)
	@for p in $(ALL_DOCS) ; do \
		echo Installing $$p to $(INSTALL_DIR) ; \
		cp $$p $(INSTALL_DIR) ; \
		chmod 644 $(INSTALL_DIR)/$$p ; \
	done
	@for p in $(WRAP_DOCS) ; do \
		echo Linking $$p to oprotowrap.1 ; \
		ln -s $(INSTALL_DIR)/oprotowrap.1 $(INSTALL_DIR)/$$p ; \
	done 

uninstall:
	@for p in $(WRAP_DOCS) $(ALL_DOCS) ; do \
		echo Removing $(INSTALL_DIR)/$$p ; \
		rm -f $(INSTALL_DIR)/$$p ; \
	done 

