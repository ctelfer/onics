# Makefile for ONICS scripts

INSTALL_DIR=/usr/local/share/man/man1

ALL_DOCS= \
	  h2xpkt.1 nft.1 nvmas.1 nvmpf.1 pc2xpkt.1 pcapin.1 pcapout.1 \
	  pdiff.1 pktdemux.1 pktin.1 pktmux.1 pktout.1 pktrel.1 pml.1 \
	  rawpkt.1 x2hpkt.1 xpkt2pc.1 

install: $(ALL_DOCS)
	cp $(ALL_DOCS) $(INSTALL_DIR)

uninstall:
	for p in $(ALL_DOCS) ; do rm -f $(INSTALL_DIR)/$$p ; done 

