COMMON_TARGETS= \
	${BINDIR}/rawpkt \
	${BINDIR}/pktdemux \
	${BINDIR}/pktmux \
	${BINDIR}/pktrel \
	${BINDIR}/x2hpkt \
	${BINDIR}/h2xpkt \
	${BINDIR}/nvmas \
	${BINDIR}/nvmpf \
	${BINDIR}/pml \
	${BINDIR}/pc2xpkt\
	${BINDIR}/xpkt2pc\
	${BINDIR}/pdiff \
	${BINDIR}/nft \
	${BINDIR}/pmerge \
	${BINDIR}/psort \
	${BINDIR}/psplit \
	${BINDIR}/ipfrag \
	${BINDIR}/ipreasm


PCAP_TARGETS= \
	${BINDIR}/pcapin \
	${BINDIR}/pcapout

PLATFORM_TARGETS= \
	${BINDIR}/pktin \
	${BINDIR}/pktout

TARGETS=${COMMON_TARGETS} ${PCAP_TARGETS} ${PLATFORM_TARGETS}
all: makefile

makefile: makefile.tmpl
	@echo "makefile not found:  run ./configure" >&2

clean:
	rm -f ${TARGETS}
	rm -f *.o
	rm -f lex.pml.c pml.c pml.h pml.out pml_tok_strs.c
	rm -f ../lemon/lemon

veryclean: clean
	rm -f makefile
	rm -f .has_pcap
	rm -f pktin.c pktout.c
	rm -f pcapin-tgt.c pcapout-tgt.c
	rm -f onics_config.h
	@echo "makefile destroyed: will be rebuilt next time"
