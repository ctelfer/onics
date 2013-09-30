# Makefile for ONICS
CC=gcc
CATLIB_ROOT=../../catlib
INCS=-I${CATLIB_ROOT}/include
#OPTS=-O3 -Wall -Wno-pointer-sign
#LIBS=-L${CATLIB_ROOT}/lib -lcat
#DEFS=
OPTS=-g -Wall -Wno-pointer-sign
LIBS=-L${CATLIB_ROOT}/lib -lcat_dbg
DEFS=
BINDIR=../bin
INSTALL_DIR=/usr/local/bin

# common objects for packets
PKTOBJ= xpkt.o protoparse.o ns.o util.o pktbuf.o
PKTHDR= xpkt.h protoparse.h ns.h util.h pktbuf.h prid.h config.h

# all base object files
LIBOBJS= ${PKTOBJ} stdproto.o netvm.o netvm_prog.o pmltree.o \
	 netvm_std_coproc.o pmllex.o pml.o pmlncg.o pml_tok_strs.o fld.o \
	 opcap.o 

ALL_BINARIES= \
	      rawpkt pktdemux pktmux pktrel x2hpkt h2xpkt \
	      nvmas nvmpf pml pc2xpkt xpkt2pc pdiff nft \
	      pktin pktout pcapin pcapout psort psplit

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
	${BINDIR}/psort \
	${BINDIR}/psplit


PCAP_TARGETS= \
	${BINDIR}/pcapin \
	${BINDIR}/pcapout

PLATFORM_TARGETS= \
	${BINDIR}/pktin \
	${BINDIR}/pktout

TARGETS=${COMMON_TARGETS} ${PCAP_TARGETS} ${PLATFORM_TARGETS}

all: ${LIBOBJS} ${COMMON_TARGETS} ${PLATFORM_TARGETS} ${PCAP_TARGETS}

install: ${COMMON_TARGETS} ${PLATFORM_TARGETS} ${PCAP_TARGETS}
	@for p in $(ALL_BINARIES) ; do \
		echo Installing $$p to $(INSTALL_DIR); \
		cp ../bin/$$p $(INSTALL_DIR) ; \
		chmod 755 $(INSTALL_DIR)/$$p ; \
	done 

uninstall:
	@for p in $(ALL_BINARIES) ; do \
		echo Removing $(INSTALL_DIR)/$$p ; \
		rm -f $(INSTALL_DIR)/$$p ; \
	done 

pcap: ${LIBOBJS} ${PCAP_TARGETS}

platform: ${LIBOBJS} ${PLATFORM_TARGETS}

pktin.c: cfgnone
pktout.c: cfgnone

cfgnone: pktin-none.c pktout-none.c
	@[ -h pktin.c ] || ln -s pktin-none.c pktin.c
	@[ -h pktout.c ] || ln -s pktout-none.c pktout.c

cfglinux: pktin-linux.c pktout-linux.c
	@[ -h pktin.c ] || ln -s pktin-linux.c pktin.c
	@[ -h pktout.c ] || ln -s pktout-linux.c pktout.c

cfgbsd: pktin-bsd.c pktout-bsd.c
	@[ -h pktin.c ] || ln -s pktin-bsd.c pktin.c
	@[ -h pktout.c ] || ln -s pktout-bsd.c pktout.c

pcapin-tgt.c: cfgnopcap
pcapout-tgt.c: cfgnopcap

cfgnopcap: pcapin-none.c pcapout-none.c
	@[ -h pcapin-tgt.c ] || ln -s pcapin-none.c pcapin-tgt.c
	@[ -h pcapout-tgt.c ] || ln -s pcapout-none.c pcapout-tgt.c

cfgpcap: pcapin.c pcapout.c
	@[ -h pcapin-tgt.c ] || ln -s pcapin.c pcapin-tgt.c
	@[ -h pcapout-tgt.c ] || ln -s pcapout.c pcapout-tgt.c


pcapin.o: pcapin-tgt.c
	${CC} -c $< -o $@ ${DEFS} ${INCS} ${OPTS}

pcapout.o: pcapout-tgt.c
	${CC} -c $< -o $@ ${DEFS} ${INCS} ${OPTS}

${BINDIR}/pktin: pktin.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pktin pktin.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktout: pktout.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pktout pktout.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pcapin: pcapin.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pcapin pcapin.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS} -lpcap

${BINDIR}/pcapout: pcapout.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pcapout pcapout.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS} -lpcap

${BINDIR}/rawpkt: rawpkt.o ${PKTOBJ}
	${CC} -o ${BINDIR}/rawpkt rawpkt.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktmux: pktmux.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pktmux pktmux.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktdemux: pktdemux.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pktdemux pktdemux.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktrel: pktrel.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pktrel pktrel.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/x2hpkt: x2hpkt.o stdproto.o fld.o stdproto.h tcpip_hdrs.h \
		  ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/x2hpkt x2hpkt.o ${PKTOBJ} stdproto.o fld.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/h2xpkt: h2xpkt.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/h2xpkt h2xpkt.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/nvmas: nvmas.o netvm.o netvm_prog.o netvm.h netvm_prog.h \
		 ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/nvmas nvmas.o netvm_prog.o netvm.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/nvmpf: nvmpf.o stdproto.o netvm.o netvm_std_coproc.o netvm_prog.o \
	         netvm.h netvm_std_coproc.h netvm_prog.h stdproto.h \
		 tcpip_hdrs.h ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/nvmpf nvmpf.o stdproto.o netvm.o netvm_std_coproc.o \
		netvm_prog.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pml: pml_main.o pmllex.o pml.o pmltree.o pmlncg.o stdproto.o netvm.o \
		netvm_std_coproc.o netvm_prog.o pmllex.h pmltree.h pmlncg.h \
	        netvm.h netvm_prog.h netvm_std_coproc.h stdproto.h \
		tcpip_hdrs.h ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pml pml_main.o pmllex.o pml.o pmltree.o pmlncg.o \
		stdproto.o netvm.o netvm_std_coproc.o netvm_prog.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pc2xpkt: pc2xpkt.o opcap.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pc2xpkt pc2xpkt.o opcap.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/xpkt2pc: xpkt2pc.o opcap.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/xpkt2pc xpkt2pc.o opcap.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pdiff: pdiff.o stdproto.o fld.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/pdiff pdiff.o stdproto.o fld.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/nft: nft.o stdproto.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/nft nft.o stdproto.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/psort: psort.o stdproto.o fld.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/psort psort.o stdproto.o fld.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/psplit: psplit.o ${PKTOBJ} ${PKTHDR}
	${CC} -o ${BINDIR}/psplit psplit.o ${PKTOBJ} \
		${DEFS} ${OPTS} ${INCS} ${LIBS}



.c.o:
	${CC} -c $< -o $@ ${DEFS} ${INCS} ${OPTS}

pmllex.o: pmllex.c pml.h
	${CC} -c pmllex.c -o pmllex.o ${DEFS} ${INCS} ${OPTS}

pml.c pml.h: pml.yl ../lemon/lemon
	../lemon/lemon pml.yl
	touch pml.h

pml_tok_strs.c: pml.h
	echo "const char *pml_tok_strs[] = {" > pml_tok_strs.c
	echo "	\"EOF\"," >> pml_tok_strs.c
	sed -e 's/#.*_/	"/' -e 's/ .*$$/",/' pml.h >> pml_tok_strs.c
	echo "};" >> pml_tok_strs.c

../lemon/lemon: ../lemon/lemon.c
	(cd ../lemon ; make)

clean:
	rm -f ${TARGETS}
	rm -f *.o
	rm -f lex.pml.c pml.c pml.h pml.out pml_tok_strs.c
	rm -f ../lemon/lemon
	rm -f pktin.c pktout.c
	rm -f pcapin-tgt.c pcapout-tgt.c

