# Makefile for ONICS
CC=gcc
CATLIB_ROOT=../../catlib
INCS=-I${CATLIB_ROOT}/include
#OPTS=-O3
#LIBS=-L${CATLIB_ROOT}/lib -lcat
#DEFS=
OPTS=-g
LIBS=-L${CATLIB_ROOT}/lib -lcat_dbg
DEFS=
BINDIR=../bin
LIBOBJS= xpkt.o ns.o netvm.o netvm_prog.o pktbuf.o stdproto.o \
	 protoparse.o util.o pmltree.o netvm_std_coproc.o \
	 pmllex.o pml.o pmlncg.o pml_tok_strs.o fld.o

COMMON_TARGETS= \
	${BINDIR}/rawpkt \
	${BINDIR}/pktdemux \
	${BINDIR}/pktmux \
	${BINDIR}/pktrel \
	${BINDIR}/x2hpkt \
	${BINDIR}/h2xpkt \
	${BINDIR}/nvmas \
	${BINDIR}/nvmpf \
	${BINDIR}/pml

PCAP_TARGETS= \
	${BINDIR}/pcapin \
	${BINDIR}/pcapout

PLATFORM_TARGETS= \
	${BINDIR}/pktin \
	${BINDIR}/pktout

TARGETS=${COMMON_TARGETS} ${PCAP_TARGETS} ${PLATFORM_TARGETS}

all: ${LIBOBJS} ${COMMON_TARGETS}

pcap: ${LIBOBJS} ${PCAP_TARGETS}

platform: ${LIBOBJS} ${PLATFORM_TARGETS}


cfglinux: pktin-linux.c pktout-linux.c
	[ -h pktin.c ] || ln -s pktin-linux.c pktin.c
	[ -h pktout.c ] || ln -s pktout-linux.c pktout.c


${BINDIR}/pktin: pktin.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/pktin pktin.o pktbuf.o xpkt.o protoparse.o \
		ns.o util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktout: pktout.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/pktout pktout.o pktbuf.o xpkt.o protoparse.o \
		ns.o util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pcapin: pcapin.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/pcapin pcapin.o pktbuf.o xpkt.o protoparse.o ns.o \
		util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS} -lpcap

${BINDIR}/pcapout: pcapout.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/pcapout pcapout.o pktbuf.o xpkt.o protoparse.o ns.o \
		util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS} -lpcap

${BINDIR}/rawpkt: rawpkt.c pktbuf.o xpkt.o protoparse.o ns.o util.o 
	${CC} -o ${BINDIR}/rawpkt rawpkt.c pktbuf.o xpkt.o protoparse.o ns.o \
		util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktmux: pktmux.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/pktmux pktmux.o pktbuf.o xpkt.o protoparse.o ns.o \
		util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktdemux: pktdemux.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/pktdemux pktdemux.o pktbuf.o xpkt.o protoparse.o ns.o \
		util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktrel: pktrel.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/pktrel pktrel.o pktbuf.o xpkt.o protoparse.o ns.o \
		util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/x2hpkt: x2hpkt.o pktbuf.o xpkt.o protoparse.o stdproto.o util.o ns.o
	${CC} -o ${BINDIR}/x2hpkt x2hpkt.o pktbuf.o xpkt.o protoparse.o \
		stdproto.o util.o ns.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/h2xpkt: h2xpkt.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/h2xpkt h2xpkt.o pktbuf.o xpkt.o protoparse.o \
		stdproto.o ns.o util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/nvmas: nvmas.o netvm.o netvm_prog.o pktbuf.o protoparse.o xpkt.o \
		 ns.o util.o
	${CC} -o ${BINDIR}/nvmas nvmas.o netvm_prog.o netvm.o pktbuf.o ns.o \
		protoparse.o xpkt.o util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/nvmpf: protoparse.o stdproto.o util.o pktbuf.o netvm.o xpkt.o \
		 netvm_std_coproc.o netvm_prog.o ns.o nvmpf.c \
	         netvm.h protoparse.h pktbuf.h xpkt.h netvm_prog.h
	${CC} -o ${BINDIR}/nvmpf nvmpf.c protoparse.o stdproto.o util.o \
	         pktbuf.o netvm.o xpkt.o netvm_std_coproc.o netvm_prog.o ns.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pml:   pml_main.c protoparse.o stdproto.o util.o pktbuf.o netvm.o \
		 xpkt.o netvm_std_coproc.o netvm_prog.o ns.o \
		 pmllex.o pml.o pmltree.o pmlncg.o \
	         netvm.h protoparse.h pktbuf.h xpkt.h netvm_prog.h \
		 pmlncg.h netvm_prog.h pmltree.h
	${CC} -o ${BINDIR}/pml pml_main.c protoparse.o stdproto.o util.o \
	         pktbuf.o netvm.o xpkt.o netvm_std_coproc.o netvm_prog.o ns.o \
		 pmllex.o pml.o pmltree.o pmlncg.o \
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

