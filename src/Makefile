# Makefile for the nettools
CC=gcc
CATLIB_ROOT=../../catlib
INCS=-I${CATLIB_ROOT}/include
#OPTS=-O3 
#LIBS=-L${CATLIB_ROOT}/lib -lcat -lpcap
#DEFS=
# Some of these are gcc-specific.  TODO: remove/group compiler specific flags.
OPTS=-g -Wall -Wno-sign-conversion -Wno-pointer-sign -O3 -fno-strict-aliasing
LIBS=-L${CATLIB_ROOT}/lib -lcat -lpcap
DEFS=
BINDIR=../bin
LIBOBJS= xpkt.o ns.o netvm.o netvm_prog.o pktbuf.o stdproto.o \
	 protoparse.o util.o lex.pml.o pmltree.o netvm_std_coproc.o \
	 pml.o

TARGETS=${BINDIR}/pcapin \
	${BINDIR}/pcapout \
	${BINDIR}/pktdemux \
	${BINDIR}/pktmux \
	${BINDIR}/pktrel \
	${BINDIR}/x2hpkt \
	${BINDIR}/h2xpkt \
	${BINDIR}/nvmas \
	${BINDIR}/nvmpf

all: ${LIBOBJS} ${TARGETS}

${BINDIR}/pcapin: pcapin.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/pcapin pcapin.o pktbuf.o xpkt.o protoparse.o ns.o \
		util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pcapout: pcapout.o pktbuf.o xpkt.o protoparse.o ns.o util.o
	${CC} -o ${BINDIR}/pcapout pcapout.o pktbuf.o xpkt.o protoparse.o ns.o \
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


.c.o: $<
	${CC} -Wall -c $< -o $@ ${DEFS} ${INCS} ${OPTS}

lex.pml.c: pml.l pml.h
	flex pml.l

lex.pml.o: lex.pml.c
	${CC} -Wall -c lex.pml.c -o lex.pml.o -DTHIS_IS_SCANNER \
		${DEFS} ${INCS} ${OPTS}

pml.c pml.h: pml.yl ../lemon/lemon
	../lemon/lemon pml.yl
	touch pml.h

../lemon/lemon: ../lemon/lemon.c
	(cd ../lemon ; make)

clean:
	rm -f ${TARGETS}
	rm -f *.o
	rm -f lex.pml.c pml.c pml.h pml.out

