# Makefile for the paptools
CC=gcc
CATLIB_ROOT=../../catlib
INCS=-I${CATLIB_ROOT}/include
#OPTS=-O3 
#LIBS=-L${CATLIB_ROOT}/lib -lcat -lpcap
#DEFS=
# Some of these are gcc-specific.  TODO: remove/group compiler specific flags.
OPTS=-g -Wall -Wno-sign-conversion -Wno-pointer-sign
LIBS=-L${CATLIB_ROOT}/lib -lcat_dbg -lpcap
DEFS=
BINDIR=../bin
LIBOBJS= xpkt.o ns.o netvm.o netvm_rt.o pktbuf.o stdproto.o \
	 protoparse.o util.o lex.pml.o pmltree.o netvm_std_coproc.o \
	 pml.o

TARGETS=${BINDIR}/pcapin \
	${BINDIR}/pcapout \
	${BINDIR}/pktdemux \
	${BINDIR}/pktmux \
	${BINDIR}/pktrel \
	${BINDIR}/x2hpkt

all: ${LIBOBJS} ${TARGETS}

${BINDIR}/pcapin: pcapin.o pktbuf.o xpkt.o protoparse.o
	${CC} -o ../bin/pcapin pcapin.o pktbuf.o xpkt.o protoparse.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pcapout: pcapout.o pktbuf.o xpkt.o protoparse.o
	${CC} -o ../bin/pcapout pcapout.o pktbuf.o xpkt.o protoparse.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktmux: pktmux.o pktbuf.o xpkt.o protoparse.o
	${CC} -o ../bin/pktmux pktmux.o pktbuf.o xpkt.o protoparse.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktdemux: pktdemux.o pktbuf.o xpkt.o protoparse.o
	${CC} -o ../bin/pktdemux pktdemux.o pktbuf.o xpkt.o protoparse.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktrel: pktrel.o pktbuf.o xpkt.o protoparse.o
	${CC} -o ../bin/pktrel pktrel.o pktbuf.o xpkt.o protoparse.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/x2hpkt: x2hpkt.o pktbuf.o xpkt.o protoparse.o stdproto.o util.o ns.o
	${CC} -o ../bin/x2hpkt x2hpkt.o pktbuf.o xpkt.o protoparse.o stdproto.o\
		util.o ns.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/h2xpkt: h2xpkt.o pktbuf.o xpkt.o protoparse.o stdproto.o
	${CC} -o ../bin/h2xpkt h2xpkt.o pktbuf.o xpkt.o protoparse.o stdproto.o\
		${DEFS} ${OPTS} ${INCS} ${LIBS}

.c.o: $<
	${CC} -Wall -c $< -o $@ ${DEFS} ${INCS} ${OPTS}

lex.pml.c: pml.l pml.h pmllex.h
	flex pml.l

pml.c: pml.yl ../lemon/lemon pmllex.h
	../lemon/lemon pml.yl

pml.h: pml.yl ../lemon/lemon
	../lemon/lemon pml.yl

../lemon/lemon: ../lemon/lemon.c
	(cd ../lemon ; make)

clean:
	rm -f ${TARGETS}
	rm -f *.o
	rm -f lex.pml.c pml.c pml.h pml.out

