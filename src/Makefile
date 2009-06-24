# Makefile for the paptools
CC=gcc
CATLIB_ROOT=../../catlib
INCS=-I${CATLIB_ROOT}/include
#OPTS=-O3 
#LIBS=-L${CATLIB_ROOT}/lib -lcat -lpcap
#DEFS=
OPTS=-g
LIBS=-L${CATLIB_ROOT}/lib -lcat_dbg -lpcap
DEFS=
BINDIR=../bin
LIBOBJS= metapkt.o namespace.o netvm.o netvm_rt.o pktbuf.o pptcpip.o \
	protoparse.o util.o lex.pml.o

TARGETS=${BINDIR}/pcapin \
	${BINDIR}/pcapout \
	${BINDIR}/pktdemux \
	${BINDIR}/pktmux \
	${BINDIR}/pktrel

all: ${LIBOBJS} ${TARGETS}

${BINDIR}/pcapin: pcapin.o pktbuf.o
	${CC} -o ../bin/pcapin pcapin.o pktbuf.o ${DEFS} ${OPTS} \
		${INCS} ${LIBS}

${BINDIR}/pcapout: pcapout.o pktbuf.o
	${CC} -o ../bin/pcapout pcapout.o pktbuf.o ${DEFS} ${OPTS} \
		${INCS} ${LIBS}

${BINDIR}/testpp: testpp.o protoparse.o pptcpip.o util.o pktbuf.o
	${CC} -o ../bin/testpp testpp.o pktbuf.o protoparse.o pptcpip.o util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testvm: testvm.o protoparse.o pptcpip.o util.o pktbuf.o netvm.o \
	          metapkt.o netvm.h protoparse.h pktbuf.h metapkt.h
	${CC} -o ../bin/testvm testvm.o pktbuf.o protoparse.o pptcpip.o util.o \
		netvm.o metapkt.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktmux: pktmux.o pktbuf.o
	${CC} -o ../bin/pktmux pktmux.o pktbuf.o  \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktdemux: pktdemux.o pktbuf.o
	${CC} -o ../bin/pktdemux pktdemux.o pktbuf.o  \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/pktrel: pktrel.o pktbuf.o
	${CC} -o ../bin/pktrel pktrel.o pktbuf.o  \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

.c.o: $<
	${CC} -Wall -c $< -o $@ ${DEFS} ${INCS} ${OPTS}

lex.pml.c: pml.l pml.h
	flex pml.l

pml.c: pml.yl ../lemon/lemon
	../lemon/lemon pml.yl

pml.h: pml.yl ../lemon/lemon
	../lemon/lemon pml.yl

../lemon/lemon: ../lemon/lemon.c
	(cd ../lemon ; make)

clean:
	rm -f ${TARGETS}
	rm -f *.o
	rm -f lex.pml.c pml.c pml.h

