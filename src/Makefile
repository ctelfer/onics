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
LIBOBJS= metapkt.o namespace.o ncl.o netvm.o netvm_rt.o pktbuf.o pptcpip.o \
	protoparse.o tokenizer.o util.o

TARGETS=${BINDIR}/pcapin \
	${BINDIR}/pcapout \
	${BINDIR}/ped

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

${BINDIR}/ped: ped.o protoparse.o pptcpip.o util.o pktbuf.o netvm.o netvm_rt.o \
	          metapkt.o netvm.h protoparse.h pktbuf.h metapkt.h netvm_rt.h
	${CC} -o ../bin/ped ped.o pktbuf.o protoparse.o pptcpip.o util.o \
		netvm.o metapkt.o netvm_rt.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

.c.o: $<
	${CC} -Wall -c $< -o $@ ${DEFS} ${INCS} ${OPTS}


clean:
	rm -f ${TARGETS}
	rm -f *.o

