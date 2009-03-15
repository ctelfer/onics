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

TARGETS=${BINDIR}/pcapin \
	${BINDIR}/pcapout \
	${BINDIR}/testpp

all: ${TARGETS}

${BINDIR}/pcapin: pcapin.o packet.o
	${CC} -o ../bin/pcapin pcapin.o packet.o ${DEFS} ${OPTS} \
		${INCS} ${LIBS}

${BINDIR}/pcapout: pcapout.o packet.o
	${CC} -o ../bin/pcapout pcapout.o packet.o ${DEFS} ${OPTS} \
		${INCS} ${LIBS}

${BINDIR}/testpp: testpp.o testpp.o protoparse.o pptcpip.o util.o
	${CC} -o ../bin/testpp testpp.o packet.o protoparse.o pptcpip.o util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

.c.o:
	${CC} -c $< -o $@ ${DEFS} ${INCS} ${OPTS}


clean:
	rm -f ${TARGETS}
	rm -f *.o

