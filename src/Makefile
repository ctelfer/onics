# Makefile for the paptools
CC=gcc
OPTS=-O3 
CATLIB_ROOT=../../catlib
INCS=-I${CATLIB_ROOT}/include
LIBS=-L${CATLIB_ROOT}/lib -lcat -lpcap
DEFS=
BINDIR=../bin

TARGETS=${BINDIR}/pcapin \
	${BINDIR}/pcapout

all: ${TARGETS}

../bin/pcapin: pcapin.o packet.o
	${CC} -o ../bin/pcapin pcapin.o packet.o ${DEFS} ${OPTS} \
		${INCS} ${LIBS}

../bin/pcapout: pcapout.o packet.o
	${CC} -o ../bin/pcapout pcapout.o packet.o ${DEFS} ${OPTS} \
		${INCS} ${LIBS}

.c.o:
	${CC} -c $< -o $@ ${DEFS} ${INCS} ${OPTS}


clean:
	rm ${TARGETS}
	rm -f *.o

