# Makefile for the paptools
CC=gcc
CATLIB_ROOT=../../catlib
INCS=-I${CATLIB_ROOT}/include -I../src/
OPTS=-g
LIBS=-L${CATLIB_ROOT}/lib -lcat_dbg -lpcap
DEFS=
BINDIR=../bin
LIBOBJS= ../src/metapkt.o ../src/namespace.o ../src/ncl.o ../src/netvm.o \
	 ../src/netvm_rt.o ../src/pktbuf.o ../src/pptcpip.o ../src/protoparse.o\
	 ../src/tokenizer.o ../src/util.o

TARGETS= ${BINDIR}/testpp \
	${BINDIR}/testvm \
	${BINDIR}/testns \
	${BINDIR}/testnmllex 

all: ${TARGETS}

${BINDIR}/testpp: ../src/protoparse.o ../src/pptcpip.o ../src/util.o \
	../src/pktbuf.o testpp.c
	${CC} -o ../bin/testpp testpp.c ../src/pktbuf.o ../src/protoparse.o \
		../src/pptcpip.o ../src/util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testvm: ../src/protoparse.o ../src/pptcpip.o ../src/util.o \
	../src/pktbuf.o ../src/netvm.o ../src/metapkt.o ../src/netvm.h \
	../src/protoparse.h ../src/pktbuf.h ../src/metapkt.h testvm.c
	${CC} -o ../bin/testvm testvm.c ../src/pktbuf.o ../src/protoparse.o \
		../src/pptcpip.o ../src/util.o ../src/netvm.o ../src/metapkt.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testns: testns.c ../src/namespace.o ../src/util.o testns.c
	${CC} -o ../bin/testns testns.c ../src/namespace.o ../src/util.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testnmllex: testnmllex.c ../src/lex.nml.o
	${CC} -o ../bin/testnmllex testnmllex.c ../src/lex.nml.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

../src/lex.nml.o: ../src/nml.l
	(cd ../src ; make lex.nml.o)

${LIBOBJS}:
	(cd ../src ; make)


clean:
	rm -f ${TARGETS}
	rm -f *.o

