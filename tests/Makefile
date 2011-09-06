# Makefile for the paptools
CC=gcc
CATLIB_ROOT=../../catlib
INCS=-I${CATLIB_ROOT}/include -I../src/
OPTS=-g
LIBS=-L${CATLIB_ROOT}/lib -lcat_dbg -lpcap
DEFS=
BINDIR=../bin
LIBOBJS= ../src/xpkt.o ../src/namespace.o ../src/ncl.o ../src/netvm.o \
	 ../src/netvm_rt.o ../src/pktbuf.o ../src/stdproto.o ../src/protoparse.o\
	 ../src/tokenizer.o ../src/util.o ../src/netvm_std_coproc.o

TARGETS= ${BINDIR}/testpp \
	${BINDIR}/testvm \
	${BINDIR}/testns \
	${BINDIR}/testpmllex \
	${BINDIR}/testpmlparse

all: ${TARGETS}

${BINDIR}/testpp: ../src/protoparse.o ../src/stdproto.o ../src/util.o \
	../src/pktbuf.o ../src/xpkt.o testpp.c
	${CC} -o ../bin/testpp testpp.c ../src/pktbuf.o ../src/protoparse.o \
		../src/stdproto.o ../src/util.o ../src/ns.o ../src/xpkt.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testvm: ../src/protoparse.o ../src/stdproto.o ../src/util.o \
	../src/pktbuf.o ../src/netvm.o ../src/xpkt.o ../src/netvm.h \
	../src/protoparse.h ../src/pktbuf.h ../src/xpkt.h \
	../src/netvm_std_coproc.o testvm.c
	${CC} -o ../bin/testvm testvm.c ../src/pktbuf.o ../src/protoparse.o \
		../src/stdproto.o ../src/util.o ../src/netvm.o ../src/xpkt.o \
		../src/ns.o ../src/netvm_std_coproc.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testns: testns.c ../src/ns.o ../src/util.o ../src/stdproto.o \
		  ../src/protoparse.o testns.c
	${CC} -o ../bin/testns testns.c ../src/ns.o ../src/util.o \
		 ../src/stdproto.o ../src/protoparse.o \
		 ${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testpmllex: testpmllex.c ../src/lex.pml.o
	${CC} -o ../bin/testpmllex testpmllex.c ../src/lex.pml.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testpmlparse: testpmlparse.c ../src/lex.pml.o ../src/pml.o \
	../src/pmltree.o ../src/util.o ../src/ns.o
	${CC} -o ../bin/testpmlparse testpmlparse.c ../src/lex.pml.o \
		../src/pml.o ../src/pmltree.o ../src/util.o ../src/ns.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

../src/lex.pml.o: ../src/pml.l
	(cd ../src ; make lex.pml.o)

${LIBOBJS}:
	(cd ../src ; make)


clean:
	rm -f ${TARGETS}
	rm -f *.o

