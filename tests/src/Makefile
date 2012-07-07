# Makefile for the paptools
CC=gcc
CATLIB_ROOT=../../../catlib
TOOLSRC=../../src
INCS=-I${CATLIB_ROOT}/include -I$(TOOLSRC)
OPTS=-g
LIBS=-L${CATLIB_ROOT}/lib -lcat_dbg
DEFS=
BINDIR=../bin
LIBOBJS= $(TOOLSRC)/xpkt.o $(TOOLSRC)/namespace.o $(TOOLSRC)/ncl.o \
	 $(TOOLSRC)/netvm.o $(TOOLSRC)/netvm_rt.o $(TOOLSRC)/pktbuf.o \
	 $(TOOLSRC)/stdproto.o $(TOOLSRC)/protoparse.o $(TOOLSRC)/tokenizer.o \
	 $(TOOLSRC)/util.o $(TOOLSRC)/netvm_std_coproc.o

TARGETS= \
	${BINDIR}/testpp \
	${BINDIR}/testvm \
	${BINDIR}/testns \
	${BINDIR}/testpmllex \
	${BINDIR}/testpmlparse

all: ${TARGETS}

${BINDIR}/testpp: $(TOOLSRC)/protoparse.o $(TOOLSRC)/stdproto.o \
		  $(TOOLSRC)/util.o  $(TOOLSRC)/pktbuf.o $(TOOLSRC)/xpkt.o \
		  testpp.c
	${CC} -o ../bin/testpp testpp.c $(TOOLSRC)/pktbuf.o \
		$(TOOLSRC)/protoparse.o $(TOOLSRC)/stdproto.o \
		$(TOOLSRC)/util.o $(TOOLSRC)/ns.o $(TOOLSRC)/xpkt.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testvm: $(TOOLSRC)/protoparse.o $(TOOLSRC)/stdproto.o \
	          $(TOOLSRC)/util.o $(TOOLSRC)/pktbuf.o $(TOOLSRC)/netvm.o \
		  $(TOOLSRC)/xpkt.o $(TOOLSRC)/netvm.h $(TOOLSRC)/protoparse.h\
		  $(TOOLSRC)/pktbuf.h $(TOOLSRC)/xpkt.h \
		  $(TOOLSRC)/netvm_std_coproc.o testvm.c
	${CC} -o ../bin/testvm testvm.c $(TOOLSRC)/pktbuf.o \
		$(TOOLSRC)/protoparse.o $(TOOLSRC)/stdproto.o \
		$(TOOLSRC)/util.o $(TOOLSRC)/netvm.o \
		$(TOOLSRC)/xpkt.o $(TOOLSRC)/ns.o $(TOOLSRC)/netvm_std_coproc.o\
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testns: testns.c $(TOOLSRC)/ns.o $(TOOLSRC)/util.o \
		  $(TOOLSRC)/stdproto.o $(TOOLSRC)/protoparse.o testns.c
	${CC} -o ../bin/testns testns.c $(TOOLSRC)/ns.o $(TOOLSRC)/util.o \
		 $(TOOLSRC)/stdproto.o $(TOOLSRC)/protoparse.o \
		 ${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testpmllex: testpmllex.c $(TOOLSRC)/lex.pml.o
	${CC} -o ../bin/testpmllex testpmllex.c $(TOOLSRC)/lex.pml.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

${BINDIR}/testpmlparse: testpmlparse.c $(TOOLSRC)/lex.pml.o $(TOOLSRC)/pml.o \
			$(TOOLSRC)/pmltree.o $(TOOLSRC)/util.o $(TOOLSRC)/ns.o \
			$(TOOLSRC)/stdproto.o $(TOOLSRC)/protoparse.o
	${CC} -o ../bin/testpmlparse testpmlparse.c $(TOOLSRC)/lex.pml.o \
		$(TOOLSRC)/pml.o $(TOOLSRC)/pmltree.o $(TOOLSRC)/util.o \
		$(TOOLSRC)/ns.o $(TOOLSRC)/stdproto.o $(TOOLSRC)/protoparse.o \
		${DEFS} ${OPTS} ${INCS} ${LIBS}

$(TOOLSRC)/lex.pml.o: $(TOOLSRC)/pml.l
	cd $(TOOLSRC) ; make lex.pml.o

${LIBOBJS}:
	cd $(TOOLSRC) ; make


clean:
	rm -f ${TARGETS}
	rm -f *.o

