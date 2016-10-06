# Makefile for yap protocol library
CC=gcc
ONICS_PATH=../..
CATLIB_PATH=../../../catlib
INCS=-I${ONICS_PATH}/src -I${CATLIB_PATH}/include
#OPTS=-O3 -Wall -Wno-pointer-sign
OPTS=-g -Wall -Wno-pointer-sign
LIBS=
DEFS=

# common objects for packets
OBJS=yap.o
SRCS=yap.c
ALL_BINARIES=yap.so

TARGETS=yap.so

all: ${TARGETS} ${OBJS}

yap.o: yap.c
	$(CC) -fPIC ${OPTS} ${INCS} ${DEFS} -c yap.c

yap.so: yap.o
	$(CC) -shared -fPIC -o yap.so yap.o 

clean:
	rm -f ${TARGETS} ${OBJS}

veryclean: clean
