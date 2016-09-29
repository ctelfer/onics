# Makefile for yproto protocol library
CC=gcc
ONICS_PATH=../..
CATLIB_PATH=../../../catlib
INCS=-I${ONICS_PATH}/src -I${CATLIB_PATH}/include
#OPTS=-O3 -Wall -Wno-pointer-sign
OPTS=-g -Wall -Wno-pointer-sign
LIBS=
DEFS=

# common objects for packets
OBJS=yproto.o
SRCS=yproto.c
ALL_BINARIES=yproto.so

TARGETS=yproto.so

all: ${TARGETS} ${OBJS}

yproto.o: yproto.c
	$(CC) -fPIC ${OPTS} ${INCS} ${DEFS} -c yproto.c

yproto.so: yproto.o
	$(CC) -shared -fPIC -o yproto.so yproto.o 

clean:
	rm -f ${TARGETS} ${OBJS}

veryclean: clean
