# Makefile for ONICS library scripts

ALL_LIBS=mkpkt.pml


all: $(ALL_DOCS)

clean:


install: $(ALL_DOCS)
	@( INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	LIB_INSTALL_DIR=$${INSTALL_PREFIX}/lib/pml; \
	mkdir -p $${LIB_INSTALL_DIR} ; \
	for p in $(ALL_LIBS) ; do \
		echo Installing $$p to $${LIB_INSTALL_DIR} ; \
		cp $$p $${LIB_INSTALL_DIR} ; \
		chmod 644 $${LIB_INSTALL_DIR}/$$p ; \
	done )

uninstall:
	@( INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	LIB_INSTALL_DIR=$${INSTALL_PREFIX}/lib/pml; \
	for p in $(ALL_LIBS) ; do \
		echo Removing $${LIB_INSTALL_DIR}/$$p ; \
		rm -f $${LIB_INSTALL_DIR}/$$p ; \
	done )
