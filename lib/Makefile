# Makefile for ONICS library scripts

ALL_LIBS=std.pml


all: $(ALL_LIBS)

clean:


install: $(ALL_LIBS)
	@( INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	PROTO_INSTALL_DIR=$${INSTALL_PREFIX}/lib/onics/protocols; \
	echo Creating $${PROTO_INSTALL_DIR} ; \
	mkdir -p $${PROTO_INSTALL_DIR} ; \
	PML_INSTALL_DIR=$${INSTALL_PREFIX}/lib/pml; \
	mkdir -p $${PML_INSTALL_DIR} ; \
	for p in $(ALL_LIBS) ; do \
		echo Installing $$p to $${PML_INSTALL_DIR} ; \
		cp $$p $${PML_INSTALL_DIR} ; \
		chmod 644 $${PML_INSTALL_DIR}/$$p ; \
	done )

uninstall:
	@( INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	PML_INSTALL_DIR=$${INSTALL_PREFIX}/lib/pml; \
	for p in $(ALL_LIBS) ; do \
		echo Removing $${PML_INSTALL_DIR}/$$p ; \
		rm -f $${PML_INSTALL_DIR}/$$p ; \
	done ; \
	echo Removing $${PML_INSTALL_DIR} ; \
	rm -rf $${PML_INSTALL_DIR} ; \
	echo Removing $${INSTALL_PREFIX}/lib/onics ; \
	rm -rf $${INSTALL_PREFIX}/lib/onics )
