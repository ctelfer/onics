
all: normal

normal:
	@(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	( [ -f src/makefile ] || \
	  (echo "Run ./configure first" >&2 && exit 1) ) &&\
	echo "Building binaries..." && make -C src && \
	echo "Building libraries ..." && make -C lib && \
	echo "Building documentation..." && make -C doc && \
	echo "Done" )

test: 
	make -C tests 

install:
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	make -C src install &&\
	make -C lib install &&\
	make -C scripts install &&\
	make -C doc install)

uninstall:
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	make -C src uninstall &&\
	make -C lib uninstall &&\
	make -C scripts uninstall &&\
	make -C doc uninstall)

clean:
	make -C src clean
	make -C lib clean
	make -C doc clean
	make -C tests clean

veryclean:
	make -C src veryclean
	make -C lib clean
	make -C doc clean
	make -C tests clean
