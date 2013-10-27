
all:
	cd src && ./configure && make
	cd doc && make
	cd tests && make

install:
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	cd src && ./configure && make install && \
	cd ../scripts && make install && \
	cd ../doc && make install )

uninstall:
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	cd src && make uninstall && \
	cd ../scripts && make uninstall && \
	cd ../doc && make uninstall )

clean:
	cd src && make clean
	cd doc && make clean
	cd tests && make clean
