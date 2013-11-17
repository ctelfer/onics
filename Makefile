
all:
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	cd src && ./configure && make && \
	cd ../lib && make && \
	cd ../doc && make && \
	cd ../tests && make )

install:
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	cd src && make install && \
	cd ../lib && make install && \
	cd ../scripts && make install && \
	cd ../doc && make install )

uninstall:
	(INSTALL_PREFIX=$${INSTALL_PREFIX:-/usr/local} ; \
	cd src && make uninstall && \
	cd ../lib && make uninstall && \
	cd ../scripts && make uninstall && \
	cd ../doc && make uninstall )

clean:
	cd src && make veryclean
	cd lib && make clean
	cd doc && make clean
	cd tests && make clean
