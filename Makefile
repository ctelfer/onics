
all:
	cd src && ./configure && make
	cd tests ; make

install:
	cd src && ./configure && make install
	cd scripts && make install
	cd doc && make install 

uninstall:
	cd src && make uninstall
	cd scripts && make uninstall
	cd doc && make uninstall 

clean:
	cd src ; make clean
	cd tests ; make clean
