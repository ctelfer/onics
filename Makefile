
all:
	(cd src ; make)
	(cd tests/src ; make)

clean:
	(cd src ; make clean)
	(cd tests/src ; make clean);
