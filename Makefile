
all:
	(cd src ; make)
	(cd tests ; make)

clean:
	(cd src ; make clean)
	(cd tests ; make clean);
