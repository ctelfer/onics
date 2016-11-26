# Makefile for the paptools
BINDIR=../bin
TARGETS= \
	$(BINDIR)/testpp \
	$(BINDIR)/testvm \
	$(BINDIR)/testns \
	$(BINDIR)/testpmllex \
	$(BINDIR)/testpmlparse \
	$(BINDIR)/testfld \
	$(BINDIR)/testpkb

all:
	@echo "Run ./configure from the top level directory first"
	@exit 1


clean:
	rm -f $(TARGETS)
	rm -f *.o

veryclean: clean
	rm -f makefile
