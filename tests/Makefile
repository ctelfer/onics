
tests:
	cd src ; make
	./vm_test.sh
	bin/testns
	./pp_test.sh
	./pml_lex_test.sh
	./pml_parse_test.sh
	./pml_cg_watch.sh

clean:
	cd src ; make clean
	rm -f tmp/*
