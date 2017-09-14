
tests:
	cd src ; make
	./vm_test.sh
	bin/testns
	./pp_test.sh
	./fld_test.sh
	./pml_lex_test.sh
	./pml_parse_test.sh
	./pml_cg_watch.sh
	./pml_exec_test.sh
	./seq_test.sh
	./script_test.sh
	./util_test.sh
	@echo All tests passed
	@echo

clean:
	make -C src clean
	rm -fr tmp/*

veryclean: clean
	make -C src veryclean
