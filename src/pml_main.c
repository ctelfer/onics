#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cat/err.h>
#include <cat/stdclio.h>
#include <cat/optparse.h>
#include <cat/str.h>
#include <cat/emalloc.h>

#include "prid.h"
#include "pktbuf.h"
#include "protoparse.h"
#include "stdproto.h"
#include "tcpip_hdrs.h"
#include "netvm.h"
#include "netvm_std_coproc.h"
#include "netvm_prog.h"
#include "pmltree.h"
#include "pmlncg.h"


struct clopt options[] = {
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help and exit"),
	CLOPT_INIT(CLOPT_NOARG, 'e', "--ignore-err", "ignore netvm errors"),
	CLOPT_INIT(CLOPT_NOARG, 'v', "--verbose", "increase verbosity"),
	CLOPT_INIT(CLOPT_NOARG, 'q', "--quiet", "decrease verbosity"),
	CLOPT_INIT(CLOPT_NOARG, 's', "--step", "single step the program"),
	CLOPT_INIT(CLOPT_STRING, 'i', "--infile", "input file"),
	CLOPT_INIT(CLOPT_STRING, 'c', "--compile", 
		   "compile to netvm program file"),
};

struct clopt_parser optparser =
	CLOPTPARSER_INIT(options, array_length(options));


uint64_t vm_stack[1024];
int verbosity = 0;
int ignore_errors = 0;
int single_step = 0;
char *progname;
const char *ofname = NULL;
const char *ifname = NULL;


void usage()
{
	char buf[4096];
	fprintf(stderr, "usage: nvmpf [options]\n");
	optparse_print(&optparser, buf, sizeof(buf));
	str_cat(buf, "\n", sizeof(buf));
	fprintf(stderr, "%s\n", buf);
	exit(1);
}


void parse_options(int argc, char *argv[])
{
	struct clopt *opt;
	int rv;
	optparse_reset(&optparser, argc, argv);
	while (!(rv = optparse_next(&optparser, &opt))) {
		if (opt->ch == 'h') {
			usage();
		} else if (opt->ch == 'e') {
			ignore_errors = 1;
	        } else if (opt->ch == 'v') {
			++verbosity;
		} else if (opt->ch == 'q') {
			--verbosity;
		} else if (opt->ch == 'i') {
			ifname = opt->val.str_val;
		} else if (opt->ch == 'c') {
			ofname = opt->val.str_val;
		}
	}
	if (rv != argc - 1)
		usage();
}


void print_vmret(int vmrv, int ec, uint pc, uint64_t rc)
{
	if (vmrv == 0) {
		fprintf(stderr, "VM provided no return value\n");
	} else if (vmrv == 1) {
		fprintf(stderr, "VM returned value %llu\n", (ulonglong)rc);
	} else if (vmrv == -1) {
		fprintf(stderr, "VM returned error @%u: %s\n", pc,
			netvm_estr(ec));
	} else {
		abort_unless(0);
	}
}


static void print_stack(struct netvm *vm)
{
	uint sp;
	fprintf(stderr, "Stack: (BP = %u)\n", vm->bp);
	sp = vm->sp;
	while (sp > 0) {
		--sp;
		fprintf(stderr, "\t%4u: %llu (0x%llx)\n", sp,
		        (ulonglong)vm->stack[sp],
		        (ulonglong)vm->stack[sp]);
	}
}


void run_without_packets(struct netvm_program *prog, int epi, struct netvm *vm)
{
	int vmrv;
	uint64_t rc;

	if (prog->eps[epi] == NVMP_EP_INVALID)
		return;

	if (single_step) {
		if (verbosity > 0)
			fprintf(stderr, "Single stepping program\n");
		if (verbosity > 2)
			fprintf(stderr, "Executing %u\n", vm->pc);

		vmrv = nvmp_exec(prog, epi, vm, 1, &rc);

		if (verbosity > 3)
			print_stack(vm);

		while (vmrv == -2) {
			if (verbosity > 2)
				fprintf(stderr, "Executing %u\n", vm->pc);

			vmrv = nvmp_exec(prog, NVMP_EXEC_CONTINUE, vm, 1, &rc);

			if (verbosity > 3)
				print_stack(vm);
		}
	} else {
		if (verbosity > 0)
			fprintf(stderr, "Running to completion\n");
		vmrv = nvmp_exec(prog, epi, vm, -1, &rc);
	}

	if (verbosity > 0) {
		print_vmret(vmrv, vm->error, vm->pc, rc);
		if (verbosity > 1)
			print_stack(vm);
	}
	if (vmrv < 0 && !ignore_errors) {
		if (verbosity > 0)
			fprintf(stderr, "exiting\n");
		exit(1);
	}
}


static void send_clr_packets(struct netvm *vm, int send)
{
	int i;
	struct pktbuf *p;

	for (i = 0; i < NETVM_MAXPKTS; ++i) {
		p = netvm_clr_pkt(vm, i, 1);
		if (p != NULL) {
			if (send) {
				if (pkb_pack(p) < 0)
					err("Error packing packet for writing");
				if (pkb_file_write(p, stdout) < 0)
					errsys("Error writing out packet");
			}
			pkb_free(p);
		}
	}
}


void run_with_packets(struct netvm_program *prog, struct netvm *vm, int filter)
{
	struct pktbuf *p;
	int npkt = 0;
	int npass = 0;
	int pass, vmrv;
	uint64_t rc;

	if (prog->eps[NVMP_EP_PACKET] == NVMP_EP_INVALID)
		return;

	while (pkb_file_read(&p, stdin) > 0) {
		if (pkb_parse(p) < 0)
			errsys("Error parsing packets");
		++npkt;

		netvm_load_pkt(vm, p, 0);
		if (single_step) {
			if (verbosity > 0)
				fprintf(stderr, "Single stepping program\n");
			if (verbosity > 1)
				fprintf(stderr, "Executing %u\n", vm->pc);

			vmrv = nvmp_exec(prog, NVMP_EP_PACKET, vm, 1, &rc);

			if (verbosity > 3)
				print_stack(vm);

			while (vmrv == -2) {
				if (verbosity > 1)
					fprintf(stderr, "Executing %u\n",
						vm->pc);

				vmrv = nvmp_exec(prog, NVMP_EXEC_CONTINUE, vm,
						 1, &rc);

				if (verbosity > 3)
					print_stack(vm);
			}
		} else {
			if (verbosity > 0)
				fprintf(stderr, "Running to completion\n");
			vmrv = nvmp_exec(prog, NVMP_EP_PACKET, vm, -1, &rc);
		}

		if (vmrv < 0)
			err("VM returned error @%u: %s\n", vm->pc, 
			    netvm_estr(vm->error));

		pass = (vmrv == 1) && rc;
		if (pass)
			++npass;

		if (verbosity > 0) {
			fprintf(stderr, "Packet %5u: ", npkt);
			print_vmret(vmrv, vm->error, vm->pc, rc);
			if (verbosity > 1)
				print_stack(vm);
		}
		if (vmrv < 0 && !ignore_errors) {
			if (verbosity > 0)
				fprintf(stderr, "exiting\n");
			exit(1);
		}

		send_clr_packets(vm, !filter || pass);
	}

	if (verbosity > 1)
		fprintf(stderr, "%u out of %u packets returned 'true'\n", 
			npass, npkt);
}


void parse_pml_program(FILE *f, struct netvm_program *prog)
{
	int tok;
	pml_scanner_t scanner;
	pml_parser_t parser;
	struct pml_ast ast;
	struct pml_lex_val none, extra;
	
	pml_lexv_init(&none);
	if (pmllex_init(&scanner))
		errsys("pmllex_init:");
	pmlset_in(f, scanner);
	pmlset_extra(none, scanner);

	if (!(parser = pml_alloc()))
		errsys("pml_alloc:");
	pml_ast_init(&ast);

	if (verbosity > 0)
		fprintf(stderr, "Starting program parse\n");

	do {
		tok = pmllex(scanner);
		if (tok < 0)
			err("Encountered invalid token on line %d\n",
			    pmlget_lineno(scanner));
		extra = pmlget_extra(scanner);
		if (pml_parse(parser, &ast, tok, extra)) {
			err("parse error on line %d: %s\n",
			    pmlget_lineno(scanner), ast.errbuf);
		}
		pmlset_extra(none, scanner);
	} while (tok > 0);

	if (!ast.done)
		err("Program file is not a complete PML program\n");

	pmllex_destroy(scanner);
	pml_free(parser);

	/* TODO: modify pml_ast_print() to take a file to print to files */

	if (verbosity > 0)
		fprintf(stderr, "done parsing:  optimizing the program\n");

	if (pml_ast_optimize(&ast) < 0)
		err("Error optimizing PML tree: %s\n", ast.errbuf);


	if (pml_to_nvmp(&ast, prog, 0) < 0)
		errsys("Error generating code in pml_to_nvmp:");
}


void run_program(struct netvm *vm, struct netvm_program *prog)
{
	int i;
	int rv;
	uint len;

	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		if (prog->sdescs[i].perms == 0)
			continue;
		len = prog->sdescs[i].len;
		netvm_set_mseg(vm, i, emalloc(len), len, 
			       prog->sdescs[i].perms);
	}

	if ((rv = nvmp_validate(prog, vm)) < 0)
		err("Error validating program: %s\n", netvm_estr(rv));

	nvmp_init_mem(prog, vm);
	run_without_packets(prog, NVMP_EP_START, vm);
	run_with_packets(prog, vm, vm->matchonly);
	run_without_packets(prog, NVMP_EP_END, vm);
}


int main(int argc, char *argv[])
{
	struct netvm vm;
	struct netvm_std_coproc vmcps;
	struct netvm_program prog;
	struct file_emitter fe;
	FILE *f;

	parse_options(argc, argv);

	register_std_proto();
	pkb_init(1);
	file_emitter_init(&fe, stderr);
	netvm_init(&vm, vm_stack, array_length(vm_stack));
	if (init_netvm_std_coproc(&vm, &vmcps) < 0)
		errsys("Error initializing NetVM coprocessors");
	set_outport_emitter(&vmcps.outport, &fe.fe_emitter);


	if (ifname != NULL) {
		if ((f = fopen(ifname , "r")) == NULL)
			errsys("error opening input file:");
	} else {
		f = stdin;
	}

	parse_pml_program(f, &prog);

	run_program(&vm, &prog);
	
	return 0;
}
