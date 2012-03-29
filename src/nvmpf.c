#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cat/err.h>
#include <cat/stdclio.h>
#include <cat/optparse.h>
#include <cat/str.h>
#include <cat/emalloc.h>
#include "pktbuf.h"
#include "protoparse.h"
#include "stdproto.h"
#include "tcpip_hdrs.h"
#include "netvm.h"
#include "netvm_std_coproc.h"
#include "netvm_prog.h"


struct clopt options[] = {
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help and exit"),
	CLOPT_INIT(CLOPT_NOARG, 'e', "--ignore-err", "ignore netvm errors"),
	CLOPT_INIT(CLOPT_NOARG, 'v', "--verbose", "increase verbosity"),
	CLOPT_INIT(CLOPT_NOARG, 'q', "--quiet", "decrease verbosity"),
};

struct clopt_parser optparser =
	CLOPTPARSER_INIT(options, array_length(options));


uint64_t vm_stack[1024];
int verbosity = 0;
int ignore_errors = 0;
char *progname;


void usage()
{
	char buf[4096];
	fprintf(stderr, "usage: nvmpf [options] progfile\n");
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
		if (opt->ch == 'h')
			usage();
		else if (opt->ch == 'e')
			ignore_errors = 1;
		else if (opt->ch == 'v')
			++verbosity;
		else if (opt->ch == 'q')
			--verbosity;
	}
	if (rv != argc - 1)
		usage();
	progname = argv[rv];
}


void print_vmret(int vmrv, int ec, uint pc, uint64_t rc)
{
	if (vmrv == 0) {
		fprintf(stderr, "VM provided no return value\n");
	} else if (vmrv == 1) {
		fprintf(stderr, "VM returned value %llu\n", (ulonglong)rc);
	} else if (vmrv == -1) {
		fprintf(stderr, "VM returned error @%u: %s\n", pc, netvm_estr(ec));
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

	if (verbosity > 3) {
		fprintf(stderr, "Executing %u\n", vm->pc);
		vmrv = nvmp_exec(prog, epi, vm, 1, &rc);
		print_stack(vm);
		while (vmrv == -2) {
			fprintf(stderr, "Executing %u\n", vm->pc);
			vmrv = nvmp_exec(prog, NVMP_EXEC_CONTINUE, vm, 1, &rc);
			print_stack(vm);
		}
	} else {
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
		if (verbosity > 3) {
			fprintf(stderr, "Executing %u\n", vm->pc);
			vmrv = nvmp_exec(prog, NVMP_EP_PACKET, vm, 1, &rc);
			print_stack(vm);
			while (vmrv == -2) {
				fprintf(stderr, "Executing %u\n", vm->pc);
				vmrv = nvmp_exec(prog, NVMP_EXEC_CONTINUE, vm, 1, &rc);
				print_stack(vm);
			}
		} else {
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


int main(int argc, char *argv[])
{
	struct netvm vm;
	struct netvm_std_coproc vmcps;
	struct netvm_program prog;
	struct file_emitter fe;
	int rv;
	int i;
	FILE *pf;
	uint len;

	parse_options(argc, argv);

	register_std_proto();
	pkb_init(1);

	file_emitter_init(&fe, stderr);
	netvm_init(&vm, vm_stack, array_length(vm_stack));
	if (init_netvm_std_coproc(&vm, &vmcps) < 0)
		errsys("Error initializing NetVM coprocessors");
	set_outport_emitter(&vmcps.outport, &fe.fe_emitter);

	if ((pf = fopen(progname, "r")) == NULL)
		errsys("fopen");
	if (nvmp_read(&prog, pf, &rv) < 0)
		err("Error reading netvm program %s\n", progname);
	fclose(pf);
	
	for (i = 0; i < NETVM_MAXMSEGS; ++i) {
		if (prog.sdescs[i].perms == 0)
			continue;
		len = prog.sdescs[i].len;
		netvm_set_mseg(&vm, i, emalloc(len), len, prog.sdescs[i].perms);
	}

	if ((rv = nvmp_validate(&prog, &vm)) < 0)
		err("Error validating program: %s\n", netvm_estr(rv));

	nvmp_init_mem(&prog, &vm);

	run_without_packets(&prog, NVMP_EP_START, &vm);
	run_with_packets(&prog, &vm, vm.matchonly);
	run_without_packets(&prog, NVMP_EP_END, &vm);

	return 0;
}
