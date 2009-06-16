#include "pktbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <cat/err.h>
#include <cat/optparse.h>
#include <cat/uevent.h>
#include <cat/io.h>
#include <cat/stduse.h>

#define MAX_FDS      1021

int g_nfd = 0;

struct clopt g_optarr[] = {
  CLOPT_INIT(CLOPT_NOARG,  'h', "--help", "print help")
};
struct clopt_parser g_oparser =
  CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));


void usage(const char *estr)
{
  char ubuf[4096];
  if ( estr != NULL )
     fprintf(stderr, "Error -- %s\n", estr);
  optparse_print(&g_oparser, ubuf, sizeof(ubuf));
  err("usage: %s [options] <nstreams>\n"
      "\t<nstreams> must be between 1 and %d\n"
      "%s", g_oparser.argv[0], MAX_FDS, ubuf);
}


void parse_options()
{
  int rv;
  struct clopt *opt;

  while ( !(rv = optparse_next(&g_oparser, &opt)) ) {
    switch(opt->ch) {
    case 'h':
      usage(NULL);
    }
  }
  if ( rv < 0 )
    usage(g_oparser.errbuf);

  if ( g_oparser.argc - rv == 0 )
    usage("No number of streams");
  if ( g_oparser.argc - rv != 1 )
    usage("Extra arguments present");
  g_nfd = atoi(g_oparser.argv[rv]);
  if ( g_nfd <= 0 )
    usage("Must have at least one input stream");
  if ( g_nfd > MAX_FDS )
    usage("Too many streams");
}


/* determine if an FD is open for reading or not and if not quit */
void testfd(int fd)
{
  int flags = fcntl(fd, F_GETFL);
  if ( flags == -1 )
    err("%d is not a valid file descriptor", fd);
  if ( (flags & O_ACCMODE) != O_RDONLY && (flags & O_ACCMODE) != O_RDWR )
    err("File descriptor %d is not writable", fd);
}


int readpkt(void *arg, struct callback *cb)
{
  int rv;
  struct pktbuf *p;
  struct ue_ioevent *ioe = container(cb, struct ue_ioevent, cb);

  if ( (rv = pkb_fd_read(ioe->fd, &p)) <= 0 ) {
    if ( rv < 0 )
      logsys(1, "Error reading from fd %d\n", ioe->fd);
    ue_io_del(cb);
    return 0;
  }
  if ( pkb_fd_write(1, p) < 0 )
    errsys("Error writing packet %u\n");
  p->pkb_class = ioe->fd - 3;
  pkb_free(p);

  return 0;
}


int main(int argc, char *argv[])
{
  int i;
  struct uemux mux;

  optparse_reset(&g_oparser, argc, argv);
  parse_options();
  fclose(stdin);

  ue_init(&mux);
  for ( i = 3; i < 3 + g_nfd; ++i ) {
    testfd(i);
    ue_io_new(&mux, UE_RD, i, readpkt, NULL);
  }

  ue_run(&mux);
  ue_fini(&mux, &estdmem);

  return 0;
}
