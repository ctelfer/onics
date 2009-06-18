#include "pktbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <cat/err.h>
#include <cat/optparse.h>

ulong g_npkts = 0;
int g_nfiles;
char **g_files;
char *nofilearr[] = { "-" };

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
  err("usage: %s [options]\n"
      "%s", g_oparser.argv[0], ubuf);
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

  if ( g_oparser.argc - rv == 0 ) {
    g_files = nofilearr;
    g_nfiles = array_length(nofilearr);
  } else {
    g_nfiles = g_oparser.argc - rv;
    g_files = g_oparser.argv + g_oparser.argc;
  }
}


int main(int argc, char *argv[])
{
  int fd, i, rv, stdinread = 0;
  struct pktbuf *p;
  unsigned long filepkts = 0;

  for ( i = 0; i < g_nfiles; ++i ) {
    if ( strcmp(g_files[i], "-") == 0 ) {
      if ( stdinread )
        continue;
      fd = 0;
      stdinread = 1;
    } else {
      if ( (fd = open(g_files[i], O_RDONLY)) < 0 )
        errsys("Error opening file '%s': ", g_files[i]);
    }

    filepkts = 0;

    while ( (rv = pkb_fd_read(fd, &p)) > 0 ) {
      ++g_npkts;
      ++filepkts;
      if ( pkb_fd_write(1, p) < 0 )
        errsys("Error writing packet %lu", g_npkts);
    }

    if ( rv < 0 )
      errsys("Error reading packet %lu from '%s'", filepkts + 1, g_files[i]);

    close(fd);
  }

  return 0;
}
