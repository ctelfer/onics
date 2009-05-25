#include <stdio.h>
#include <cat/cat.h>
#include <cat/err.h>
#include "namespace.h"
#include "util.h"

#define E(x) ERRCK(x)

byte_t tcphdr[] = {
  '\x00', '\x16', '\x94', '\x53', '\x66', '\xa0', '\xde', '\x9d', '\x80', 
  '\xba', '\x8a', '\x0c', '\x80', '\x18', '\x03', '\x59', '\xab', '\x0f', 
  '\x00', '\x00',
};

unsigned long extract(byte_t *p, unsigned off, unsigned len)
{
  if ( len == 1 ) {
    byte_t b;
    unpack(p + off, len, "b", &b);
    return b;
  } else if ( len == 2 ) { 
    ushort h;
    unpack(p + off, len, "h", &h);
    return h;
  } else if ( len == 4 ) { 
    ulong w;
    unpack(p + off, len, "w", &w);
    return w;
  } else {
    err("invalid length: %u\n", len);
  }
}

int main(int argc, char *argv[])
{
  struct ns_namespace *tcpns = ns_new_namespace("tcp", 1);
  struct ns_namespace *ns = ns_new_namespace("ports", 1);
  struct ns_field *f, *bf;
  struct ns_scalar *s;
  struct ns_ranges *r;
  struct ns_element *e;
  unsigned long v;

  E(!tcpns);
  E(!ns);

  E(ns_insert(tcpns, (struct ns_element *)ns_new_field("sport", 0, 2)));
  E(ns_insert(tcpns, (struct ns_element *)ns_new_field("dport", 2, 2)));
  E(ns_insert(tcpns, (struct ns_element *)ns_new_field("seqn", 4, 4)));
  E(ns_insert(tcpns, (struct ns_element *)ns_new_field("ackn", 8, 4)));
  E(ns_insert(tcpns, (struct ns_element *)ns_new_bitfield("syn", 13*8 + 6, 1)));
  E(ns_insert(tcpns, (struct ns_element *)ns_new_bitfield("ack", 13*8 + 3, 1)));
  E(ns_insert(tcpns, (struct ns_element *)ns_new_bitfield("psh", 13*8 + 4, 1)));

  E(ns_insert(ns, (struct ns_element *)ns_new_scalar("http", 80)));
  E(ns_insert(ns, (struct ns_element *)ns_new_scalar("ssh", 22)));
  E(ns_insert(ns, (struct ns_element *)ns_new_srange("reserved", 0, 1023)));
  E(!(r = ns_new_srange("oddrange", 80, 92)));
  ns_add_srange(r, 20, 40);
  E(ns_insert(ns, (struct ns_element *)r));
  E(ns_insert(tcpns, (struct ns_element *)ns));

  E(ns_register(tcpns));

  E(!(e = ns_name_lookup(tcpns, "seqn", NSTYPE_ANY)));
  printf("seqn (from tcpns) is of type %d\n", e->nstype);
  E(!(e = ns_name_lookup(NULL, "tcp.seqn", NSTYPE_ANY)));
  printf("tcp.seqn is of type %d\n", e->nstype);

  E(!(e = ns_name_lookup(NULL, "tcp.sport", NSTYPE_FIELD)));
  f = (struct ns_field *)e;
  E(!(e = ns_name_lookup(NULL, "tcp.ports.ssh", NSTYPE_SCALAR)));
  s = (struct ns_scalar *)e;
  v = extract(tcphdr, f->off, f->size);
  printf("extracted source port %s tcp.ports.ssh (%lu vs %lu)\n", 
         (v == s->value) ? "matches" : "doesn't match", v, s->value);

  E(!(bf = (struct ns_field *)ns_name_lookup(NULL, "tcp.syn", NSTYPE_FIELD)));
  printf("tcp.syn %s set\n", 
         getbitfield(tcphdr, bf->off, bf->size) ? "is" : "is not");

  E(!(bf = (struct ns_field *)ns_name_lookup(NULL, "tcp.ack", NSTYPE_FIELD)));
  printf("tcp.ack %s set\n", 
         getbitfield(tcphdr, bf->off, bf->size) ? "is" : "is not");
         
  E(!(bf = (struct ns_field *)ns_name_lookup(NULL, "tcp.psh", NSTYPE_FIELD)));
  printf("tcp.psh %s set\n", 
         getbitfield(tcphdr, bf->off, bf->size) ? "is" : "is not");


  E(!(e = ns_name_lookup(NULL, "tcp.sport", NSTYPE_FIELD)));
  f = (struct ns_field *)e;
  v = extract(tcphdr, f->off, f->size);
  E(!(e = ns_name_lookup(NULL, "tcp.ports.oddrange", NSTYPE_SRANGE)));
  printf("tcp.sport %s tcp.ports.oddrange\n",
         ns_cmp_scalar(e, v) ? "matches" : "doesn't match");

  E(!(e = ns_name_lookup(NULL, "tcp.dport", NSTYPE_FIELD)));
  f = (struct ns_field *)e;
  v = extract(tcphdr, f->off, f->size);
  E(!(e = ns_name_lookup(NULL, "tcp.ports.oddrange", NSTYPE_SRANGE)));
  printf("tcp.dport %s tcp.ports.oddrange\n",
         ns_cmp_scalar(e, v) ? "matches" : "doesn't match");

  return 0;
}
