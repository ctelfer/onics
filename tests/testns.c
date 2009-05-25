#include <stdio.h>
#include <cat/cat.h>
#include "namespace.h"

byte_t tcphdr[] = {
  '\x00', '\x16', '\x94', '\x53', '\x66', '\xa0', '\xde', '\x9d', '\x80', 
  '\xba', '\x8a', '\x0c', '\x80', '\x18', '\x03', '\x59', '\xab', '\x0f', 
  '\x00', '\x00',
};

int main(int argc, char *argv[])
{
  struct ns_namespace *tcpns = ns_new_namespace("tcp", 1);
  struct ns_namespace *ns = ns_new_namespace("ports", 1);
  struct ns_field *f, *bf;
  struct ns_scalar *s;
  struct ns_ranges *r;
  struct ns_element *e;

  ns_insert(tcpns, (struct ns_element *)ns_new_field("sport", 0, 2));
  ns_insert(tcpns, (struct ns_element *)ns_new_field("dport", 2, 2));
  ns_insert(tcpns, (struct ns_element *)ns_new_field("seqn", 4, 4));
  ns_insert(tcpns, (struct ns_element *)ns_new_field("ackn", 8, 4));
  ns_insert(tcpns, (struct ns_element *)ns_new_bitfield("syn", 13*8 + 6, 1));
  ns_insert(tcpns, (struct ns_element *)ns_new_bitfield("ack", 13*8 + 3, 1));
  ns_insert(tcpns, (struct ns_element *)ns_new_bitfield("psh", 13*8 + 4, 1));

  ns_insert(ns, (struct ns_element *)ns_new_scalar("http", 80));
  ns_insert(ns, (struct ns_element *)ns_new_scalar("ssh", 22));
  ns_insert(ns, (struct ns_element *)ns_new_srange("reserved", 0, 1023));
  r = ns_new_srange("oddrange", 22, 23);
  ns_add_srange(r, 80, 92);
  ns_insert(ns, (struct ns_element *)r);
  ns_insert(tcpns, (struct ns_element *)ns);

  ns_register(tcpns);

  if ( !(e = ns_name_lookup(tcpns, "seqn", -1)) ) {
    printf("seqn not found in tcpns\n");
  } else {
    printf("seqn (from tcpns) is of type %d\n", e->nstype);
  }
  if ( !(e = ns_name_lookup(NULL, "tcp.seqn", -1)) ) {
    printf("tcp.seqn not found\n");
  } else {
    printf("tcp.seqn is of type %d\n", e->nstype);
  }


  return 0;
}
