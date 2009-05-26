#include <stdio.h>
#include <cat/cat.h>
#include <cat/err.h>
#include <string.h>
#include "namespace.h"
#include "util.h"

#define E(x) ERRCK((x) ? -1 : 0)

byte_t tcphdr[] = {
  '\x00', '\x16', '\x94', '\x53', '\x66', '\xa0', '\xde', '\x9d', '\x80', 
  '\xba', '\x8a', '\x0c', '\x80', '\x18', '\x03', '\x59', '\xab', '\x0f', 
  '\x00', '\x00',
};

byte_t iphdr[] = { 
  '\x45', '\x10', '\x00', '\x34', '\xa1', '\x5c', '\x40', '\x00', '\x40', 
  '\x06', '\x17', '\xfa', '\xc0', '\xa8', '\x00', '\x06', '\xc0', '\xa8', 
  '\x00', '\x07',
};


byte_t addr0[4] = "\xc0\xa8\x00\x06";
byte_t addr1[4] = "\xc0\xa8\x00\x00";
byte_t mask1[4] = "\xff\xff\x00\x00";
byte_t addr2[4] = "\xc0\xa8\xFF\xFF";
byte_t addr3[4] = "\x7f\x00\x00\x00";
byte_t addr4[4] = "\x7f\xFF\xFF\xFF";
byte_t addr5[4] = "\xc0\x00\x00\x06";
byte_t mask5[4] = "\xf0\x00\x00\x0f";

byte_t saddr[4];
byte_t daddr[4];


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


#define arr2raw(a,r) (r.data = a, r.len = sizeof(a), &r)

int main(int argc, char *argv[])
{
  struct ns_namespace *tcpns = ns_new_namespace("tcp", 1);
  struct ns_namespace *ns = ns_new_namespace("ports", 1);
  struct ns_field *f, *bf;
  struct ns_scalar *s;
  struct ns_ranges *r;
  struct ns_masked *m;
  struct ns_element *e;
  struct ns_rawval *nsrv;
  unsigned long v;
  struct raw rv, rv2;

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

  E(ns_name_lookup(NULL, "a.b.c", NSTYPE_ANY));
  E(ns_name_lookup(NULL, "tcp.b.c", NSTYPE_ANY));
  E(ns_name_lookup(NULL, "tcp.ports.c", NSTYPE_ANY));
  printf("all bad lookup tests passed\n");

  ns = ns_new_namespace("ip", 1);
  E(!ns_register(ns));
  ns_free((struct ns_element *)ns);
  printf("successfully freed node after id collision in namespace\n");

  E(ns_deregister(tcpns));
  ns_free((struct ns_element *)tcpns);
  E(ns_name_lookup(NULL, "tcp", NSTYPE_ANY));
  E(ns_name_lookup(NULL, "tcp.ports.oddrange", NSTYPE_ANY));
  printf("successfully freed tcpns\n");

  ns = ns_new_namespace("ip", 1);
  E(ns_insert(ns, (struct ns_element *)ns_new_field("saddr", 12, 4)));
  E(ns_insert(ns, (struct ns_element *)ns_new_field("daddr", 16, 4)));
  E(ns_insert(ns, (struct ns_element *)ns_new_raw("addr0", arr2raw(addr0,rv))));
  E(ns_insert(ns, (struct ns_element *)ns_new_masked("maddr1", 
                                                     arr2raw(addr1,rv),
                                                     arr2raw(mask1,rv2))));
  E(ns_insert(ns, (struct ns_element *)ns_new_prefixed("paddr1", 
                                                       arr2raw(addr1,rv), 24)));
  r = ns_new_rrange("rraddr1", arr2raw(addr3,rv), arr2raw(addr4,rv2));
  ns_add_rrange(r, arr2raw(addr1,rv), arr2raw(addr2,rv2));
  E(ns_insert(ns, (struct ns_element *)r));
  E(ns_insert(ns, (struct ns_element *)ns_new_masked("maddr2", 
                                                     arr2raw(addr5,rv),
                                                     arr2raw(mask5,rv2))));

  E(!(e = ns_name_lookup(ns, "saddr", NSTYPE_FIELD)));
  f = (struct ns_field *)e;
  memcpy(saddr, iphdr + f->off, f->size);
  E(!(e = ns_name_lookup(ns, "daddr", NSTYPE_FIELD)));
  f = (struct ns_field *)e;
  memcpy(daddr, iphdr + f->off, f->size);

  E(!(nsrv = (struct ns_rawval *)ns_name_lookup(ns, "addr0", NSTYPE_RAW)));
  if ( ns_cmp_raw((struct ns_element *)nsrv, saddr, 4) )
    printf("saddr matches addr0\n");
  if ( ns_cmp_raw((struct ns_element *)nsrv, daddr, 4) )
    printf("daddr matches addr0\n");

  E(!(m = (struct ns_masked *)ns_name_lookup(ns, "maddr1", NSTYPE_MASKED)));
  if ( ns_cmp_raw((struct ns_element *)m, saddr, 4) )
    printf("saddr matches maddr1\n");
  if ( ns_cmp_raw((struct ns_element *)m, daddr, 4) )
    printf("daddr matches maddr1\n");

  E(!(m = (struct ns_masked *)ns_name_lookup(ns, "paddr1", NSTYPE_MASKED)));
  if ( ns_cmp_raw((struct ns_element *)m, saddr, 4) )
    printf("saddr matches paddr1\n");
  if ( ns_cmp_raw((struct ns_element *)m, daddr, 4) )
    printf("daddr matches paddr1\n");

  E(!(m = (struct ns_masked *)ns_name_lookup(ns, "maddr2", NSTYPE_MASKED)));
  if ( ns_cmp_raw((struct ns_element *)m, saddr, 4) )
    printf("saddr matches maddr2\n");
  if ( ns_cmp_raw((struct ns_element *)m, daddr, 4) )
    printf("daddr matches maddr2\n");

  E(!(r = (struct ns_ranges *)ns_name_lookup(ns, "rraddr1", NSTYPE_RRANGE)));
  if ( ns_cmp_raw((struct ns_element *)r, saddr, 4) )
    printf("saddr matches rraddr1\n");
  if ( ns_cmp_raw((struct ns_element *)r, daddr, 4) )
    printf("daddr matches rraddr1\n");

  ns_free((struct ns_element *)ns);
  printf("all done\n");
  return 0;
}
