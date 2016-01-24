INTRODUCTION
============

ONICS is a command line tool suite along with the code building blocks
for those tools to capture, dissect, manipulate and send network data.
The intent of these tools is to make it possible to manipulate packets
on the command line in a UNIX-shell like fashion the same way one can
manipulate text with programs like sed, awk, cat, tr, etc.  In fact,
many of said command line tools and be used with the ONICS tool suite if
done properly.  There are currently 21 binary tools and 28 Bourne shell
scripts in the repository.

This tool suite comes with regression tests, examples, complete manpages
and extended libraries to improve programmabilitiy.  All binaries are
written in pure ANSI-89 C code.  Most have no external dependencies
outside of libc and catlib (see below).  The few that do will not be
compiled or installed if their dependencies are not detected.  It is
also simple to add support for new protocols and have all the tools in
the suite automatically updated.  All scripts are written in pure Bourne
Shell.

See LICENSE.txt for the free/libre open source licensing of this suite.



QUICK START
===========

 1) First download both Catlib and ONICS and put the distributions in
    the same top level directory.  You can find catlib at:
      ** https://github.com/ctelfer/catlib
      ** https://gitlab.com/catlib/catlib
    Similarly, one can find ONICS at:
      ** https://github.com/ctelfer/onics
      ** https://gitlab.com/onics/onics

 2) Change to the catlib directory and type:

    make

 3) Change to the onics directory and type:

    make

 4) (optional) To install run:

    sudo make install

This will:
 * build the tools
 * build test programs (under tests/bin)
 * run regression tests
 * optionally install the programs and manpages in /usr/local



EXAMPLES
========

    # Create a TCP packet to go to 10.0.0.1 and send it out on eth0
    mktcp "ip.daddr = 10.0.0.1" | pktout eth0

    # Capture packets from eth0 and dump them in annotated hex form
    pktin eth0 | x2hpkt | less

    # Convert a pcap file to xpkt format
    pc2xpkt in.pcap out.xpkt

    # Extract the packets 3 through 10 from a packet stream
    pfind 3 -to 10 file.xpkt 
  
    # Read from an interface using libpcap and dump to an xpkt file
    pktin eth0 out.xpkt
  
    # Join two xpkt files into one.  (note: you can't do this with pcap
    # files, but can with xpkt)
    cat XPFILE1 XPFILE2 > XPFILE3 
  
    # Send an xpkt file to tcpdump for dissecting (why? to demonstrate tool 
    # integration)
    xpkt2pc XPKTFILE | tcpdump -vvvvs 0 -r - 
  
    # Full pipeline of translations:
    # pcap -> xpkt -> hexpkt -> xpkt -> pcap -> tcpdump output -> less
    pc2xpkt in.pcap | x2hpkt -x | h2xpkt | xpkt2pc | tcpdump -nvXs 0 -r - | less

    # Create a packet layer by layer and send out eth0
    echo "hello world" | rawpkt | tcpwrap | ipwrap | ethwrap | pktout eth0
  
  
    #
    # Now for some cooler stuff
    #
  
    # Read all packets from one interface, toggle their DF bits and send
    # them out a different interface.
    pktin eth2 | 
      pml -e '?- ip -? { ip.df = ip.df ^ 1 ; fix_csums(0); }' |
      pktout eth3


    # Read in the first 5 TCP packets to port 80, drop the rest and
    # fragment the ones that get through at an MTU of 777
    cat > x.pml <<EOF
      var n = 0;
      ?- not tcp or tcp.dport != 80 or n >= 5 -? { drop; }
      { n = n + 1; }
    EOF
    pml -f x.pml in.xpkt | ipfrag -m 777 > out.xpkt
  

    # Print an error for every TCP packet that has evil in it.
    pcapin -i IFACE1 | 
      pml -e '
        int n = 0;
        { n = n + 1; }
        ?- tcp and tcp.payload =~ `[eE][vV][iI][lL]` -? { 
            print "Packet ", n, " is evil\n";
        }' >/dev/null



LIST OF TOOLS
=============

Below is a list of the current binary tools in the suite.

 * pml - an AWK-like program for packet streams

 * pdiff - compares packet streams and print the differences

 * nft - tracks individual flows in a stream of packets

 * pspilt - split a packet stream to multiple streams

 * psort - sort the packets in a stream

 * ipfrag - fragments IP/IPv6 packets

 * ipreasm - reassemble IP/IPv6 packets

 * pktin - reads packets from a network interface

 * pktout - write packets to a network interface

 * x2hpkt - converts XPKTs to “hex packet” format

 * h2xpkt - converts “hex packet” packets to XPKT format

 * pcapin - reads in pcap files or interfaces through libpcap

 * pcapout - dumps packets to a pcap file or to an interface vi libpcap

 * nvmas - an assembler for the NetVM that underlies pml and nvmpf

 * nvmpf - a pure NetVM packet filter program

 * pc2xpkt - convert PCAP files to XPKT without libpcap

 * pktmux - a program to multiplex packets from multiple input streams

 * pktdemux - a program to demultiplex packets to different output streams

 * pktrel - release packets according to a traffic specification

 * rawpkt - convert a file into a packet with no datalink types

 * xpkt2pc - convert XPKT files to PCAP without libpcap


There are also various scripts built on the binary tools.  All of these
scripts should be in strictly compliant Bourne shell.  So they should
work just about everywhere.

 * ethwrap - wrap packets in an ethernet frame header

 * gre-decap - decapsulate [NV]GRE+IP+Etherent packets

 * gre-encap - encapsulate packets in [NV]GRE+IP+Etherent headers

 * ipwrap  - wrap packets in an IPv4 header

 * ip6wrap - wrap packets in an IPv6 header

 * icmpwrap - wrap packets in an ICMP header

 * icmp6wrap - wrap packets in an ICMPv6 header

 * mkarp - create an ARP packet

 * mkicmp - create an ICMP packet

 * mkicmp6 - create an ICMPv6 packet

 * mktcp - create a TCP packet

 * mktcp6 - create a TCP in IPv6 packet

 * mkudp - create a UDP packet

 * mkudp6 - create a UDP in IPv6 packet

 * pcount - count the packets in a stream

 * peseq - embed a sequence number into various fields in a packet stream

 * pfind - a program to select a subset of packets from a stream

 * phead - extract the first N packets from a packet stream

 * ppop - pop the outermost protocol(s) from each packet in a packet stream

 * ptail - extract the last N packets from a packet stream

 * pxseq - extract a sequence number from embedded fields in a packet stream

 * tcpsess - generate a partial or complete TCP stream from data files

 * tcpwrap - wrap packets in a TCP header

 * udpwrap - wrap packets in a UDP header

 * vxlan-decap - decapsulate VXLAN+UDP+IP+Etherent packets

 * vxlan-encap - encapsulate packets in VXLAN+UDP+IP+Etherent headers

 * xpktdump - dump a stream of packets in readable format with pagination

 * xtsscale - scale the timestamps for a stream of packets



PHILOSOPHY
==========

The tools in the suite and their underlying components were designed
with several principles in mind.

 * Self-contained -- The intent is to ultimately have these tools only
    require a compliant C compiler to build.  

 * Pluggable -- One should be able to plug new tools in without changing
    the existing ones.

 * Protocol agnostic -- The tools should be able to adapt to 
    new protocols without changing the main tool code.

 * Simple -- Each tool should do a few things well and no more.

 * Small, bounded resource footprint -- Each tool should be able to
    function well in low memory/CPU environments.



DIRECTORIES
===========

 * bin/ - target directory where the binaries get built
 * doc/ - contains the documentation (man pages)
 * lemon/ - contains the public-domain lemon parser generator
 * lib/ - contains libraries to be installed in the system
 * scripts/ - contains Bourne shell scripts for the tool suite
 * src/ - source code for all binaries
 * tests/ - contains various unit tests for the tools



COMPONENTS
==========

There are several notable pieces of infrastructure that the ONICS tools
tend to rely on.

 * XPKT -- an external packet format.  This is a PCAP replacement that
       offers extensibility and the easy ability to cut and paste
       packets from a stream of XPKT-formatted packets.

 * NetVM -- a 64-bit stack based virtual machine augmented for packet
       processing.  This VM uses segmented memory regions and a
       read-only code store.  In certain configurations programs can be
       verified to have bounded runtime and stack space requirements.

 * PML -- Packet Manipulation Language.  An langauge in the flavor of
       AWK for manipulating packets in a pattern/action style.  The
       language is not as powerful as, say, Python, Ruby or even Lua.
       But it does operate with fixed memory requirements and treats
       packets as first-class data objects making manipulating them and
       their protocols intuitive.

 * ProtoParse -- a protocol-neutral set API for creating network
       protocol disectors and namespaces.  These APIs allow the tools
       in the suite to function without specific understanding of the
       protocols they interpret.



CATLIB
======

One quick note about Catlib.  Catlib is a library of useful (to me
anyways) C code for various common and not-so-common data structures and
algorithms.  I built it up over the years, tore it apart, rebuilt it,
used it for my thesis, and reworked it as my programming tastes changed.
Its current incarnation focuses heavily on making individual modules as
independent of one another (and external APIs) as possible.  So one
could, for example, extract only one or two files to get a functioning
AVL tree implementation that works without the rest of the library or
even a functioning Standard C library.  I freely confess that some of
the code in that library I wrote simply to prove that I could implement
it myself without needing someone else's code.

One last quick note about "lemon".  The lemon parser generator is a
public domain parser generator that D. Richard Hipp wrote as part of
sqlite.  I like it better than bison for a variety of reasons and use it
to generate the PML parser.  It is self-contained (two C files) and,
being public domain, it can go directly in this project.  But I am by no
means claiming credit for writing this code: that accolade goes to Dr.
Hipp and if he is reading this: you have my many thanks!



MORE SAMPLES
============

See tests/data/pml/*.pml for more PML code examples.

There are also examples in the manpages for the above programs and scripts.
