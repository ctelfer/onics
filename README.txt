
INTRODUCTION

ONICS is a command line tool suite along with the code building blocks
for those tools to capture, dissect, manipulate and send network data.
The intent of these tools is to make it possible to manipulate packets
on the command line in a UNIX-shell like fashion the same way one can
manipulate text with programs like sed, awk, cat, tr, etc.  In fact, many
of said command line tools and be used with the ONICS tool suite if done
properly. 



QUICK START

To build:
     1) First download both Catlib and ONICS and put the distributions in
     the same top level directory.  You must also have 'flex' and 'libpcap'
     installed on the machine and currently gcc.  (All these deps will go
     away at some point.)

     2) Change to the catlib directory and type:
       make

     3) Change to the onics directory and type
       make

  The tool binaries as well as some test programs (named test*) are now
  in onics/bin.

Examples:

  # convert a pcap file to xpkt format
  pcapin PCAPFILE > XPKTFILE

  # Read from an interface using libpcap and dump to an xpkt file
  pcapin -i INTERFACE > xpkt file

  # dump a pcap file to a hex format for reading
  pcapin PCAPFILE | x2hpkt | less

  # convert xpkt to hexpkt
  x2hpkt < INXPKT > OUTHEXPKT

  # convert hexpkt to xpkt
  x2hpkt < INHEXPKT > OUTXPKT

  # Join two xpkt files into one.  (note: you can't do this with pcap
  # files, but can with xpkt)
  cat XPFILE1 XPFILE2 > XPFILE3 

  # Send an xpkt file to tcpdump for dissecting (why? to demonstrate tool 
  # integration)
  pcapout XPKTFILE | tcpdump -vvvvs 0 -r - 

  # Full pipeline of translations:
  # pcap -> xpkt -> hexpkt -> xpkt -> pcap -> tcpdump output
  pcapin < PCAPFILE | x2hpkt -x | h2xpkt | pcapout | tcpdump -nvXs 0 -r - | less


  #
  # Now for some cooler stuff
  #

  # Read all packets from one interface, toggle their DF bits and send
  # them out a different interface.
  pcapin -i IFACE1 | 
    pml -e '?- ip -? { ip.df = ip.df ^ 1 ; fix_all_csum(0); }'
    pcapout -i IFACE2


  # Read in the first 5 TCP packets, drop the rest.
  cat > x.pml <<EOF
    var n = 0;
    ?- not tcp or n >= 5 -? { drop; }
    { n = n + 1; }
  EOF
  pml -f x.pml < INXPKT > OUTXPKT


  # Print an error for every TCP packet that has evil in it.
  # Note the '\' is for the shell: it is not part of PML
  pcapin -i IFACE1 | 
    pml -e '
      var n = 0;
      { n = n + 1; }
      ?- tcp and tcp.payload =~ `[eE][vV][iI][lL]` -? { 
          print "Packet ", n, " is evil\n";
      }'




PHILOSOPHY

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

Some of these ideals are not yet met to the developer's satisfaction
yet.  For example, the PML language currently depends on flex.  The
PCAP utilities require libpcap.  The NetVM that underlies PML uses a
64-bit runtime stack which is a bit much for embedded environments
(although compilers can cope).  Each of these choices had a rationale
(or maybe a rationalization) but the hope is nevertheless to continue to
push the tools towards those ideals.



COMPONENTS

There are several notable pieces of infrastructure that the ONICS tools
tend to rely on.

    XPKT -- an external packet format.  This is a PCAP replacement that
        offers extensibility and the easy ability to cut and paste
        packets from a stream of XPKT-formatted packets.

    NetVM -- a 64-bit stack based virtual machine augmented for packet
        processing.  This VM uses segmented memory regions and a
        read-only code store.  In certain configurations programs can be
        verified to have bounded runtime and stack space requirements.

    PML -- Packet Manipulation Language.  An langauge in the flavor of
        AWK for manipulating packets in a pattern/action style.  The
        language is not as powerful as, say, Python, Ruby or even Lua.
        But it does operate with fixed memory requirements and treats
        packets as first-class data objects making manipulating them and
        their protocols intuitive.

    ProtoParse -- a protocol-neutral set API for creating network
        protocol disectors and namespaces.  These APIs allow the tools
        in the suite to function without specific understanding of the
        protocols they interpret.

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
X myself without needing someone else's code.

One last quick note about "lemon".  The lemon parser generator is a
public domain parser generator that D. Richard Hipp wrote as part of
sqlite.  I like it better than bison for a variety of reasons and use it
to generate the PML parser.  Among other factors, it is self-contained
(two C files) and being public domain, it can go directly in this
project.  But I am by no means claiming credit for writing this code:
that accolade goes to Dr. Hipp and if he is reading this: you have my
many thanks!



CURRENT TOOLS

The tool suite currently consists of 11 tools some of which are still in
progress and one of which isn’t started.  Obviously, we can add more as
time goes on.  Furthermore, this suite will eventually be augmented by
shell scripts using these tools for common tasks.

    pml - an AWK-like program for packets using the Packet Manipulation
        Language and running on the NetVM.

    pcapin - reads in pcap files or interfaces through libpcap and emits
        XPKT packets.

    pcapout - reads in a stream of XPKT packets and dumps them to a pcap
        file or to an interface through libpcap.

    x2hpkt - converts XPKTs to “hex packet” format: an annotated
        hex-based format.

    h2xpkt - converts “hex packet” packets to XPKT format.

    nvmas - an assembler for the NetVM that underlies pml and nvmpf.

    nvmpf - a pure NetVM packet filter program.

    pktmux - a program to multiplex packets from multiple input streams.
        (needs some work)

    pktdemux - a program to demultiplex packets to different output
        streams. (needs some work)

    pktrel - a program to release packets according to a traffic
        specification for delay, loss, jitter, throughput, etc.. (unfinished)

    pktdiff - a program to compare packet streams or traces and emit
        differences between them. (not started)



MORE SAMPLES

   TODO

   See testdata/pml/cg_test*.pml for more PML code examples.
