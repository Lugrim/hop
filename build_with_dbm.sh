#!/bin/sh -x

touch hopscript/RewriteLib.c

cd hopscript

make o/RewriteLib.o

bigloo -O3 -fstackable -fsharing -L /home/aurore/Software/hop/lib/hop/3.6.0 -srfi bigloo-compile -cc gcc -srfi enable-tls -srfi license-academic -srfi enable-ssl -srfi enable-threads -srfi enable-avahi -srfi enable-upnp -srfi enable-libuv  -srfi hop-dynamic -L /home/aurore/Software/hop/lib/hop/3.6.0 -copt "-fPIC -DHOP_REWRITE_OPCODE -DDEBUG_VERBOSE" -srfi bigloo-compile -unsafe -safee -c property.scm -o o/property.o -cg


cd ..

make "CCFLAGS=-DHOP_REWRITE_OPCODE" "BLDFLAGS=-lcapstone" && sudo make install
