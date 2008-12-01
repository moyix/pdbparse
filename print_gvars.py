#!/usr/bin/env python

import sys
import pdbparse
from pdbparse.pe import Sections
from pdbparse.omap import remap,OMAP_FROM_SRC

def cstring(str):
    return str.split('\0')[0]

pdb = pdbparse.parse(sys.argv[1])
print len(pdb.streams)
sects = Sections.parse(pdb.streams[10].data)
gsyms = pdb.streams[pdb.streams[3].gsym_file]
omap = OMAP_FROM_SRC.parse(pdb.streams[12].data)

for sym in gsyms.globals:
    off = sym.offset
    try:
        virt_base = sects[sym.segment-1].VirtualAddress
        nm = cstring(sects[sym.segment-1].Name)
        #print "%-40s: (%s+%x) = (%x+%x) = %x (pre-OMAP)" % (sym.name,nm,off,virt_base,off,off+virt_base)
        print "%s,%x,%d,%s" % (sym.name,remap(off+virt_base,omap),sym.symtype,nm)
    except IndexError:
        print >> sys.stderr, "Skipping %s, segment %d does not exist" % (sym.name,sym.segment-1)
