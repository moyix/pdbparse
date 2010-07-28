#!/usr/bin/env python

import sys
import pdbparse
from optparse import OptionParser

from pdbparse.pe import Sections
from pdbparse.omap import remap,OMAP_ENTRIES

def cstring(str):
    return str.split('\0')[0]

parser = OptionParser()
parser.add_option("-n", "--no-omap",
                  action="store_false", dest="omap", default=True,
                  help="don't try to make use of OMAP information")
(opts, args) = parser.parse_args()

if len(args) != 3:
    op.error("Need filename, base address, and first section offset")

pdb = pdbparse.parse(args[0])
imgbase = int(args[1], 0)
secbase = int(args[2], 0)
sects = Sections.parse(pdb.streams[secbase].data)
gsyms = pdb.streams[pdb.streams[3].gsym_file]

if opts.omap:
    omap = OMAP_ENTRIES.parse(pdb.streams[secbase+2].data)
else:
    omap = None
    remap = lambda x,y: x

for sym in gsyms.globals:
    try:
        off = sym.offset
        virt_base = sects[sym.segment-1].VirtualAddress
        nm = cstring(sects[sym.segment-1].Name)
        #print "%-40s: (%s+%x) = (%x+%x) = %x (pre-OMAP)" % (sym.name,nm,off,virt_base,off,off+virt_base)
        print "%s,%#x,%d,%s" % (sym.name,imgbase+remap(off+virt_base,omap),sym.symtype,nm)
    except IndexError,e:
        print >> sys.stderr, "Skipping %s, segment %d does not exist" % (sym.name,sym.segment-1)
