#!/usr/bin/env python

import sys
import pdbparse
from optparse import OptionParser

from pdbparse.pe import Sections
from pdbparse.omap import Omap

def cstring(str):
    return str.split('\0')[0]

parser = OptionParser()
parser.add_option("-n", "--no-omap",
                  action="store_false", dest="omap", default=True,
                  help="don't try to make use of OMAP information")
(opts, args) = parser.parse_args()

if len(args) != 2:
    parser.error("Need filename and base address")

pdb = pdbparse.parse(args[0])
imgbase = int(args[1], 0)
sects = pdb.STREAM_SECT_HDR_ORIG.sections
gsyms = pdb.STREAM_GSYM

if opts.omap:
    omap = pdb.STREAM_OMAP_FROM_SRC
else:
    class Dummy: pass
    omap = Dummy()
    omap.remap = lambda x: x

for sym in gsyms.globals:
    try:
        off = sym.offset
        virt_base = sects[sym.segment-1].VirtualAddress
        nm = cstring(sects[sym.segment-1].Name)
        print "%s,%#x,%d,%s" % (sym.name,imgbase+omap.remap(off+virt_base),sym.symtype,nm)
    except IndexError,e:
        print >> sys.stderr, "Skipping %s, segment %d does not exist" % (sym.name,sym.segment-1)
