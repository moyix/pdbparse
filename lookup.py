#!/usr/bin/env python

import sys, os
import pdbparse
from operator import itemgetter,attrgetter
from bisect import bisect_right
from struct import unpack
from pdbparse.pe import Sections
from pdbparse.omap import Omap
from pdbparse.undecorate import undecorate

try:
    from IPython.Shell import IPShellEmbedxxx
    ipy = True
except ImportError:
    import code
    ipy = False

if len(sys.argv) < 4 or len(sys.argv[1:]) % 3 != 0:
    print >> sys.stderr, "usage: %s <pdb> <base> <omap> [[<pdb> <base> <omap>] ...]" % sys.argv[0]
    sys.exit(1)

mods = [ (sys.argv[i],sys.argv[i+1],int(sys.argv[i+2])) for i in range(1,len(sys.argv)-2,3) ]

addrs = {}

# Set this to the first PDB section that contains section headers
# Common bases:
#   ntdll: 8
#   ntoskrnl: 10
# BASE = 

for pdbname,basestr,BASE in mods:
    pdbbase = os.path.basename(pdbname).split('.')[0]
    print "Loading symbols for %s..." % pdbbase
    pdb = pdbparse.parse(pdbname)
    base = int(basestr,0)
    sects = Sections.parse(pdb.streams[BASE].data)
    orig_sects = Sections.parse(pdb.streams[BASE+3].data)
    gsyms = pdb.streams[pdb.streams[3].gsym_file]
    omap = Omap(pdb.streams[BASE+2].data)
    omap_rev = Omap(pdb.streams[BASE+1].data)

    last_sect = max(sects, key=attrgetter('VirtualAddress'))
    limit = base + last_sect.VirtualAddress + last_sect.Misc.VirtualSize

    addrs[base,limit] = {}
    addrs[base,limit]['name'] = pdbbase
    addrs[base,limit]['addrs'] = []
    for sym in gsyms.globals:
        off = sym.offset
        try:
            virt_base = sects[sym.segment-1].VirtualAddress
        except IndexError:
            continue

        mapped = omap.remap(off+virt_base) + base
        addrs[base,limit]['addrs'].append((mapped,sym.name))

    addrs[base,limit]['addrs'].sort(key=itemgetter(0))

def lookup(loc):
    for base,limit in addrs:
        if loc in xrange(base,limit):
            mod = addrs[base,limit]['name']
            symbols = addrs[base,limit]['addrs']
            locs  = [a[0] for a in symbols]
            names = [a[1] for a in symbols]
            idx = bisect_right(locs, loc) - 1
            diff = loc - locs[idx]
            if diff:
                return "%s!%s+%#x" % (mod,names[idx],diff)
            else:
                return "%s!%s" % (mod,names[idx])
    return "unknown"

banner = "Use lookup(addr) to resolve an address to its nearest symbol"
if ipy:
    ipshell = IPShellEmbed([], banner=banner)
    ipshell()
else:
    code.interact(banner=banner, local=locals())
