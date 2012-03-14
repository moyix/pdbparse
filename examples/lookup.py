#!/usr/bin/env python

import sys, os
import pdbparse
from operator import itemgetter,attrgetter
from bisect import bisect_right
from pdbparse.undecorate import undecorate

class Lookup(object):
    def __init__(self, mods):
        self.addrs = {}

        for pdbname,basestr in mods:
            pdbbase = os.path.basename(pdbname).split('.')[0]
            print "Loading symbols for %s..." % pdbbase
            pdb = pdbparse.parse(pdbname)
            base = int(basestr,0)
            sects = pdb.STREAM_SECT_HDR_ORIG.sections
            gsyms = pdb.STREAM_GSYM
            omap = pdb.STREAM_OMAP_FROM_SRC

            last_sect = max(sects, key=attrgetter('VirtualAddress'))
            limit = base + last_sect.VirtualAddress + last_sect.Misc.VirtualSize

            self.addrs[base,limit] = {}
            self.addrs[base,limit]['name'] = pdbbase
            self.addrs[base,limit]['addrs'] = []
            for sym in gsyms.globals:
                off = sym.offset
                try:
                    virt_base = sects[sym.segment-1].VirtualAddress
                except IndexError:
                    continue

                mapped = omap.remap(off+virt_base) + base
                self.addrs[base,limit]['addrs'].append((mapped,sym.name))

            self.addrs[base,limit]['addrs'].sort(key=itemgetter(0))

        self.locs = {}
        self.names = {}
        for base,limit in self.addrs:
            mod = self.addrs[base,limit]['name']
            symbols = self.addrs[base,limit]['addrs']
            self.locs[base,limit]  = [a[0] for a in symbols]
            self.names[base,limit] = [a[1] for a in symbols]

    def lookup(self, loc):
        for base,limit in self.addrs:
            if loc in xrange(base,limit):
                mod = self.addrs[base,limit]['name']
                symbols = self.addrs[base,limit]['addrs']
                locs  = self.locs[base,limit]
                names = self.names[base,limit] 
                idx = bisect_right(locs, loc) - 1
                diff = loc - locs[idx]
                if diff:
                    return "%s!%s+%#x" % (mod,names[idx],diff)
                else:
                    return "%s!%s" % (mod,names[idx])
        return "unknown"

if __name__ == "__main__":
    try:
        from IPython.frontend.terminal.embed import InteractiveShellEmbed
        ipy = True
    except ImportError:
        import code
        ipy = False

    if len(sys.argv) < 3 or len(sys.argv[1:]) % 2 != 0:
        print >> sys.stderr, "usage: %s <pdb> <base> [[<pdb> <base>] ...]" % sys.argv[0]
        sys.exit(1)

    mods = [ (sys.argv[i],sys.argv[i+1]) for i in range(1,len(sys.argv)-1,2) ]

    lobj = Lookup(mods)
    lookup = lobj.lookup
    
    banner = "Use lookup(addr) to resolve an address to its nearest symbol"
    if ipy:
        shell = InteractiveShellEmbed(banner2=banner)
        shell()
    else:
        code.interact(banner=banner, local=locals())
