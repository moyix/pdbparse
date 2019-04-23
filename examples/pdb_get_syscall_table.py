#!/usr/bin/env python
from __future__ import print_function

import sys
import pdbparse
from struct import unpack
from pdbparse.pe import Sections
from pdbparse.omap import Omap
from pdbparse.undecorate import undecorate
from pefile import PE
from collections import namedtuple


class SyscallTable(object):

    def __init__(self, ServiceTable, ServiceLimit, ArgumentTable):
        self.ServiceTable = ServiceTable
        self.ServiceLimit = ServiceLimit
        self.ArgumentTable = ArgumentTable

    def __repr__(self):
        return "SyscallTable(%s,%s,%s)" % (self.ServiceTable, self.ServiceLimit, self.ArgumentTable)


names = [
    SyscallTable('KiServiceTable', 'KiServiceLimit', 'KiArgumentTable'),
    SyscallTable('W32pServiceTable', 'W32pServiceLimit', 'W32pArgumentTable'),
]

addrs = [
    SyscallTable(0, 0, 0),
    SyscallTable(0, 0, 0),
]

values = [
    SyscallTable(0, 0, 0),
    SyscallTable(0, 0, 0),
]

if len(sys.argv) != 3:
    print("usage: %s <exe> <pdb>" % sys.argv[0], file = sys.stderr)
    sys.exit(1)

pe = PE(sys.argv[1])
pdb = pdbparse.parse(sys.argv[2])
sects = pdb.STREAM_SECT_HDR_ORIG.sections
gsyms = pdb.STREAM_GSYM
omap = pdb.STREAM_OMAP_FROM_SRC
omap_rev = pdb.STREAM_OMAP_TO_SRC

for tbl, addr in zip(names, addrs):
    for sym in gsyms.globals:
        if not hasattr(sym, 'offset'): continue
        try:
            virt_base = sects[sym.segment - 1].VirtualAddress
        except IndexError:
            continue
        off = sym.offset

        if tbl.ServiceTable in sym.name:
            value = omap.remap(off + virt_base)
            addr.ServiceTable = value
            #print tbl.ServiceTable,hex(omap.remap(off+virt_base))
        elif tbl.ServiceLimit in sym.name:
            value = omap.remap(off + virt_base)
            addr.ServiceLimit = value
            #print tbl.ServiceLimit,hex(value)
        elif tbl.ArgumentTable in sym.name:
            value = omap.remap(off + virt_base)
            addr.ArgumentTable = value
            #print tbl.ArgumentTable,hex(value)

for addr, val in zip(addrs, values):
    if not addr.ServiceTable: continue
    limit = unpack("<L", pe.get_data(addr.ServiceLimit, 4))[0]
    functions = unpack("<%dL" % limit, pe.get_data(addr.ServiceTable, limit * 4))
    functions = [f - pe.OPTIONAL_HEADER.ImageBase for f in functions]
    args = unpack("<%dB" % limit, pe.get_data(addr.ArgumentTable, limit))
    #for i,f,a in zip(range(limit), functions, args):
    #    print i, hex(f), hex(a)
    val.ServiceTable = functions
    val.ServiceLimit = limit
    val.ArgumentTable = args

function_names = {}

for i, val in enumerate(values):
    if not val.ServiceTable: continue
    remapped = [omap_rev.remap(f) for f in val.ServiceTable]
    for sym in gsyms.globals:
        if not hasattr(sym, 'offset'): continue
        try:
            virt_base = sects[sym.segment - 1].VirtualAddress
        except IndexError:
            continue
        off = sym.offset

        for j, f in enumerate(remapped):
            if f == virt_base + off:
                ordinal = i << 12 | j
                function_names[ordinal] = sym.name
                #print "Found %s for function %x" % (sym.name,ordinal)

for i, val in enumerate(values):
    if not val.ServiceTable: continue
    for j in range(val.ServiceLimit):
        ordinal = i << 12 | j
        print("Ordinal %#06x Name: %s Args: %d (%#x bytes) Offset: %#x" % (ordinal, undecorate(
            function_names[ordinal])[0], val.ArgumentTable[j] / 4, val.ArgumentTable[j], val.ServiceTable[j]))
