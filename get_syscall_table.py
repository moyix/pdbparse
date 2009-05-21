#!/usr/bin/env python

import sys
import pdbparse
from struct import unpack
from pdbparse.pe import Sections
from pdbparse.omap import remap,OMAP_ENTRIES
from pefile import PE
from collections import namedtuple

class SyscallTable(object):
    def __init__(self, ServiceTable, ServiceLimit, ArgumentTable):
        self.ServiceTable = ServiceTable
        self.ServiceLimit = ServiceLimit
        self.ArgumentTable = ArgumentTable

names = [
    SyscallTable('_KiServiceTable', '_KiServiceLimit', '_KiArgumentTable'),
    SyscallTable('_W32pServiceTable', '_W32pServiceLimit', '_W32pArgumentTable'),
]

addrs = [
    SyscallTable(0,0,0),
    SyscallTable(0,0,0),
]

values = [
    SyscallTable(0,0,0),
    SyscallTable(0,0,0),
]

pe = PE(sys.argv[1])
pdb = pdbparse.parse(sys.argv[2])
sects = Sections.parse(pdb.streams[10].data)
orig_sects = Sections.parse(pdb.streams[13].data)
gsyms = pdb.streams[pdb.streams[3].gsym_file]
omap = OMAP_ENTRIES.parse(pdb.streams[12].data)
omap_rev = OMAP_ENTRIES.parse(pdb.streams[11].data)

for tbl,addr in zip(names,addrs):
    for sym in gsyms.globals:
        try:
            virt_base = sects[sym.segment-1].VirtualAddress
        except IndexError:
            continue
        off = sym.offset

        if sym.name == tbl.ServiceTable:
            value = remap(off+virt_base,omap)
            addr.ServiceTable = value
            print tbl.ServiceTable,hex(remap(off+virt_base,omap))
        elif sym.name == tbl.ServiceLimit:
            value = remap(off+virt_base,omap)
            addr.ServiceLimit = value
            print tbl.ServiceLimit,hex(value)
        elif sym.name == tbl.ArgumentTable:
            value = remap(off+virt_base,omap)
            addr.ArgumentTable = value
            print tbl.ArgumentTable,hex(value)

for addr,val in zip(addrs,values):
    if not addr.ServiceTable: continue
    limit = unpack("<L", pe.get_data(addr.ServiceLimit,4))[0]
    functions = unpack("<%dL" % limit, pe.get_data(addr.ServiceTable, limit*4))
    functions = [f - pe.OPTIONAL_HEADER.ImageBase for f in functions]
    args = unpack("<%dB" % limit, pe.get_data(addr.ArgumentTable, limit))
    #for i,f,a in zip(range(limit), functions, args):
    #    print i, hex(f), hex(a)
    val.ServiceTable = functions
    val.ServiceLimit = limit
    val.ArgumentTable = args

function_names = {}

for i,val in enumerate(values):
    if not val.ServiceTable: continue
    remapped = [remap(f,omap_rev) for f in val.ServiceTable]
    for sym in gsyms.globals:
        try:
            virt_base = sects[sym.segment-1].VirtualAddress
        except IndexError:
            continue
        off = sym.offset

        for j,f in enumerate(remapped):
            if f == virt_base+off:
                ordinal = i << 12 | j
                function_names[ordinal] = sym.name
                #print "Found %s for function %x" % (sym.name,ordinal)

for i,val in enumerate(values):
    if not val.ServiceTable: continue
    for j in range(val.ServiceLimit):
        ordinal = i << 12 | j
        print "Ordinal %#06x Name: %s Args: %d (%#x bytes) Offset: %#x" % (ordinal, function_names[ordinal],
                                                                       val.ArgumentTable[j] / 4, val.ArgumentTable[j],
                                                                       val.ServiceTable[j])
