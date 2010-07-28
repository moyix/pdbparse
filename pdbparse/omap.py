#!/usr/bin/env python

from construct import *
from bisect import bisect

OMAP_ENTRY = Struct("OmapFromSrc",
    ULInt32("From"),
    ULInt32("To"),
)

OMAP_ENTRIES = GreedyRange(OMAP_ENTRY)

def remap(address, omap):
    froms = [o.From for o in omap]
    #print len(froms)
    pos = bisect(froms, address)
    #print pos
    if froms[pos] != address: pos = pos - 1

    if omap[pos].To == 0: return omap[pos].To
    else: return omap[pos].To + (address - omap[pos].From)
