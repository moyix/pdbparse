#!/usr/bin/env python

from construct import *
from bisect import bisect

OMAP_FROM_SRC_ENTRY = Struct("OmapFromSrc",
    ULInt32("From"),
    ULInt32("To"),
)

OMAP_TO_SRC_ENTRY = Struct("OmapToSrc",
    ULInt32("To"),
    ULInt32("From"),
)

OMAP_FROM_SRC = GreedyRange(OMAP_FROM_SRC_ENTRY)
OMAP_TO_SRC = GreedyRange(OMAP_TO_SRC_ENTRY)

def remap(address, omap):
    froms = [o.From for o in omap]
    pos = bisect(froms, address)
    if froms[pos] != address: pos = pos - 1

    if omap[pos].To == 0: return omap[pos].To
    else: return omap[pos].To + (address - omap[pos].From)
