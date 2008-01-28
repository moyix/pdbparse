#!/usr/bin/env python

from construct import *

OMAP_ENTRY = Struct("Omap",
    ULInt32("From"),
    ULInt32("To"),
)

OMAPS = GreedyRange(OMAP_ENTRY)

def remap(address, omap):
    for i in range(len(omap)-1):
        if omap[i].From <= address and omap[i+1].From > address:
            if omap[i].To == 0: return omap[i].To
            else: return omap[i].To + (address - omap[i].From)
