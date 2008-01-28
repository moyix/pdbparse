#!/usr/bin/env python

from construct import *

PESection = Struct("Section",
    String("Name", 8),
    ULInt32("PhysicalAddress"),
    ULInt32("VirtualAddress"),
    ULInt32("SizeOfRawData"),
    ULInt32("PointerToRawData"),
    ULInt32("PointerToRelocations"),
    ULInt32("PointerToLinenumbers"),
    ULInt16("NumberOfRelocations"),
    ULInt16("NumberOfRelocations"),
    ULInt32("Characteristics"),
)

Sections = GreedyRange(PESection)
