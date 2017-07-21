#!/usr/bin/env python

from construct import *

IMAGE_SECTION_HEADER = Struct("IMAGE_SECTION_HEADER",
    String("Name", 8),
    Union("Misc",
        ULInt32("PhysicalAddress"),
        ULInt32("VirtualSize"),
    ),
    ULInt32("VirtualAddress"),
    ULInt32("SizeOfRawData"),
    ULInt32("PointerToRawData"),
    ULInt32("PointerToRelocations"),
    ULInt32("PointerToLinenumbers"),
    ULInt16("NumberOfRelocations"),
    ULInt16("NumberOfLinenumbers"),
    ULInt32("Characteristics"),
)

Sections = OptionalGreedyRange(IMAGE_SECTION_HEADER)
