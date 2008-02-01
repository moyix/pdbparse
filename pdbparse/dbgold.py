#!/usr/bin/env python

from construct import *
from pdbparse.pe import IMAGE_SECTION_HEADER
from pdbparse.fpo import FPO_DATA

DebugDirectoryType = Enum(ULInt32("Type"),
    IMAGE_DEBUG_TYPE_UNKNOWN        = 0,
    IMAGE_DEBUG_TYPE_COFF           = 1,
    IMAGE_DEBUG_TYPE_CODEVIEW       = 2,
    IMAGE_DEBUG_TYPE_FPO            = 3,
    IMAGE_DEBUG_TYPE_MISC           = 4,
    IMAGE_DEBUG_TYPE_EXCEPTION      = 5,
    IMAGE_DEBUG_TYPE_FIXUP          = 6,
    IMAGE_DEBUG_TYPE_OMAP_TO_SRC    = 7,
    IMAGE_DEBUG_TYPE_OMAP_FROM_SRC  = 8,
    IMAGE_DEBUG_TYPE_BORLAND        = 9,
    IMAGE_DEBUG_TYPE_RESERVED       = 10,
    _default_ = "IMAGE_DEBUG_TYPE_UNKNOWN",
)

IMAGE_SEPARATE_DEBUG_HEADER = Struct("IMAGE_SEPARATE_DEBUG_HEADER",
    Const(Bytes("Signature", 2), "DI"),
    ULInt16("Flags"),
    ULInt16("Machine"),
    ULInt16("Characteristics"),
    ULInt32("TimeDateStamp"),
    ULInt32("CheckSum"),
    ULInt32("ImageBase"),
    ULInt32("SizeOfImage"),
    ULInt32("NumberOfSections"),
    ULInt32("ExportedNamesSize"),
    ULInt32("DebugDirectorySize"),
    ULInt32("SectionAlignment"),
    Array(2,ULInt32("Reserved")),
)

IMAGE_DEBUG_DIRECTORY = Struct("IMAGE_DEBUG_DIRECTORY",
    ULInt32("Characteristics"),
    ULInt32("TimeDateStamp"),
    ULInt16("MajorVersion"),
    ULInt16("MinorVersion"),
    DebugDirectoryType,
    ULInt32("SizeOfData"),
    ULInt32("AddressOfRawData"),
    ULInt32("PointerToRawData"),
    Pointer(lambda ctx: ctx.PointerToRawData,
        String("Data", lambda ctx: ctx.SizeOfData)
    ),
)

IMAGE_DEBUG_MISC = Struct("IMAGE_DEBUG_MISC",
    ULInt32("DataType"),
    ULInt32("Length"),
    ULInt32("Unicode"),
    Byte("Unicode"),
    Array(3, Byte("Reserved")),
    String("Data", lambda ctx: ctx.Length - 12),
)

IMAGE_FUNCTION_ENTRY = Struct("IMAGE_FUNCTION_ENTRY",
    ULInt32("StartingAddress"),
    ULInt32("EndingAddress"),
    ULInt32("EndOfPrologue"),
)

DbgFile = Struct("DbgFile",
    IMAGE_SEPARATE_DEBUG_HEADER,
    Array(lambda ctx: ctx.IMAGE_SEPARATE_DEBUG_HEADER.NumberOfSections,
        IMAGE_SECTION_HEADER),
    Tunnel(
        String("data",
            lambda ctx: ctx.IMAGE_SEPARATE_DEBUG_HEADER.ExportedNamesSize),
        GreedyRange(CString("ExportedNames")),
    ),
    Array(lambda ctx: ctx.IMAGE_SEPARATE_DEBUG_HEADER.DebugDirectorySize 
                  / IMAGE_DEBUG_DIRECTORY.sizeof(), IMAGE_DEBUG_DIRECTORY)
)
