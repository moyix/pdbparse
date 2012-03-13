#!/usr/bin/env python

from construct import *
from pdbparse.pe import IMAGE_SECTION_HEADER
from pdbparse.fpo import FPO_DATA
from pdbparse.info import GUID

CV_RSDS_HEADER = Struct("CV_RSDS",
    Const(Bytes("Signature", 4), "RSDS"),
    GUID("GUID"),
    ULInt32("Age"),
    CString("Filename"),
)

CV_NB10_HEADER = Struct("CV_NB10",
    Const(Bytes("Signature", 4), "NB10"),
    ULInt32("Offset"),
    ULInt32("Timestamp"),
    ULInt32("Age"),
    CString("Filename"),
)

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

DebugMiscType = Enum(ULInt32("Type"),
    IMAGE_DEBUG_MISC_EXENAME        = 1,
    _default_ = Pass,
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
    DebugMiscType,
    ULInt32("Length"),
    Byte("Unicode"),
    Array(3, Byte("Reserved")),
    Tunnel(
        String("Strings", lambda ctx: ctx.Length - 12),
        GreedyRange(CString("Strings")),
    ),
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
