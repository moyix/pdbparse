#!/usr/bin/env python

from construct import *

def SymbolRange(name): 
    return Struct(name,
        ULInt16("segment"),
        Padding(2),
        ULInt32("offset"),
        ULInt32("size"),
        ULInt32("characteristics"),
        ULInt16("index"),
        Padding(2),
        ULInt32("timestamp"),
        ULInt32("unknown"),
    )

DBIHeader = Struct("DBIHeader",
    Const(Bytes("magic", 4), "\xFF\xFF\xFF\xFF"),
    ULInt32("version"),
    ULInt32("unknown"),
    ULInt32("hash1_file"),
    ULInt32("hash2_file"),
    ULInt16("gsym_file"),
    ULInt16("unknown2"),
    ULInt32("module_size"),
    ULInt32("offset_size"),
    ULInt32("hash_size"),
    ULInt32("srcmodule_size"),
    ULInt32("pdbimport_size"),
    Array(5, ULInt32("resvd")),
)

DBIExHeader = Struct("DBIExHeader",
    ULInt32("unknown1"),
    SymbolRange("range"),
    ULInt16("flag"),
    SLInt16("file"),
    ULInt32("symbol_size"),
    ULInt32("lineno_size"),
    ULInt32("unknown2"),
    ULInt32("nSrcFiles"),
    ULInt32("attribute"),
    Array(2, ULInt32("reserved")),
    CString("filename1"),
    Aligned(CString("filename2")),
)

DBI = Debugger(Struct("DBI",
    DBIHeader,
    #GreedyRange(DBIExHeader),
))

def parse_stream(stream):
    return DBI.parse_stream(stream)

def parse(data):
    return DBI.parse(data)
