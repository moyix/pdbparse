#!/usr/bin/env python

from construct import *

_ALIGN = 4

def get_parsed_size(tp,con):
    return len(tp.build(con))

def SymbolRange(name): 
    return Struct(name,
        SLInt16("segment"),
        Padding(2),
        ULInt32("offset"),
        SLInt32("size"),
        ULInt32("characteristics"),
        SLInt16("index"),
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
    ULInt16("gsym_file"),           # stream containing global symbols
    ULInt16("unknown2"),
    ULInt32("module_size"),         # total size of DBIExHeaders
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
    Array(2,
        CString("filenames"),
    ),
)

DBI = Debugger(Struct("DBI",
    DBIHeader,
))

def parse_stream(stream):
    pos = 0
    dbihdr = DBIHeader.parse_stream(stream)
    pos += get_parsed_size(DBIHeader, dbihdr)
    stream.seek(pos)
    dbiexhdr_data = stream.read(dbihdr.module_size)

    dbiexhdrs = []
    while dbiexhdr_data:
        dbiexhdrs.append(DBIExHeader.parse(dbiexhdr_data))
        sz = get_parsed_size(DBIExHeader,dbiexhdrs[-1])
        if sz % _ALIGN != 0: sz = sz + (_ALIGN - (sz % _ALIGN))
        dbiexhdr_data = dbiexhdr_data[sz:]
    print stream.tell()
    return Container(DBIHeader = dbihdr, DBIExHeaders = ListContainer(dbiexhdrs))

def parse(data):
    return parse_stream(StringIO(data))
