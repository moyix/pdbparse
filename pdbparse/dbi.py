#!/usr/bin/env python

from construct import *

_ALIGN = 4

def get_parsed_size(tp,con):
    return len(tp.build(con))

def SymbolRange(name): 
    return Struct(name,
        SLInt16("section"),
        Padding(2),
        SLInt32("offset"),
        SLInt32("size"),
        ULInt32("flags"),
        SLInt16("module"),
        Padding(2),
        ULInt32("dataCRC"),
        ULInt32("relocCRC"),
    )

DBIHeader = Struct("DBIHeader",
    Const(Bytes("magic", 4), "\xFF\xFF\xFF\xFF"),                           # 0
    ULInt32("version"),                                                     # 4
    ULInt32("age"),                                                         # 8
    SLInt16("gssymStream"),                                                 # 12
    ULInt16("vers"),                                                        # 14
    SLInt16("pssymStream"),                                                 # 16
    ULInt16("pdbver"),                                                      # 18
    SLInt16("symrecStream"),           # stream containing global symbols   # 20
    ULInt16("pdbver2"),                                                     # 22
    ULInt32("module_size"),         # total size of DBIExHeaders            # 24
    ULInt32("secconSize"),                                                  # 28
    ULInt32("secmapSize"),                                                  # 32
    ULInt32("filinfSize"),                                                  # 36
    ULInt32("tsmapSize"),                                                   # 40
    ULInt32("mfcIndex"),                                                    # 44
    ULInt32("dbghdrSize"),                                                  # 48
    ULInt32("ecinfoSize"),                                                  # 52
    ULInt16("flags"),                                                       # 56
    Enum(ULInt16("Machine"),                                                # 58
        IMAGE_FILE_MACHINE_I386 = 0x014c,
        IMAGE_FILE_MACHINE_IA64 = 0x0200,
        IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    ),
    ULInt32("resvd"),                                                       # 60
)

DBIExHeader = Struct("DBIExHeader",
    ULInt32("opened"),
    SymbolRange("range"),
    ULInt16("flags"),
    SLInt16("stream"),
    ULInt32("symSize"),
    ULInt32("oldLineSize"),
    ULInt32("lineSize"),
    SLInt16("nSrcFiles"),
    Padding(2),
    ULInt32("offsets"),
    ULInt32("niSource"),
    ULInt32("niCompiler"),
    CString("modName"),
    CString("objName"),
)

DbiDbgHeader = Struct("DbiDbgHeader",
    SLInt16("snFPO"),
    SLInt16("snException"),
    SLInt16("snFixup"),
    SLInt16("snOmapToSrc"),
    SLInt16("snOmapFromSrc"),
    SLInt16("snSectionHdr"),
    SLInt16("snTokenRidMap"),
    SLInt16("snXdata"),
    SLInt16("snPdata"),
    SLInt16("snNewFPO"),
    SLInt16("snSectionHdrOrig"),
)

def parse_stream(stream):
    pos = 0
    dbihdr = DBIHeader.parse_stream(stream)
    pos += get_parsed_size(DBIHeader, dbihdr)
    stream.seek(pos)
    dbiexhdr_data = stream.read(dbihdr.module_size)

    # sizeof() is broken on CStrings for construct, so
    # this ugly ugly hack is necessary
    dbiexhdrs = []
    while dbiexhdr_data:
        dbiexhdrs.append(DBIExHeader.parse(dbiexhdr_data))
        sz = get_parsed_size(DBIExHeader,dbiexhdrs[-1])
        if sz % _ALIGN != 0: sz = sz + (_ALIGN - (sz % _ALIGN))
        dbiexhdr_data = dbiexhdr_data[sz:]
    
    # "Section Contribution"
    stream.seek(dbihdr.secconSize, 1)
    # "Section Map"
    stream.seek(dbihdr.secmapSize, 1)
    # "File Info"
    stream.seek(dbihdr.filinfSize, 1)
    # "TSM"
    stream.seek(dbihdr.tsmapSize, 1)
    # "EC"
    stream.seek(dbihdr.ecinfoSize, 1)
    # The data we really want
    dbghdr = DbiDbgHeader.parse_stream(stream)
    
#      bits.Position += dh.secconSize;
#
#      // Skip the Section Map substream.
#      bits.Position += dh.secmapSize;
#
#      // Skip the File Info substream.
#      bits.Position += dh.filinfSize;
#
#      // Skip the TSM substream.
#      bits.Position += dh.tsmapSize;
#
#      // Skip the EC substream.
#      bits.Position += dh.ecinfoSize;

    return Container(DBIHeader=dbihdr,
                     DBIExHeaders=ListContainer(dbiexhdrs),
                     DBIDbgHeader=dbghdr)

def parse(data):
    return parse_stream(StringIO(data))
