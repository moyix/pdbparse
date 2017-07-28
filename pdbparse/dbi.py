#!/usr/bin/env python

# Python 2 and 3
from io import BytesIO

# Python 2 and 3: forward-compatible
from builtins import range 

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
    Const(Bytes("magic", 4), b"\xFF\xFF\xFF\xFF"),                          # 0
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
        IMAGE_FILE_MACHINE_UNKNOWN   = 0x0000,
        IMAGE_FILE_MACHINE_I386      = 0x014c,
        IMAGE_FILE_MACHINE_R3000     = 0x0162,
        IMAGE_FILE_MACHINE_R4000     = 0x0166,
        IMAGE_FILE_MACHINE_R10000    = 0x0168,
        IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169,
        IMAGE_FILE_MACHINE_ALPHA     = 0x0184,
        IMAGE_FILE_MACHINE_SH3       = 0x01a2,
        IMAGE_FILE_MACHINE_SH3DSP    = 0x01a3,
        IMAGE_FILE_MACHINE_SH3E      = 0x01a4,
        IMAGE_FILE_MACHINE_SH4       = 0x01a6,
        IMAGE_FILE_MACHINE_SH5       = 0x01a8,
        IMAGE_FILE_MACHINE_ARM       = 0x01c0,
        IMAGE_FILE_MACHINE_THUMB     = 0x01c2,
        IMAGE_FILE_MACHINE_ARMNT     = 0x01c4,
        IMAGE_FILE_MACHINE_AM33      = 0x01d3,
        IMAGE_FILE_MACHINE_POWERPC   = 0x01f0,
        IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1,
        IMAGE_FILE_MACHINE_IA64      = 0x0200,
        IMAGE_FILE_MACHINE_MIPS16    = 0x0266,
        IMAGE_FILE_MACHINE_ALPHA64   = 0x0284,
        IMAGE_FILE_MACHINE_AXP64     = 0x0284,
        IMAGE_FILE_MACHINE_MIPSFPU   = 0x0366,
        IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466,
        IMAGE_FILE_MACHINE_TRICORE   = 0x0520,
        IMAGE_FILE_MACHINE_CEF       = 0x0cef,
        IMAGE_FILE_MACHINE_EBC       = 0x0ebc,
        IMAGE_FILE_MACHINE_AMD64     = 0x8664,
        IMAGE_FILE_MACHINE_M32R      = 0x9041,
        IMAGE_FILE_MACHINE_CEE       = 0xc0ee,
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
    CString("modName", encoding="utf8"),
    CString("objName", encoding="utf8"),
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

sstFileIndex = Struct("sstFileIndex",
    ULInt16("cMod"),
    ULInt16("cRef"),
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
    #
    # see: http://pierrelib.pagesperso-orange.fr/exec_formats/MS_Symbol_Type_v1.0.pdf
    # the contents of the filinfSize section is a 'sstFileIndex'
    #
    # "File Info"
    end = stream.tell() + dbihdr.filinfSize
    fileIndex = sstFileIndex.parse_stream(stream)
    modStart = Array(fileIndex.cMod, ULInt16("modStart")).parse_stream(stream)
    cRefCnt = Array(fileIndex.cMod, ULInt16("cRefCnt")).parse_stream(stream)
    NameRef = Array(fileIndex.cRef, ULInt32("NameRef")).parse_stream(stream)
    modules = [] # array of arrays of files
    files = [] # array of files (non unique)
    Names = stream.read(end - stream.tell())
    for i in range(0, fileIndex.cMod):
        these = []
        for j in range(modStart[i], modStart[i]+cRefCnt[i]):
            Name = CString("Name", encoding="utf8").parse(Names[NameRef[j]:])
            files.append(Name)
            these.append(Name)
        modules.append(these)

    #stream.seek(dbihdr.filinfSize, 1)
    # "TSM"
    stream.seek(dbihdr.tsmapSize, 1)
    # "EC"
    stream.seek(dbihdr.ecinfoSize, 1)
    # The data we really want
    dbghdr = DbiDbgHeader.parse_stream(stream)
    
    return Container(DBIHeader=dbihdr,
                     DBIExHeaders=ListContainer(dbiexhdrs),
                     DBIDbgHeader=dbghdr,
                     modules=modules,
                     files=files)

def parse(data):
    return parse_stream(BytesIO(data))
