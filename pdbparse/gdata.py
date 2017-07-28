# Python 2 and 3
from io import BytesIO

from construct import *
from pdbparse.tpi import merge_subcon

gsym = Struct("global",
    ULInt16("leaf_type"),
    Embed(Switch("data", lambda ctx: ctx.leaf_type,
        {
            0x110E : Struct("data_v3",
                ULInt32("symtype"),
                ULInt32("offset"),
                ULInt16("segment"),
                CString("name", encoding="utf8"),
            
            ),
            0x1009 : Struct("data_v2",
                ULInt32("symtype"),
                ULInt32("offset"),
                ULInt16("segment"),
                PascalString("name", length_field=ULInt8("len")),
            ),
        },
        default = Pass,
    ))
)

GlobalsData = OptionalGreedyRange(
    Tunnel(
        PascalString("globals", length_field=ULInt16("len")),
        gsym,
    )
)

def parse(data):
    con = GlobalsData.parse(data)
    return con

def parse_stream(stream):
    con = GlobalsData.parse_stream(stream)
    return con
