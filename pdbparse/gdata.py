from construct import *
from cStringIO import StringIO
from pdbparse.tpi import merge_subcon

gsym = Struct("global",
    ULInt16("leaf_type"),
    Switch("data", lambda ctx: ctx.leaf_type,
        {
            0x110E : Struct("data_v3",
                ULInt32("symtype"),
                ULInt32("offset"),
                ULInt16("segment"),
                CString("name"),
            ),
        }
    ),
)

GlobalsData = GreedyRange(
    Tunnel(
        PascalString("globals", length_field=ULInt16("len")),
        gsym,
    )
)

def parse(data):
    con = GlobalsData.parse(data)
    for sc in con:
        merge_subcon(sc, "data")
    return con

def parse_stream(stream):
    con = GlobalsData.parse_stream(stream)
    for sc in con:
        merge_subcon(sc, "data")
    return con
