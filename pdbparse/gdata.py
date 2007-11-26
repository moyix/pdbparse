from construct import *
from cStringIO import StringIO
from pdbparse.tpi import merge_subcon

_gsym = Struct("global",
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

class GDataAdapter(Adapter):
    def _encode(self,obj,context):
        return _gsym._build(StringIO(obj),context)
    def _decode(self,obj,context):
        con = _gsym._parse(StringIO(obj),context)
        merge_subcon(con, "data")
        return con

GlobalsData = GreedyRange(GDataAdapter(PascalString("globals", length_field=ULInt16("len"))))

def parse(data):
    return GlobalsData.parse(data)

def parse_stream(stream):
    return GlobalsData.parse_stream(stream)
