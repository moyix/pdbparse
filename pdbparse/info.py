from construct import *
from cStringIO import StringIO

_strarray = GreedyRange(CString("names"))

class StringArrayAdapter(Adapter):
    def _encode(self,obj,context):
        return _strarray._build(StringIO(obj),context)
    def _decode(self,obj,context):
        return _strarray._parse(StringIO(obj),context)

def GUID(name):
    return Struct(name,
        ULInt32("Data1"),
        ULInt16("Data2"),
        ULInt16("Data3"),
        String("Data4", 8),
    )

Info = Struct("Info",
    ULInt32("Version"),
    ULInt32("TimeDateStamp"),
    ULInt32("Age"),
    GUID("GUID"),
    ULInt32("cbNames"),
    StringArrayAdapter(MetaField("names", lambda ctx: ctx.cbNames)),
)

def parse_stream(stream):
    return Info.parse_stream(stream)

def parse(data):
    return Info.parse(data)

