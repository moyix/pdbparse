# Python 2 and 3

from construct import *

gsym = "global" / Struct(
    "leaf_type" / Int16ul, "data" / Switch(
        lambda ctx: ctx.leaf_type, {
            0x110E:
            "data_v3" / Struct(
                "symtype" / Int32ul,
                "offset" / Int32ul,
                "segment" / Int16ul,
                "name" / CString(encoding = "utf8"),
            ),
            0x1009:
            "data_v2" / Struct(
                "symtype" / Int32ul,
                "offset" / Int32ul,
                "segment" / Int16ul,
                "name" / PascalString(lengthfield = "len" / Int8ul, encoding = "utf8"),
            ),
        }))

GlobalsData = GreedyRange(
    RestreamData(
        "globals" / PascalString(lengthfield = "len" / Int16ul, encoding = "utf8"),
        gsym,
    ))


def parse(data):
    con = GlobalsData.parse(data)
    return con


def parse_stream(stream):
    con = GlobalsData.parse_stream(stream)
    return con
