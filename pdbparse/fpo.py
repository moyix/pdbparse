from construct import *

# FPO DATA
FPO_DATA = "FPO_DATA" / Struct(
    "ulOffStart" / Int32ul,  # offset 1st byte of function code
    "cbProcSize" / Int32ul,  # number of bytes in function
    "cdwLocals" / Int32ul,  # number of bytes in locals/4
    "cdwParams" / Int16ul,  # number of bytes in params/4
    Embedded("BitValues" / BitStruct(
        "cbProlog" / Octet,  # number of bytes in prolog
        "cbFrame" / BitsInteger(2),  # frame type
        "reserved" / Bit,  # reserved for future use
        "fUseBP" / Flag,  # TRUE if EBP has been allocated
        "fHasSEH" / Flag,  # TRUE if SEH in func
        "cbRegs" / BitsInteger(3),  # number of regs saved
    )),
)

# New style FPO records with program strings
FPO_DATA_V2 = "FPO_DATA_V2" / Struct(
    "ulOffStart" / Int32ul,
    "cbProcSize" / Int32ul,
    "cbLocals" / Int32ul,
    "cbParams" / Int32ul,
    "maxStack" / Int32ul,  # so far only observed to be 0
    "ProgramStringOffset" / Int32ul,
    "cbProlog" / Int16ul,
    "cbSavedRegs" / Int16ul,
    "flags" / FlagsEnum(
        Int32ul,
        SEH = 1,
        CPPEH = 2,  # conjectured
        fnStart = 4,
    ),
)

# Ranges for both types
FPO_DATA_LIST = GreedyRange(FPO_DATA)
FPO_DATA_LIST_V2 = GreedyRange(FPO_DATA_V2)

# Program string storage
# May move this to a new file; in private symbols the values
# include things that are not just FPO related.
FPO_STRING_DATA = Struct(
    "FPO_STRING_DATA",
    "Signature" / Const(b"\xFE\xEF\xFE\xEF", Bytes(4)),
    "Unk1" / Int32ul,
    "szDataLen" / Int32ul,
    "StringData" / Union(
        0,
        "Data" / Bytes(lambda ctx: ctx._.szDataLen),
        "Strings" / RestreamData(
            Bytes(lambda ctx: ctx._.szDataLen),
            GreedyRange(CString(encoding = "utf8")),
        ),
    ),
    "lastDwIndex" / Int32ul,  # data remaining = (last_dword_index+1)*4
    "UnkData" / HexDump(Bytes(lambda ctx: ((ctx.lastDwIndex + 1) * 4))),
    Terminated,
)
