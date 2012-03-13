from construct import *

# FPO DATA
FPO_DATA = Struct("FPO_DATA",
    ULInt32("ulOffStart"),          # offset 1st byte of function code
    ULInt32("cbProcSize"),          # number of bytes in function
    ULInt32("cdwLocals"),           # number of bytes in locals/4
    ULInt16("cdwParams"),           # number of bytes in params/4
    BitStruct("BitValues",
        Octet("cbProlog"),          # number of bytes in prolog
        BitField("cbFrame",2),      # frame type
        Bit("reserved"),            # reserved for future use
        Flag("fUseBP"),             # TRUE if EBP has been allocated
        Flag("fHasSEH"),            # TRUE if SEH in func
        BitField("cbRegs",3),       # number of regs saved
    ),
)

# New style FPO records with program strings
FPO_DATA_V2 = Struct("FPO_DATA_V2",
    ULInt32("ulOffStart"),
    ULInt32("cbProcSize"),
    ULInt32("cbLocals"),
    ULInt32("cbParams"),
    ULInt32("Unk1"),        # always 0
    ULInt32("ProgramStringOffset"),
    ULInt16("cbProlog"),
    ULInt16("cbSavedRegs"),
    ULInt32("Unk2"),        # some kind of flags. 0,1,4,5
)

# Ranges for both types
FPO_DATA_LIST = GreedyRange(FPO_DATA)
FPO_DATA_LIST_V2 = GreedyRange(FPO_DATA_V2)

# Program string storage
# May move this to a new file; in private symbols the values
# include things that are not just FPO related.
FPO_STRING_DATA = Struct("FPO_STRING_DATA",
    Const(Bytes("Signature",4), "\xFE\xEF\xFE\xEF"),
    ULInt32("Unk1"),
    ULInt32("szDataLen"),
    Union("StringData",
        String("Data",lambda ctx: ctx._.szDataLen),
        Tunnel(
            String("Strings",lambda ctx: ctx._.szDataLen),
            GreedyRange(CString("Strings")),
        ),
    ),
    ULInt32("lastDwIndex"), # data remaining = (last_dword_index+1)*4
    HexDumpAdapter(String("UnkData", lambda ctx: ((ctx.lastDwIndex+1)*4))),
    Terminator,
)
