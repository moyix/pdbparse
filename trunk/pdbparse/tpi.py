#!/usr/bin/env python

from construct import *
from cStringIO import StringIO

# For each metatype, which attributes are references
# to another type
type_refs = {
    "LF_ARGLIST": ["arg_type"],
    "LF_ARRAY": ["element_type", "index_type"],
    "LF_ARRAY_ST": ["element_type", "index_type"],
    "LF_BITFIELD": ["base_type"],
    "LF_CLASS": ["fieldlist", "derived", "vshape"],
    "LF_ENUM": ["utype", "fieldlist"],
    "LF_FIELDLIST": [],
    "LF_MFUNC": ["return_type", "class_type", "this_type", "arglist"],
    "LF_MODIFIER": ["modified_type"],
    "LF_POINTER": ["utype"],
    "LF_PROCEDURE": ["return_type", "arglist"],
    "LF_STRUCTURE": ["fieldlist", "derived", "vshape"],
    "LF_STRUCTURE_ST": ["fieldlist", "derived", "vshape"],
    "LF_UNION": ["fieldlist"],
    "LF_UNION_ST": ["fieldlist"],
    "LF_VTSHAPE": [],

    # FIELDLIST substructures
    "LF_BCLASS": ["index"],
    "LF_ENUMERATE": [],
    "LF_MEMBER": ["index"],
    "LF_MEMBER_ST": ["index"],
    "LF_METHOD": ["mlist"],
    "LF_NESTTYPE": ["index"],
    "LF_ONEMETHOD": ["index"],
    "LF_VFUNCTAB": ["type"],
}

### Enums for base and leaf types
# Note: python only supports a max of 255 arguments to
# a function, so we have to put it into a dict and then
# call the function with the ** operator
base_types = {
    'T_NOTYPE'                : 0x00000000,
    'T_ABS'                   : 0x00000001,
    'T_SEGMENT'               : 0x00000002,
    'T_VOID'                  : 0x00000003,

    'T_HRESULT'               : 0x00000008,
    'T_32PHRESULT'            : 0x00000408,
    'T_64PHRESULT'            : 0x00000608,

    'T_PVOID'                 : 0x00000103,
    'T_PFVOID'                : 0x00000203,
    'T_PHVOID'                : 0x00000303,
    'T_32PVOID'               : 0x00000403,
    'T_32PFVOID'              : 0x00000503,
    'T_64PVOID'               : 0x00000603,

    'T_CURRENCY'              : 0x00000004,
    'T_NBASICSTR'             : 0x00000005,
    'T_FBASICSTR'             : 0x00000006,
    'T_NOTTRANS'              : 0x00000007,
    'T_BIT'                   : 0x00000060,
    'T_PASCHAR'               : 0x00000061,

    'T_CHAR'                  : 0x00000010,
    'T_PCHAR'                 : 0x00000110,
    'T_PFCHAR'                : 0x00000210,
    'T_PHCHAR'                : 0x00000310,
    'T_32PCHAR'               : 0x00000410,
    'T_32PFCHAR'              : 0x00000510,
    'T_64PCHAR'               : 0x00000610,

    'T_UCHAR'                 : 0x00000020,
    'T_PUCHAR'                : 0x00000120,
    'T_PFUCHAR'               : 0x00000220,
    'T_PHUCHAR'               : 0x00000320,
    'T_32PUCHAR'              : 0x00000420,
    'T_32PFUCHAR'             : 0x00000520,
    'T_64PUCHAR'              : 0x00000620,

    'T_RCHAR'                 : 0x00000070,
    'T_PRCHAR'                : 0x00000170,
    'T_PFRCHAR'               : 0x00000270,
    'T_PHRCHAR'               : 0x00000370,
    'T_32PRCHAR'              : 0x00000470,
    'T_32PFRCHAR'             : 0x00000570,
    'T_64PRCHAR'              : 0x00000670,

    'T_WCHAR'                 : 0x00000071,
    'T_PWCHAR'                : 0x00000171,
    'T_PFWCHAR'               : 0x00000271,
    'T_PHWCHAR'               : 0x00000371,
    'T_32PWCHAR'              : 0x00000471,
    'T_32PFWCHAR'             : 0x00000571,
    'T_64PWCHAR'              : 0x00000671,

    'T_INT1'                  : 0x00000068,
    'T_PINT1'                 : 0x00000168,
    'T_PFINT1'                : 0x00000268,
    'T_PHINT1'                : 0x00000368,
    'T_32PINT1'               : 0x00000468,
    'T_32PFINT1'              : 0x00000568,
    'T_64PINT1'               : 0x00000668,

    'T_UINT1'                 : 0x00000069,
    'T_PUINT1'                : 0x00000169,
    'T_PFUINT1'               : 0x00000269,
    'T_PHUINT1'               : 0x00000369,
    'T_32PUINT1'              : 0x00000469,
    'T_32PFUINT1'             : 0x00000569,
    'T_64PUINT1'              : 0x00000669,

    'T_SHORT'                 : 0x00000011,
    'T_PSHORT'                : 0x00000111,
    'T_PFSHORT'               : 0x00000211,
    'T_PHSHORT'               : 0x00000311,
    'T_32PSHORT'              : 0x00000411,
    'T_32PFSHORT'             : 0x00000511,
    'T_64PSHORT'              : 0x00000611,

    'T_USHORT'                : 0x00000021,
    'T_PUSHORT'               : 0x00000121,
    'T_PFUSHORT'              : 0x00000221,
    'T_PHUSHORT'              : 0x00000321,
    'T_32PUSHORT'             : 0x00000421,
    'T_32PFUSHORT'            : 0x00000521,
    'T_64PUSHORT'             : 0x00000621,

    'T_INT2'                  : 0x00000072,
    'T_PINT2'                 : 0x00000172,
    'T_PFINT2'                : 0x00000272,
    'T_PHINT2'                : 0x00000372,
    'T_32PINT2'               : 0x00000472,
    'T_32PFINT2'              : 0x00000572,
    'T_64PINT2'               : 0x00000672,

    'T_UINT2'                 : 0x00000073,
    'T_PUINT2'                : 0x00000173,
    'T_PFUINT2'               : 0x00000273,
    'T_PHUINT2'               : 0x00000373,
    'T_32PUINT2'              : 0x00000473,
    'T_32PFUINT2'             : 0x00000573,
    'T_64PUINT2'              : 0x00000673,

    'T_LONG'                  : 0x00000012,
    'T_PLONG'                 : 0x00000112,
    'T_PFLONG'                : 0x00000212,
    'T_PHLONG'                : 0x00000312,
    'T_32PLONG'               : 0x00000412,
    'T_32PFLONG'              : 0x00000512,
    'T_64PLONG'               : 0x00000612,

    'T_ULONG'                 : 0x00000022,
    'T_PULONG'                : 0x00000122,
    'T_PFULONG'               : 0x00000222,
    'T_PHULONG'               : 0x00000322,
    'T_32PULONG'              : 0x00000422,
    'T_32PFULONG'             : 0x00000522,
    'T_64PULONG'              : 0x00000622,

    'T_INT4'                  : 0x00000074,
    'T_PINT4'                 : 0x00000174,
    'T_PFINT4'                : 0x00000274,
    'T_PHINT4'                : 0x00000374,
    'T_32PINT4'               : 0x00000474,
    'T_32PFINT4'              : 0x00000574,
    'T_64PINT4'               : 0x00000674,

    'T_UINT4'                 : 0x00000075,
    'T_PUINT4'                : 0x00000175,
    'T_PFUINT4'               : 0x00000275,
    'T_PHUINT4'               : 0x00000375,
    'T_32PUINT4'              : 0x00000475,
    'T_32PFUINT4'             : 0x00000575,
    'T_64PUINT4'              : 0x00000675,

    'T_QUAD'                  : 0x00000013,
    'T_PQUAD'                 : 0x00000113,
    'T_PFQUAD'                : 0x00000213,
    'T_PHQUAD'                : 0x00000313,
    'T_32PQUAD'               : 0x00000413,
    'T_32PFQUAD'              : 0x00000513,
    'T_64PQUAD'               : 0x00000613,

    'T_UQUAD'                 : 0x00000023,
    'T_PUQUAD'                : 0x00000123,
    'T_PFUQUAD'               : 0x00000223,
    'T_PHUQUAD'               : 0x00000323,
    'T_32PUQUAD'              : 0x00000423,
    'T_32PFUQUAD'             : 0x00000523,
    'T_64PUQUAD'              : 0x00000623,

    'T_INT8'                  : 0x00000076,
    'T_PINT8'                 : 0x00000176,
    'T_PFINT8'                : 0x00000276,
    'T_PHINT8'                : 0x00000376,
    'T_32PINT8'               : 0x00000476,
    'T_32PFINT8'              : 0x00000576,
    'T_64PINT8'               : 0x00000676,

    'T_UINT8'                 : 0x00000077,
    'T_PUINT8'                : 0x00000177,
    'T_PFUINT8'               : 0x00000277,
    'T_PHUINT8'               : 0x00000377,
    'T_32PUINT8'              : 0x00000477,
    'T_32PFUINT8'             : 0x00000577,
    'T_64PUINT8'              : 0x00000677,

    'T_OCT'                   : 0x00000014,
    'T_POCT'                  : 0x00000114,
    'T_PFOCT'                 : 0x00000214,
    'T_PHOCT'                 : 0x00000314,
    'T_32POCT'                : 0x00000414,
    'T_32PFOCT'               : 0x00000514,
    'T_64POCT'                : 0x00000614,

    'T_UOCT'                  : 0x00000024,
    'T_PUOCT'                 : 0x00000124,
    'T_PFUOCT'                : 0x00000224,
    'T_PHUOCT'                : 0x00000324,
    'T_32PUOCT'               : 0x00000424,
    'T_32PFUOCT'              : 0x00000524,
    'T_64PUOCT'               : 0x00000624,

    'T_INT16'                 : 0x00000078,
    'T_PINT16'                : 0x00000178,
    'T_PFINT16'               : 0x00000278,
    'T_PHINT16'               : 0x00000378,
    'T_32PINT16'              : 0x00000478,
    'T_32PFINT16'             : 0x00000578,
    'T_64PINT16'              : 0x00000678,

    'T_UINT16'                : 0x00000079,
    'T_PUINT16'               : 0x00000179,
    'T_PFUINT16'              : 0x00000279,
    'T_PHUINT16'              : 0x00000379,
    'T_32PUINT16'             : 0x00000479,
    'T_32PFUINT16'            : 0x00000579,
    'T_64PUINT16'             : 0x00000679,

    'T_REAL32'                : 0x00000040,
    'T_PREAL32'               : 0x00000140,
    'T_PFREAL32'              : 0x00000240,
    'T_PHREAL32'              : 0x00000340,
    'T_32PREAL32'             : 0x00000440,
    'T_32PFREAL32'            : 0x00000540,
    'T_64PREAL32'             : 0x00000640,

    'T_REAL48'                : 0x00000044,
    'T_PREAL48'               : 0x00000144,
    'T_PFREAL48'              : 0x00000244,
    'T_PHREAL48'              : 0x00000344,
    'T_32PREAL48'             : 0x00000444,
    'T_32PFREAL48'            : 0x00000544,
    'T_64PREAL48'             : 0x00000644,

    'T_REAL64'                : 0x00000041,
    'T_PREAL64'               : 0x00000141,
    'T_PFREAL64'              : 0x00000241,
    'T_PHREAL64'              : 0x00000341,
    'T_32PREAL64'             : 0x00000441,
    'T_32PFREAL64'            : 0x00000541,
    'T_64PREAL64'             : 0x00000641,

    'T_REAL80'                : 0x00000042,
    'T_PREAL80'               : 0x00000142,
    'T_PFREAL80'              : 0x00000242,
    'T_PHREAL80'              : 0x00000342,
    'T_32PREAL80'             : 0x00000442,
    'T_32PFREAL80'            : 0x00000542,
    'T_64PREAL80'             : 0x00000642,

    'T_REAL128'               : 0x00000043,
    'T_PREAL128'              : 0x00000143,
    'T_PFREAL128'             : 0x00000243,
    'T_PHREAL128'             : 0x00000343,
    'T_32PREAL128'            : 0x00000443,
    'T_32PFREAL128'           : 0x00000543,
    'T_64PREAL128'            : 0x00000643,

    'T_CPLX32'                : 0x00000050,
    'T_PCPLX32'               : 0x00000150,
    'T_PFCPLX32'              : 0x00000250,
    'T_PHCPLX32'              : 0x00000350,
    'T_32PCPLX32'             : 0x00000450,
    'T_32PFCPLX32'            : 0x00000550,
    'T_64PCPLX32'             : 0x00000650,

    'T_CPLX64'                : 0x00000051,
    'T_PCPLX64'               : 0x00000151,
    'T_PFCPLX64'              : 0x00000251,
    'T_PHCPLX64'              : 0x00000351,
    'T_32PCPLX64'             : 0x00000451,
    'T_32PFCPLX64'            : 0x00000551,
    'T_64PCPLX64'             : 0x00000651,

    'T_CPLX80'                : 0x00000052,
    'T_PCPLX80'               : 0x00000152,
    'T_PFCPLX80'              : 0x00000252,
    'T_PHCPLX80'              : 0x00000352,
    'T_32PCPLX80'             : 0x00000452,
    'T_32PFCPLX80'            : 0x00000552,
    'T_64PCPLX80'             : 0x00000652,

    'T_CPLX128'               : 0x00000053,
    'T_PCPLX128'              : 0x00000153,
    'T_PFCPLX128'             : 0x00000253,
    'T_PHCPLX128'             : 0x00000353,
    'T_32PCPLX128'            : 0x00000453,
    'T_32PFCPLX128'           : 0x00000553,
    'T_64PCPLX128'            : 0x00000653,

    'T_BOOL08'                : 0x00000030,
    'T_PBOOL08'               : 0x00000130,
    'T_PFBOOL08'              : 0x00000230,
    'T_PHBOOL08'              : 0x00000330,
    'T_32PBOOL08'             : 0x00000430,
    'T_32PFBOOL08'            : 0x00000530,
    'T_64PBOOL08'             : 0x00000630,

    'T_BOOL16'                : 0x00000031,
    'T_PBOOL16'               : 0x00000131,
    'T_PFBOOL16'              : 0x00000231,
    'T_PHBOOL16'              : 0x00000331,
    'T_32PBOOL16'             : 0x00000431,
    'T_32PFBOOL16'            : 0x00000531,
    'T_64PBOOL16'             : 0x00000631,

    'T_BOOL32'                : 0x00000032,
    'T_PBOOL32'               : 0x00000132,
    'T_PFBOOL32'              : 0x00000232,
    'T_PHBOOL32'              : 0x00000332,
    'T_32PBOOL32'             : 0x00000432,
    'T_32PFBOOL32'            : 0x00000532,
    'T_64PBOOL32'             : 0x00000632,

    'T_BOOL64'                : 0x00000033,
    'T_PBOOL64'               : 0x00000133,
    'T_PFBOOL64'              : 0x00000233,
    'T_PHBOOL64'              : 0x00000333,
    'T_32PBOOL64'             : 0x00000433,
    'T_32PFBOOL64'            : 0x00000533,
    'T_64PBOOL64'             : 0x00000633,

    'T_NCVPTR'                : 0x000001F0,
    'T_FCVPTR'                : 0x000002F0,
    'T_HCVPTR'                : 0x000003F0,
    'T_32NCVPTR'              : 0x000004F0,
    'T_32FCVPTR'              : 0x000005F0,
    'T_64NCVPTR'              : 0x000006F0,
}

base_type = Enum(ULInt16("base_type"), **base_types)

# Fewer than 255 values so we're ok here
leaf_type = Enum(ULInt16("leaf_type"),
    LF_MODIFIER_16t         = 0x00000001,
    LF_POINTER_16t          = 0x00000002,
    LF_ARRAY_16t            = 0x00000003,
    LF_CLASS_16t            = 0x00000004,
    LF_STRUCTURE_16t        = 0x00000005,
    LF_UNION_16t            = 0x00000006,
    LF_ENUM_16t             = 0x00000007,
    LF_PROCEDURE_16t        = 0x00000008,
    LF_MFUNCTION_16t        = 0x00000009,
    LF_VTSHAPE              = 0x0000000A,
    LF_COBOL0_16t           = 0x0000000B,
    LF_COBOL1               = 0x0000000C,
    LF_BARRAY_16t           = 0x0000000D,
    LF_LABEL                = 0x0000000E,
    LF_NULL                 = 0x0000000F,
    LF_NOTTRAN              = 0x00000010,
    LF_DIMARRAY_16t         = 0x00000011,
    LF_VFTPATH_16t          = 0x00000012,
    LF_PRECOMP_16t          = 0x00000013,
    LF_ENDPRECOMP           = 0x00000014,
    LF_OEM_16t              = 0x00000015,
    LF_TYPESERVER_ST        = 0x00000016,
    LF_SKIP_16t             = 0x00000200,
    LF_ARGLIST_16t          = 0x00000201,
    LF_DEFARG_16t           = 0x00000202,
    LF_LIST                 = 0x00000203,
    LF_FIELDLIST_16t        = 0x00000204,
    LF_DERIVED_16t          = 0x00000205,
    LF_BITFIELD_16t         = 0x00000206,
    LF_METHODLIST_16t       = 0x00000207,
    LF_DIMCONU_16t          = 0x00000208,
    LF_DIMCONLU_16t         = 0x00000209,
    LF_DIMVARU_16t          = 0x0000020A,
    LF_DIMVARLU_16t         = 0x0000020B,
    LF_REFSYM               = 0x0000020C,
    LF_BCLASS_16t           = 0x00000400,
    LF_VBCLASS_16t          = 0x00000401,
    LF_IVBCLASS_16t         = 0x00000402,
    LF_ENUMERATE_ST         = 0x00000403,
    LF_FRIENDFCN_16t        = 0x00000404,
    LF_INDEX_16t            = 0x00000405,
    LF_MEMBER_16t           = 0x00000406,
    LF_STMEMBER_16t         = 0x00000407,
    LF_METHOD_16t           = 0x00000408,
    LF_NESTTYPE_16t         = 0x00000409,
    LF_VFUNCTAB_16t         = 0x0000040A,
    LF_FRIENDCLS_16t        = 0x0000040B,
    LF_ONEMETHOD_16t        = 0x0000040C,
    LF_VFUNCOFF_16t         = 0x0000040D,
    LF_TI16_MAX             = 0x00001000,
    LF_MODIFIER             = 0x00001001,
    LF_POINTER              = 0x00001002,
    LF_ARRAY_ST             = 0x00001003,
    LF_CLASS_ST             = 0x00001004,
    LF_STRUCTURE_ST         = 0x00001005,
    LF_UNION_ST             = 0x00001006,
    LF_ENUM_ST              = 0x00001007,
    LF_PROCEDURE            = 0x00001008,
    LF_MFUNCTION            = 0x00001009,
    LF_COBOL0               = 0x0000100A,
    LF_BARRAY               = 0x0000100B,
    LF_DIMARRAY_ST          = 0x0000100C,
    LF_VFTPATH              = 0x0000100D,
    LF_PRECOMP_ST           = 0x0000100E,
    LF_OEM                  = 0x0000100F,
    LF_ALIAS_ST             = 0x00001010,
    LF_OEM2                 = 0x00001011,
    LF_SKIP                 = 0x00001200,
    LF_ARGLIST              = 0x00001201,
    LF_DEFARG_ST            = 0x00001202,
    LF_FIELDLIST            = 0x00001203,
    LF_DERIVED              = 0x00001204,
    LF_BITFIELD             = 0x00001205,
    LF_METHODLIST           = 0x00001206,
    LF_DIMCONU              = 0x00001207,
    LF_DIMCONLU             = 0x00001208,
    LF_DIMVARU              = 0x00001209,
    LF_DIMVARLU             = 0x0000120A,
    LF_BCLASS               = 0x00001400,
    LF_VBCLASS              = 0x00001401,
    LF_IVBCLASS             = 0x00001402,
    LF_FRIENDFCN_ST         = 0x00001403,
    LF_INDEX                = 0x00001404,
    LF_MEMBER_ST            = 0x00001405,
    LF_STMEMBER_ST          = 0x00001406,
    LF_METHOD_ST            = 0x00001407,
    LF_NESTTYPE_ST          = 0x00001408,
    LF_VFUNCTAB             = 0x00001409,
    LF_FRIENDCLS            = 0x0000140A,
    LF_ONEMETHOD_ST         = 0x0000140B,
    LF_VFUNCOFF             = 0x0000140C,
    LF_NESTTYPEEX_ST        = 0x0000140D,
    LF_MEMBERMODIFY_ST      = 0x0000140E,
    LF_MANAGED_ST           = 0x0000140F,
    LF_ST_MAX               = 0x00001500,
    LF_TYPESERVER           = 0x00001501,
    LF_ENUMERATE            = 0x00001502,
    LF_ARRAY                = 0x00001503,
    LF_CLASS                = 0x00001504,
    LF_STRUCTURE            = 0x00001505,
    LF_UNION                = 0x00001506,
    LF_ENUM                 = 0x00001507,
    LF_DIMARRAY             = 0x00001508,
    LF_PRECOMP              = 0x00001509,
    LF_ALIAS                = 0x0000150A,
    LF_DEFARG               = 0x0000150B,
    LF_FRIENDFCN            = 0x0000150C,
    LF_MEMBER               = 0x0000150D,
    LF_STMEMBER             = 0x0000150E,
    LF_METHOD               = 0x0000150F,
    LF_NESTTYPE             = 0x00001510,
    LF_ONEMETHOD            = 0x00001511,
    LF_NESTTYPEEX           = 0x00001512,
    LF_MEMBERMODIFY         = 0x00001513,
    LF_MANAGED              = 0x00001514,
    LF_TYPESERVER2          = 0x00001515,
    LF_CHAR                 = 0x00008000,
    LF_SHORT                = 0x00008001,
    LF_USHORT               = 0x00008002,
    LF_LONG                 = 0x00008003,
    LF_ULONG                = 0x00008004,
    LF_REAL32               = 0x00008005,
    LF_REAL64               = 0x00008006,
    LF_REAL80               = 0x00008007,
    LF_REAL128              = 0x00008008,
    LF_QUADWORD             = 0x00008009,
    LF_UQUADWORD            = 0x0000800A,
    LF_REAL48               = 0x0000800B,
    LF_COMPLEX32            = 0x0000800C,
    LF_COMPLEX64            = 0x0000800D,
    LF_COMPLEX80            = 0x0000800E,
    LF_COMPLEX128           = 0x0000800F,
    LF_VARSTRING            = 0x00008010,
    LF_OCTWORD              = 0x00008017,
    LF_UOCTWORD             = 0x00008018,
    LF_DECIMAL              = 0x00008019,
    LF_DATE                 = 0x0000801A,
    LF_UTF8STRING           = 0x0000801B,
    LF_PAD0                 = 0x000000F0,
    LF_PAD1                 = 0x000000F1,
    LF_PAD2                 = 0x000000F2,
    LF_PAD3                 = 0x000000F3,
    LF_PAD4                 = 0x000000F4,
    LF_PAD5                 = 0x000000F5,
    LF_PAD6                 = 0x000000F6,
    LF_PAD7                 = 0x000000F7,
    LF_PAD8                 = 0x000000F8,
    LF_PAD9                 = 0x000000F9,
    LF_PAD10                = 0x000000FA,
    LF_PAD11                = 0x000000FB,
    LF_PAD12                = 0x000000FC,
    LF_PAD13                = 0x000000FD,
    LF_PAD14                = 0x000000FE,
    LF_PAD15                = 0x000000FF
)

### CodeView bitfields and enums
# NOTE: Construct assumes big-endian
# ordering for BitStructs
CV_fldattr = BitStruct("fldattr",
    Flag("noconstruct"),
    Flag("noinherit"),
    Flag("pseudo"),
    Enum(BitField("mprop", 3),
        MTvanilla   = 0x00,
        MTvirtual   = 0x01,
        MTstatic    = 0x02,
        MTfriend    = 0x03,
        MTintro     = 0x04,
        MTpurevirt  = 0x05,
        MTpureintro = 0x06,
        _default_   = Pass,
    ),
    Enum(BitField("access", 2),
        private    = 1,
        protected  = 2,
        public     = 3,
        _default_  = Pass,
    ),

    Padding(7),
    Flag("compgenx"),
)

CV_call = Enum(ULInt8("call_conv"),
    NEAR_C          = 0x00000000,
    FAR_C           = 0x00000001,
    NEAR_PASCAL     = 0x00000002,
    FAR_PASCAL      = 0x00000003,
    NEAR_FAST       = 0x00000004,
    FAR_FAST        = 0x00000005,
    SKIPPED         = 0x00000006,
    NEAR_STD        = 0x00000007,
    FAR_STD         = 0x00000008,
    NEAR_SYS        = 0x00000009,
    FAR_SYS         = 0x0000000A,
    THISCALL        = 0x0000000B,
    MIPSCALL        = 0x0000000C,
    GENERIC         = 0x0000000D,
    ALPHACALL       = 0x0000000E,
    PPCCALL         = 0x0000000F,
    SHCALL          = 0x00000010,
    ARMCALL         = 0x00000011,
    AM33CALL        = 0x00000012,
    TRICALL         = 0x00000013,
    SH5CALL         = 0x00000014,
    M32RCALL        = 0x00000015,
    RESERVED        = 0x00000016,
    _default_       = Pass,
)

CV_property = BitStruct("prop",
    Flag("fwdref"),
    Flag("opcast"),
    Flag("opassign"),
    Flag("cnested"),
    Flag("isnested"),
    Flag("ovlops"),
    Flag("ctor"),
    Flag("packed"),

    BitField("reserved", 7, swapped=True),
    Flag("scoped"),
)

def val(name):
    return Struct("value",
        Value("_value_name", lambda ctx: name),
        ULInt16("value_or_type"),
        IfThenElse("name_or_val", lambda ctx: ctx.value_or_type < leaf_type._encode("LF_CHAR",ctx),
            CString("name"),
            Switch("val", lambda ctx: leaf_type._decode(ctx.value_or_type, {}),
                {
                    "LF_CHAR": Struct("char",
                        String("value", 1),
                        CString("name"),
                    ),
                    "LF_SHORT": Struct("short",
                        SLInt16("value"),
                        CString("name"),
                    ),
                    "LF_USHORT": Struct("ushort",
                        ULInt16("value"),
                        CString("name"),
                    ),
                    "LF_LONG": Struct("char",
                        SLInt32("value"),
                        CString("name"),
                    ),
                    "LF_ULONG": Struct("char",
                        ULInt32("value"),
                        CString("name"),
                    ),
                },
            ),
        ),
    )

PadAlign = If(lambda ctx: ctx._pad > 0xF0,
    Optional(Padding(lambda ctx: ctx._pad & 0x0F))
)

### Leaf types
subStruct = Struct("substructs",
    leaf_type,
    Switch("type_info", lambda ctx: ctx.leaf_type,
        {
            "LF_MEMBER_ST": Struct("lfMemberST",
                CV_fldattr,
                ULInt32("index"),
                ULInt16("offset"),
                PascalString("name"),
                Peek(ULInt8("_pad")),
                PadAlign,
            ),
            "LF_MEMBER": Struct("lfMember",
                CV_fldattr,
                ULInt32("index"),
                val("offset"),
                Peek(ULInt8("_pad")),
                PadAlign,
            ),
            "LF_ENUMERATE": Struct("lfEnumerate",
                CV_fldattr,
                val("enum_value"),
                Peek(ULInt8("_pad")),
                PadAlign,
            ),
            "LF_BCLASS": Struct("lfBClass",
                CV_fldattr,
                ULInt32("index"),
                val("offset"),
                Peek(ULInt8("_pad")),
                PadAlign,
            ),
            "LF_VFUNCTAB": Struct("lfVFuncTab",
                Padding(2),
                ULInt32("type"),
                Peek(ULInt8("_pad")),
                PadAlign,
            ),
            "LF_ONEMETHOD": Struct("lfOneMethod",
                CV_fldattr,
                ULInt32("index"),
                Switch("intro", lambda ctx: ctx.fldattr.mprop,
                    {
                        "MTintro": Struct("value",
                            ULInt32("val"),
                            CString("str_data"),
                        ),
                        "MTpureintro": Struct("value",
                            ULInt32("val"),
                            CString("str_data"),
                        ),
                    },
                    default = CString("str_data"),
                ),
                Peek(ULInt8("_pad")),
                PadAlign,
            ),
            "LF_METHOD": Struct("lfMethod",
                ULInt16("count"),
                ULInt32("mlist"),
                CString("name"),
                Peek(ULInt8("_pad")),
                PadAlign,
            ),
            "LF_NESTTYPE": Struct("lfNestType",
                Padding(2),
                ULInt32("index"),
                CString("name"),
            ),
        },
    ),
)

lfFieldList = Struct("lfFieldList",
    GreedyRange(subStruct)
)

lfEnum = Struct("lfEnum",
    ULInt16("count"),
    CV_property,
    ULInt32("utype"),
    ULInt32("fieldlist"),
    CString("name"),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfBitfield = Struct("lfBitfield",
    ULInt32("base_type"),
    ULInt8("length"),
    ULInt8("position"),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfStructureST = Struct("lfStructureST",
    ULInt16("count"),
    CV_property,
    ULInt32("fieldlist"),
    ULInt32("derived"),
    ULInt32("vshape"),
    ULInt16("size"),
    PascalString("name"),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfStructure = Struct("lfStructure",
    ULInt16("count"),
    CV_property,
    ULInt32("fieldlist"),
    ULInt32("derived"),
    ULInt32("vshape"),
    val("size"),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfClass = Rename("lfClass", lfStructure)

lfArray = Struct("lfArray",
    ULInt32("element_type"),
    ULInt32("index_type"),
    val("size"),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfArrayST = Struct("lfArray",
    ULInt32("element_type"),
    ULInt32("index_type"),
    ULInt16("size"),
    PascalString("name"),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfArgList = Struct("lfArgList",
    ULInt32("count"),
    Array(lambda ctx: ctx.count, ULInt32("arg_type")),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfProcedure = Struct("lfProcedure",
    ULInt32("return_type"),
    CV_call,
    ULInt8("reserved"),
    ULInt16("parm_count"),
    ULInt32("arglist"),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfModifier = Struct("lfModifier",
    ULInt32("modified_type"),
    BitStruct("modifier",
        Padding(5),
        Flag("unaligned"),
        Flag("volatile"),
        Flag("const"),
        Padding(8),
    ),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfPointer = Struct("lfPointer",
    ULInt32("utype"),
    BitStruct("ptr_attr",
        Enum(BitField("mode", 3),
            PTR_MODE_PTR         = 0x00000000,
            PTR_MODE_REF         = 0x00000001,
            PTR_MODE_PMEM        = 0x00000002,
            PTR_MODE_PMFUNC      = 0x00000003,
            PTR_MODE_RESERVED    = 0x00000004,
        ),
        Enum(BitField("type", 5),
            PTR_NEAR             = 0x00000000,
            PTR_FAR              = 0x00000001,
            PTR_HUGE             = 0x00000002,
            PTR_BASE_SEG         = 0x00000003,
            PTR_BASE_VAL         = 0x00000004,
            PTR_BASE_SEGVAL      = 0x00000005,
            PTR_BASE_ADDR        = 0x00000006,
            PTR_BASE_SEGADDR     = 0x00000007,
            PTR_BASE_TYPE        = 0x00000008,
            PTR_BASE_SELF        = 0x00000009,
            PTR_NEAR32           = 0x0000000A,
            PTR_FAR32            = 0x0000000B,
            PTR_64               = 0x0000000C,
            PTR_UNUSEDPTR        = 0x0000000D,
        ),
        Padding(3),
        Flag("restrict"),
        Flag("unaligned"),
        Flag("const"),
        Flag("volatile"),
        Flag("flat32"),
        Padding(16),
    ),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfUnion = Struct("lfUnion",
    ULInt16("count"),
    CV_property,
    ULInt32("fieldlist"),
    val("size"),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfUnionST = Struct("lfUnionST",
    ULInt16("count"),
    CV_property,
    ULInt32("fieldlist"),
    ULInt16("size"),
    PascalString("name"),
    Peek(ULInt8("_pad")),
    PadAlign,
)

lfMFunc = Struct("lfMFunc",
    ULInt32("return_type"),
    ULInt32("class_type"),
    ULInt32("this_type"),
    CV_call,
    ULInt8("reserved"),
    ULInt16("parm_count"),
    ULInt32("arglist"),
    SLInt32("thisadjust"),
    Peek(ULInt8("_pad")),
    PadAlign,
) 

lfVTShape = Struct("lfVTShape",
    ULInt16("count"),
    BitStruct("vt_descriptors",
        Array(lambda ctx: ctx._.count,
            BitField("vt_descriptors", 4)
        )
    )
)

Type = Debugger(Struct("type",
    leaf_type,
    Switch("type_info", lambda ctx: ctx.leaf_type,
        {
            "LF_ARGLIST": lfArgList,
            "LF_ARRAY": lfArray,
            "LF_ARRAY_ST": lfArrayST,
            "LF_BITFIELD": lfBitfield,
            "LF_CLASS": lfClass,
            "LF_ENUM": lfEnum,
            "LF_FIELDLIST": lfFieldList,
            "LF_MFUNC": lfMFunc,
            "LF_MODIFIER": lfModifier,
            "LF_POINTER": lfPointer,
            "LF_PROCEDURE": lfProcedure,
            "LF_STRUCTURE": lfStructure,
            "LF_STRUCTURE_ST": lfStructureST,
            "LF_UNION": lfUnion,
            "LF_UNION_ST": lfUnionST,
            "LF_VTSHAPE": lfVTShape,
        },
        default = Pass,
    ),
))

Type = Struct("types",
    ULInt16("length"),
    Tunnel(
        String("type_data", lambda ctx: ctx.length),
        Type,
    ),
)

### Header structures
def OffCb(name):
    return Struct(name,
        SLInt32("off"),
        SLInt32("cb"),
    )

TPI = Struct("TPIHash",
    ULInt16("sn"),
    Padding(2),
    SLInt32("HashKey"),
    SLInt32("Buckets"),
    OffCb("HashVals"),
    OffCb("TiOff"),
    OffCb("HashAdj"),
)

Header = Struct("TPIHeader",
    ULInt32("version"),
    SLInt32("hdr_size"),
    ULInt32("ti_min"),
    ULInt32("ti_max"),
    ULInt32("follow_size"),
    TPI,
)

### Stream as a whole
TPIStream = Struct("TPIStream",
    Header,
    Array(lambda ctx: ctx.TPIHeader.ti_max - ctx.TPIHeader.ti_min, Type),
)

### END PURE CONSTRUCT DATA ###

def merge_subcon(parent, subattr):
    """Merge a subcon's fields into its parent.

    parent: the Container into which subattr's fields should be merged
    subattr: the name of the subconstruct
    """

    subcon = getattr(parent, subattr)
    for a in (k for k in dir(subcon) if not k.startswith("_")):
        setattr(parent, a, getattr(subcon, a))

    delattr(parent, subattr)

def fix_value(leaf):
    """Translate the value member of a leaf node into a nicer form.
    
    Due to limitations in construct, the inital parsed form of a value is:
    
    value
      `- _value_name
      `- value_or_type
      `- name_or_val

    OR 
    
    value
      `- _value_name
      `- value_or_type
      `- name_or_val
           `- value
           `- name

    This function normalizes the structure to just the value and the name.
    The value is named according to the string in _value_name.
    """
    if not hasattr(leaf, 'value'): return
    if leaf.value.value_or_type < leaf_type._encode("LF_CHAR",{}):
        setattr(leaf, 'name', leaf.value.name_or_val)
        setattr(leaf, leaf.value._value_name, leaf.value.value_or_type)
    else:
        setattr(leaf, 'name', leaf.value.name_or_val.name)
        setattr(leaf, leaf.value._value_name, leaf.value.name_or_val.value)

    delattr(leaf, 'value')

def resolve_typerefs(leaf, types, min):
    """Resolve the numeric type references in a leaf node.

    For each reference to another type in the leaf node, look up the
    corresponding type (base type or type defined in the TPI stream). The
    dictionary type_refs is used to determine which fields in the leaf node
    are references.
    
    leaf: the leaf node to convert
    types: a dictionary of index->type mappings
    min: the value of tpi_min; that is, the lowest type index in the stream
    """
    for attr in type_refs[leaf.leaf_type]:
        ref = getattr(leaf, attr)
        if isinstance(ref, list):
            newrefs = []
            for r in ref:
                if r < min:
                    newrefs.append(base_type._decode(r,{}))
                else:
                    newrefs.append(types[r])
            newrefs = ListContainer(newrefs)
            setattr(leaf, attr, newrefs)
        else:
            if ref < min:
                setattr(leaf, attr, base_type._decode(ref,{}))
            elif ref >= min:
                setattr(leaf, attr, types[ref])
    return leaf

def merge_fwdrefs(leaf, types, map):
    for attr in type_refs[leaf.leaf_type]:
        ref = getattr(leaf, attr)
        if isinstance(ref, list):
            newrefs = []
            for r in ref:
                try: newrefs.append(types[map[r.tpi_idx]])
                except (KeyError, AttributeError): newrefs.append(r)
            newrefs = ListContainer(newrefs)
            setattr(leaf, attr, newrefs)
        elif not isinstance(ref,str):
            try: newref = types[map[ref.tpi_idx]]
            except KeyError: newref = ref
            setattr(leaf, attr, newref)
    return leaf

def rename_2_7(lf):
    if lf.leaf_type.endswith("_ST"):
        lf.leaf_type = lf.leaf_type[:-3]

def parse_stream(fp, unnamed_hack=True, elim_fwdrefs=True):
    """Parse a TPI stream.

    fp: a file-like object that holds the type data to be parsed. Must
        support seeking.

    """
    tpi_stream = TPIStream.parse_stream(fp)
    
    # Postprocessing
    # 1. Index the types
    tpi_stream.types = dict(
        (i, t) for (i,t) in zip(
            range(tpi_stream.TPIHeader.ti_min, tpi_stream.TPIHeader.ti_max),
            tpi_stream.types
        )
    )
    for k in tpi_stream.types: tpi_stream.types[k].tpi_idx = k

    # 2. Flatten type_info and type_data
    for t in tpi_stream.types.values():
        merge_subcon(t,'type_data')
        merge_subcon(t,'type_info')
        if t.leaf_type == 'LF_FIELDLIST':
            for s in t.substructs:
                merge_subcon(s,'type_info')

    # 3. Fix up value and name structures
    for t in tpi_stream.types.values():
        if t.leaf_type == 'LF_FIELDLIST':
            for s in t.substructs:
                fix_value(s)
        else:
            fix_value(t)

    # 4. Resolve type references
    types = tpi_stream.types
    min = tpi_stream.TPIHeader.ti_min
    for i in types:
        if types[i].leaf_type == "LF_FIELDLIST":
            types[i].substructs = ListContainer([ 
                resolve_typerefs(t, types, min) for t in types[i].substructs
            ])
        else:
            types[i] = resolve_typerefs(types[i], types, min)
    
    # 5. Standardize v2 leaf names to v7 convention
    for i in types:
        rename_2_7(types[i])
        if types[i].leaf_type == "LF_FIELDLIST":
            for s in types[i].substructs: rename_2_7(s)

    # 6. Attempt to eliminate forward refs
    # Not possible to eliminate all fwdrefs; some may not be in
    # this PDB file (eg _UNICODE_STRING in ntoskrnl.pdb)
    if elim_fwdrefs:
        # Get list of fwdrefs
        fwdrefs = {}
        for i in types:
            if hasattr(types[i], 'prop') and types[i].prop.fwdref:
                fwdrefs[types[i].name] = i
        # Map them to the real type
        fwdref_map = {}
        for i in types:
            if (hasattr(types[i], 'name') and hasattr(types[i], 'prop') and
                not types[i].prop.fwdref):
                if types[i].name in fwdrefs:
                    fwdref_map[fwdrefs[types[i].name]] = types[i].tpi_idx
        # Change any references to the fwdref to point to the real type
        for i in types:
            if types[i].leaf_type == "LF_FIELDLIST":
                types[i].substructs = ListContainer([ 
                    merge_fwdrefs(t, types, fwdref_map) for t in types[i].substructs
                ])
            else:
                types[i] = merge_fwdrefs(types[i], types, fwdref_map)
        # Get rid of the resolved fwdrefs
        for i in fwdref_map: del types[i]

    if unnamed_hack:
        for i in types:
            if (hasattr(types[i], 'name') and
                    (types[i].name == "__unnamed" or
                     types[i].name == "<unnamed-tag>")):
                types[i].name = "__unnamed" + ("_%x" % types[i].tpi_idx)

    return tpi_stream

def parse(data, unnamed_hack=True, elim_fwdrefs=True):
    return parse_stream(StringIO(data), unnamed_hack, elim_fwdrefs)
    
if __name__ == "__main__":
    import sys
    import time
    st = time.time()
    tpi_stream = parse_stream(open(sys.argv[1]))
    ed = time.time()
    print "Parsed %d types in %f seconds" % (len(tpi_stream.types), ed - st)

    #for k,v in tpi_stream.types.items():
    #    print k,v
