#!/usr/bin/env python

"""
typedef struct _OffCb
        {
/*000*/ LONG off;
/*004*/ LONG cb;
/*008*/ }
        OffCb, *POffCb, **PPOffCb;

#define OffCb_ sizeof (OffCb)

// -----------------------------------------------------------------

typedef struct _TpiHash
        {
/*000*/ WORD  sn;            // stream #
/*002*/ WORD  snPad;         // padding
/*004*/ LONG  cbHashKey;
/*008*/ LONG  cHashBuckets;
/*00C*/ OffCb offcbHashVals;
/*014*/ OffCb offcbTiOff;
/*01C*/ OffCb offcbHashAdj;
/*024*/ }
        TpiHash, *PTpiHash, **PPTpiHash;

#define TpiHash_ sizeof (TpiHash)

// -----------------------------------------------------------------

typedef struct _HDR          // TPI stream header
        {
/*000*/ DWORD   vers;        // implementation version
/*004*/ LONG    cbHdr;       // header size
/*008*/ DWORD   tiMin;       // type index base  (0x1000..0xFFFFFF)
/*00C*/ DWORD   tiMac;       // type index limit (0x1000..0xFFFFFF)
/*010*/ DWORD   cbGprec;     // size of follow-up data
/*014*/ TpiHash tpihash;
/*038*/ }
        HDR, *PHDR, **PPHDR;

#define HDR_ sizeof (HDR)
"""

# Leaf type constants
LF_MODIFIER_16t         = 0x00000001
LF_POINTER_16t          = 0x00000002
LF_ARRAY_16t            = 0x00000003
LF_CLASS_16t            = 0x00000004
LF_STRUCTURE_16t        = 0x00000005
LF_UNION_16t            = 0x00000006
LF_ENUM_16t             = 0x00000007
LF_PROCEDURE_16t        = 0x00000008
LF_MFUNCTION_16t        = 0x00000009
LF_VTSHAPE              = 0x0000000A
LF_COBOL0_16t           = 0x0000000B
LF_COBOL1               = 0x0000000C
LF_BARRAY_16t           = 0x0000000D
LF_LABEL                = 0x0000000E
LF_NULL                 = 0x0000000F
LF_NOTTRAN              = 0x00000010
LF_DIMARRAY_16t         = 0x00000011
LF_VFTPATH_16t          = 0x00000012
LF_PRECOMP_16t          = 0x00000013
LF_ENDPRECOMP           = 0x00000014
LF_OEM_16t              = 0x00000015
LF_TYPESERVER_ST        = 0x00000016

LF_SKIP_16t             = 0x00000200
LF_ARGLIST_16t          = 0x00000201
LF_DEFARG_16t           = 0x00000202
LF_LIST                 = 0x00000203
LF_FIELDLIST_16t        = 0x00000204
LF_DERIVED_16t          = 0x00000205
LF_BITFIELD_16t         = 0x00000206
LF_METHODLIST_16t       = 0x00000207
LF_DIMCONU_16t          = 0x00000208
LF_DIMCONLU_16t         = 0x00000209
LF_DIMVARU_16t          = 0x0000020A
LF_DIMVARLU_16t         = 0x0000020B
LF_REFSYM               = 0x0000020C

LF_BCLASS_16t           = 0x00000400
LF_VBCLASS_16t          = 0x00000401
LF_IVBCLASS_16t         = 0x00000402
LF_ENUMERATE_ST         = 0x00000403
LF_FRIENDFCN_16t        = 0x00000404
LF_INDEX_16t            = 0x00000405
LF_MEMBER_16t           = 0x00000406
LF_STMEMBER_16t         = 0x00000407
LF_METHOD_16t           = 0x00000408
LF_NESTTYPE_16t         = 0x00000409
LF_VFUNCTAB_16t         = 0x0000040A
LF_FRIENDCLS_16t        = 0x0000040B
LF_ONEMETHOD_16t        = 0x0000040C
LF_VFUNCOFF_16t         = 0x0000040D

LF_TI16_MAX             = 0x00001000
LF_MODIFIER             = 0x00001001
LF_POINTER              = 0x00001002
LF_ARRAY_ST             = 0x00001003
LF_CLASS_ST             = 0x00001004
LF_STRUCTURE_ST         = 0x00001005
LF_UNION_ST             = 0x00001006
LF_ENUM_ST              = 0x00001007
LF_PROCEDURE            = 0x00001008
LF_MFUNCTION            = 0x00001009
LF_COBOL0               = 0x0000100A
LF_BARRAY               = 0x0000100B
LF_DIMARRAY_ST          = 0x0000100C
LF_VFTPATH              = 0x0000100D
LF_PRECOMP_ST           = 0x0000100E
LF_OEM                  = 0x0000100F
LF_ALIAS_ST             = 0x00001010
LF_OEM2                 = 0x00001011

LF_SKIP                 = 0x00001200
LF_ARGLIST              = 0x00001201
LF_DEFARG_ST            = 0x00001202
LF_FIELDLIST            = 0x00001203
LF_DERIVED              = 0x00001204
LF_BITFIELD             = 0x00001205
LF_METHODLIST           = 0x00001206
LF_DIMCONU              = 0x00001207
LF_DIMCONLU             = 0x00001208
LF_DIMVARU              = 0x00001209
LF_DIMVARLU             = 0x0000120A

LF_BCLASS               = 0x00001400
LF_VBCLASS              = 0x00001401
LF_IVBCLASS             = 0x00001402
LF_FRIENDFCN_ST         = 0x00001403
LF_INDEX                = 0x00001404
LF_MEMBER_ST            = 0x00001405
LF_STMEMBER_ST          = 0x00001406
LF_METHOD_ST            = 0x00001407
LF_NESTTYPE_ST          = 0x00001408
LF_VFUNCTAB             = 0x00001409
LF_FRIENDCLS            = 0x0000140A
LF_ONEMETHOD_ST         = 0x0000140B
LF_VFUNCOFF             = 0x0000140C
LF_NESTTYPEEX_ST        = 0x0000140D
LF_MEMBERMODIFY_ST      = 0x0000140E
LF_MANAGED_ST           = 0x0000140F

LF_ST_MAX               = 0x00001500
LF_TYPESERVER           = 0x00001501
LF_ENUMERATE            = 0x00001502
LF_ARRAY                = 0x00001503
LF_CLASS                = 0x00001504
LF_STRUCTURE            = 0x00001505
LF_UNION                = 0x00001506
LF_ENUM                 = 0x00001507
LF_DIMARRAY             = 0x00001508
LF_PRECOMP              = 0x00001509
LF_ALIAS                = 0x0000150A
LF_DEFARG               = 0x0000150B
LF_FRIENDFCN            = 0x0000150C
LF_MEMBER               = 0x0000150D
LF_STMEMBER             = 0x0000150E
LF_METHOD               = 0x0000150F
LF_NESTTYPE             = 0x00001510
LF_ONEMETHOD            = 0x00001511
LF_NESTTYPEEX           = 0x00001512
LF_MEMBERMODIFY         = 0x00001513
LF_MANAGED              = 0x00001514
LF_TYPESERVER2          = 0x00001515

LF_NUMERIC              = 0x00008000
LF_CHAR                 = 0x00008000
LF_SHORT                = 0x00008001
LF_USHORT               = 0x00008002
LF_LONG                 = 0x00008003
LF_ULONG                = 0x00008004
LF_REAL32               = 0x00008005
LF_REAL64               = 0x00008006
LF_REAL80               = 0x00008007
LF_REAL128              = 0x00008008
LF_QUADWORD             = 0x00008009
LF_UQUADWORD            = 0x0000800A
LF_REAL48               = 0x0000800B
LF_COMPLEX32            = 0x0000800C
LF_COMPLEX64            = 0x0000800D
LF_COMPLEX80            = 0x0000800E
LF_COMPLEX128           = 0x0000800F
LF_VARSTRING            = 0x00008010
LF_OCTWORD              = 0x00008017
LF_UOCTWORD             = 0x00008018
LF_DECIMAL              = 0x00008019
LF_DATE                 = 0x0000801A
LF_UTF8STRING           = 0x0000801B

LF_PAD0                 = 0x000000F0
LF_PAD1                 = 0x000000F1
LF_PAD2                 = 0x000000F2
LF_PAD3                 = 0x000000F3
LF_PAD4                 = 0x000000F4
LF_PAD5                 = 0x000000F5
LF_PAD6                 = 0x000000F6
LF_PAD7                 = 0x000000F7
LF_PAD8                 = 0x000000F8
LF_PAD9                 = 0x000000F9
LF_PAD10                = 0x000000FA
LF_PAD11                = 0x000000FB
LF_PAD12                = 0x000000FC
LF_PAD13                = 0x000000FD
LF_PAD14                = 0x000000FE
LF_PAD15                = 0x000000FF

class PDBTypeStream(PDBStream):
    def __init__(self, data, index=PDB_STREAM_TPI, page_size=0x1000):
        self.data = data
        self.index = index
        self.page_size = page_size
        
        self.version
        self.types_min
        self.types_max
        self.num_types = self.types_max - self.types_min 
