#!/usr/bin/env python

import sys
from struct import unpack,calcsize

# Leaf type constants
types = {
    "LF_MODIFIER_16t"         : 0x00000001,
    "LF_POINTER_16t"          : 0x00000002,
    "LF_ARRAY_16t"            : 0x00000003,
    "LF_CLASS_16t"            : 0x00000004,
    "LF_STRUCTURE_16t"        : 0x00000005,
    "LF_UNION_16t"            : 0x00000006,
    "LF_ENUM_16t"             : 0x00000007,
    "LF_PROCEDURE_16t"        : 0x00000008,
    "LF_MFUNCTION_16t"        : 0x00000009,
    "LF_VTSHAPE"              : 0x0000000A,
    "LF_COBOL0_16t"           : 0x0000000B,
    "LF_COBOL1"               : 0x0000000C,
    "LF_BARRAY_16t"           : 0x0000000D,
    "LF_LABEL"                : 0x0000000E,
    "LF_NULL"                 : 0x0000000F,
    "LF_NOTTRAN"              : 0x00000010,
    "LF_DIMARRAY_16t"         : 0x00000011,
    "LF_VFTPATH_16t"          : 0x00000012,
    "LF_PRECOMP_16t"          : 0x00000013,
    "LF_ENDPRECOMP"           : 0x00000014,
    "LF_OEM_16t"              : 0x00000015,
    "LF_TYPESERVER_ST"        : 0x00000016,
    "LF_SKIP_16t"             : 0x00000200,
    "LF_ARGLIST_16t"          : 0x00000201,
    "LF_DEFARG_16t"           : 0x00000202,
    "LF_LIST"                 : 0x00000203,
    "LF_FIELDLIST_16t"        : 0x00000204,
    "LF_DERIVED_16t"          : 0x00000205,
    "LF_BITFIELD_16t"         : 0x00000206,
    "LF_METHODLIST_16t"       : 0x00000207,
    "LF_DIMCONU_16t"          : 0x00000208,
    "LF_DIMCONLU_16t"         : 0x00000209,
    "LF_DIMVARU_16t"          : 0x0000020A,
    "LF_DIMVARLU_16t"         : 0x0000020B,
    "LF_REFSYM"               : 0x0000020C,
    "LF_BCLASS_16t"           : 0x00000400,
    "LF_VBCLASS_16t"          : 0x00000401,
    "LF_IVBCLASS_16t"         : 0x00000402,
    "LF_ENUMERATE_ST"         : 0x00000403,
    "LF_FRIENDFCN_16t"        : 0x00000404,
    "LF_INDEX_16t"            : 0x00000405,
    "LF_MEMBER_16t"           : 0x00000406,
    "LF_STMEMBER_16t"         : 0x00000407,
    "LF_METHOD_16t"           : 0x00000408,
    "LF_NESTTYPE_16t"         : 0x00000409,
    "LF_VFUNCTAB_16t"         : 0x0000040A,
    "LF_FRIENDCLS_16t"        : 0x0000040B,
    "LF_ONEMETHOD_16t"        : 0x0000040C,
    "LF_VFUNCOFF_16t"         : 0x0000040D,
    "LF_TI16_MAX"             : 0x00001000,
    "LF_MODIFIER"             : 0x00001001,
    "LF_POINTER"              : 0x00001002,
    "LF_ARRAY_ST"             : 0x00001003,
    "LF_CLASS_ST"             : 0x00001004,
    "LF_STRUCTURE_ST"         : 0x00001005,
    "LF_UNION_ST"             : 0x00001006,
    "LF_ENUM_ST"              : 0x00001007,
    "LF_PROCEDURE"            : 0x00001008,
    "LF_MFUNCTION"            : 0x00001009,
    "LF_COBOL0"               : 0x0000100A,
    "LF_BARRAY"               : 0x0000100B,
    "LF_DIMARRAY_ST"          : 0x0000100C,
    "LF_VFTPATH"              : 0x0000100D,
    "LF_PRECOMP_ST"           : 0x0000100E,
    "LF_OEM"                  : 0x0000100F,
    "LF_ALIAS_ST"             : 0x00001010,
    "LF_OEM2"                 : 0x00001011,
    "LF_SKIP"                 : 0x00001200,
    "LF_ARGLIST"              : 0x00001201,
    "LF_DEFARG_ST"            : 0x00001202,
    "LF_FIELDLIST"            : 0x00001203,
    "LF_DERIVED"              : 0x00001204,
    "LF_BITFIELD"             : 0x00001205,
    "LF_METHODLIST"           : 0x00001206,
    "LF_DIMCONU"              : 0x00001207,
    "LF_DIMCONLU"             : 0x00001208,
    "LF_DIMVARU"              : 0x00001209,
    "LF_DIMVARLU"             : 0x0000120A,
    "LF_BCLASS"               : 0x00001400,
    "LF_VBCLASS"              : 0x00001401,
    "LF_IVBCLASS"             : 0x00001402,
    "LF_FRIENDFCN_ST"         : 0x00001403,
    "LF_INDEX"                : 0x00001404,
    "LF_MEMBER_ST"            : 0x00001405,
    "LF_STMEMBER_ST"          : 0x00001406,
    "LF_METHOD_ST"            : 0x00001407,
    "LF_NESTTYPE_ST"          : 0x00001408,
    "LF_VFUNCTAB"             : 0x00001409,
    "LF_FRIENDCLS"            : 0x0000140A,
    "LF_ONEMETHOD_ST"         : 0x0000140B,
    "LF_VFUNCOFF"             : 0x0000140C,
    "LF_NESTTYPEEX_ST"        : 0x0000140D,
    "LF_MEMBERMODIFY_ST"      : 0x0000140E,
    "LF_MANAGED_ST"           : 0x0000140F,
    "LF_ST_MAX"               : 0x00001500,
    "LF_TYPESERVER"           : 0x00001501,
    "LF_ENUMERATE"            : 0x00001502,
    "LF_ARRAY"                : 0x00001503,
    "LF_CLASS"                : 0x00001504,
    "LF_STRUCTURE"            : 0x00001505,
    "LF_UNION"                : 0x00001506,
    "LF_ENUM"                 : 0x00001507,
    "LF_DIMARRAY"             : 0x00001508,
    "LF_PRECOMP"              : 0x00001509,
    "LF_ALIAS"                : 0x0000150A,
    "LF_DEFARG"               : 0x0000150B,
    "LF_FRIENDFCN"            : 0x0000150C,
    "LF_MEMBER"               : 0x0000150D,
    "LF_STMEMBER"             : 0x0000150E,
    "LF_METHOD"               : 0x0000150F,
    "LF_NESTTYPE"             : 0x00001510,
    "LF_ONEMETHOD"            : 0x00001511,
    "LF_NESTTYPEEX"           : 0x00001512,
    "LF_MEMBERMODIFY"         : 0x00001513,
    "LF_MANAGED"              : 0x00001514,
    "LF_TYPESERVER2"          : 0x00001515,
    "LF_NUMERIC"              : 0x00008000,
    "LF_CHAR"                 : 0x00008000,
    "LF_SHORT"                : 0x00008001,
    "LF_USHORT"               : 0x00008002,
    "LF_LONG"                 : 0x00008003,
    "LF_ULONG"                : 0x00008004,
    "LF_REAL32"               : 0x00008005,
    "LF_REAL64"               : 0x00008006,
    "LF_REAL80"               : 0x00008007,
    "LF_REAL128"              : 0x00008008,
    "LF_QUADWORD"             : 0x00008009,
    "LF_UQUADWORD"            : 0x0000800A,
    "LF_REAL48"               : 0x0000800B,
    "LF_COMPLEX32"            : 0x0000800C,
    "LF_COMPLEX64"            : 0x0000800D,
    "LF_COMPLEX80"            : 0x0000800E,
    "LF_COMPLEX128"           : 0x0000800F,
    "LF_VARSTRING"            : 0x00008010,
    "LF_OCTWORD"              : 0x00008017,
    "LF_UOCTWORD"             : 0x00008018,
    "LF_DECIMAL"              : 0x00008019,
    "LF_DATE"                 : 0x0000801A,
    "LF_UTF8STRING"           : 0x0000801B,
    "LF_PAD0"                 : 0x000000F0,
    "LF_PAD1"                 : 0x000000F1,
    "LF_PAD2"                 : 0x000000F2,
    "LF_PAD3"                 : 0x000000F3,
    "LF_PAD4"                 : 0x000000F4,
    "LF_PAD5"                 : 0x000000F5,
    "LF_PAD6"                 : 0x000000F6,
    "LF_PAD7"                 : 0x000000F7,
    "LF_PAD8"                 : 0x000000F8,
    "LF_PAD9"                 : 0x000000F9,
    "LF_PAD10"                : 0x000000FA,
    "LF_PAD11"                : 0x000000FB,
    "LF_PAD12"                : 0x000000FC,
    "LF_PAD13"                : 0x000000FD,
    "LF_PAD14"                : 0x000000FE,
    "LF_PAD15"                : 0x000000FF
}

types_s = {}
for (k,v) in types.items():
    types_s[v] = k

# Quick format note:
# flag dicts have 3 keys:
#   "flags" -- dict of single bit flags, name: mask
#   "masks" -- dict of masks, name: (mask, shift)
#   "pad"   -- dict of unused/reserved fields, name: mask

cv_prop = {
    "flags": {
        "packed"   : 0x0001,
        "ctor"     : 0x0002,
        "ovlops"   : 0x0004,
        "isnested" : 0x0008,
        "cnested"  : 0x0010,
        "opassign" : 0x0020,
        "opcast"   : 0x0040,
        "fwdref"   : 0x0080,
        "scoped"   : 0x0100,
    },
    "masks": {},
    "pad": {},
}

cv_fld_attr = {
    "flags": {
        "pseudo"      : 0x0020,
        "noinherit"   : 0x0040,
        "noconstruct" : 0x0080,
        "compgenx"    : 0x0100,
        "unused"      : 0xFE00,
    },
    "masks": {
        "access"      : (0x0003, 0), # CV_ACCESS_*
        "mprop"       : (0x001C, 2), # CV_MT*
    },
    "pad": {},
}

cv_ptr_flags = {
    "flags": {
        "flat32":     0x00000100,
        "volatile":   0x00000200,
        "const":      0x00000400,
        "unaligned":  0x00000800,
        "restricted": 0x00001000,
    },
    "masks": {
        "ptrtype": (0x0000001F, 0), # CV_PTR_*
        "ptrmode": (0x000000E0, 5), # CV_PTR_MODE_*
    },
    "pad": {
        "unused": 0xFFFFE000,
    },
}

cv_mod_flags = {
    "flags": {
        "const"     : 0x0001,
        "volatile"  : 0x0002,
        "unaligned" : 0x0004,
    },
    "mask": {},
    "pad": {
        "reserved"  : 0xFFF8,
    },
}

# Pointer types
CV_PTR_NEAR             = 0x00000000
CV_PTR_FAR              = 0x00000001
CV_PTR_HUGE             = 0x00000002
CV_PTR_BASE_SEG         = 0x00000003
CV_PTR_BASE_VAL         = 0x00000004
CV_PTR_BASE_SEGVAL      = 0x00000005
CV_PTR_BASE_ADDR        = 0x00000006
CV_PTR_BASE_SEGADDR     = 0x00000007
CV_PTR_BASE_TYPE        = 0x00000008
CV_PTR_BASE_SELF        = 0x00000009
CV_PTR_NEAR32           = 0x0000000A
CV_PTR_FAR32            = 0x0000000B
CV_PTR_64               = 0x0000000C
CV_PTR_UNUSEDPTR        = 0x0000000D

# Pointer modes
CV_PTR_MODE_PTR         = 0x00000000
CV_PTR_MODE_REF         = 0x00000001
CV_PTR_MODE_PMEM        = 0x00000002
CV_PTR_MODE_PMFUNC      = 0x00000003
CV_PTR_MODE_RESERVED    = 0x00000004

# Method access modifiers
CV_ACCESS_PRIVATE   = 0x00000001
CV_ACCESS_PROTECTED = 0x00000002
CV_ACCESS_PUBLIC    = 0x00000003

# Method properties
CV_MTvanilla   = 0x00000000
CV_MTvirtual   = 0x00000001
CV_MTstatic    = 0x00000002
CV_MTfriend    = 0x00000003
CV_MTintro     = 0x00000004
CV_MTpurevirt  = 0x00000005
CV_MTpureintro = 0x00000006

# Calling conventions
cv_call = {
    "CV_CALL_NEAR_C"          : 0x00000000,
    "CV_CALL_FAR_C"           : 0x00000001,
    "CV_CALL_NEAR_PASCAL"     : 0x00000002,
    "CV_CALL_FAR_PASCAL"      : 0x00000003,
    "CV_CALL_NEAR_FAST"       : 0x00000004,
    "CV_CALL_FAR_FAST"        : 0x00000005,
    "CV_CALL_SKIPPED"         : 0x00000006,
    "CV_CALL_NEAR_STD"        : 0x00000007,
    "CV_CALL_FAR_STD"         : 0x00000008,
    "CV_CALL_NEAR_SYS"        : 0x00000009,
    "CV_CALL_FAR_SYS"         : 0x0000000A,
    "CV_CALL_THISCALL"        : 0x0000000B,
    "CV_CALL_MIPSCALL"        : 0x0000000C,
    "CV_CALL_GENERIC"         : 0x0000000D,
    "CV_CALL_ALPHACALL"       : 0x0000000E,
    "CV_CALL_PPCCALL"         : 0x0000000F,
    "CV_CALL_SHCALL"          : 0x00000010,
    "CV_CALL_ARMCALL"         : 0x00000011,
    "CV_CALL_AM33CALL"        : 0x00000012,
    "CV_CALL_TRICALL"         : 0x00000013,
    "CV_CALL_SH5CALL"         : 0x00000014,
    "CV_CALL_M32RCALL"        : 0x00000015,
    "CV_CALL_RESERVED"        : 0x00000016,
}

cv_call_s = {}
for (k,v) in cv_call.items():
    cv_call_s[v] = k

def split_s(st, n):
    r = []
    for i in range(0,len(st),n):
        r.append(st[i:i+n])
    return r

def get_flags(value, flags):
    """Return a list of flags for a value.

    Arguments:
        value - the value to be tested
        flags - a dictionary of name -> bit flag mappings

    """
    return [k for (k,v) in flags["flags"].items() if (value & v) > 0]

def mask(value, mask_dict, mask):
    (mk,sh) = mask_dict[mask]
    return (value & mk) >> sh

def null_terminate(st):
    if not st: return st
    if not isinstance(st,str): return st
    for i in range(len(st)):
        if st[i] == '\0':
            return st[:i]
    return st

def val(data):
    """Get value data from a CV data record.

    returns: (val, name, val_len)
        val: value contained or None
        name: name of value
        val_len: length of value data in bytes (including the two type bytes)
    
    (val_len + len(name) + 1) should be the entire usable data length

    """
    (data_type,) = unpack("<H", data[:2])
    if data_type < types['LF_NUMERIC']:
        (v,) = unpack("<H", data[:2])
        return (v, null_terminate(data[2:]), 2)
    else:
        if data_type == types['LF_CHAR']:
            return (data[2:3], null_terminate(data[3:]), 3)
        elif data_type == types['LF_SHORT']:
            (v,) = unpack("<h", data[2:4])
            return (v,null_terminate(data[4:]), 4)
        elif data_type == types['LF_USHORT']:
            (v,) = unpack("<H", data[2:4])
            return (v,null_terminate(data[4:]), 4)
        elif data_type == types['LF_LONG']:
            (v,) = unpack("<l", data[2:6])
            return (v,null_terminate(data[6:]), 6)
        elif data_type == types['LF_ULONG']:
            (v,) = unpack("<L", data[2:6])
            return (v,null_terminate(data[6:]), 6)

def mval(attr, data):
    mtype = mask(attr, cv_fld_attr, 'mprop')
    if mtype == CV_MTintro or mtype == CV_MTpureintro:
        (v,) = unpack("<H",data[:2])
        name = null_terminate(data[2:])
        return (v,name,2)
    else:
        return (None, null_terminate(data), 0)

def print_structure(data, idx):
    fmt = "<HHHLLL"
    fmtl = calcsize(fmt)
    (lf, count, property, field, derived,
            vshape) = unpack(fmt, data[:fmtl])
    (v,name,n) = val(data[fmtl:])
    print "%#04x: Structure %s, %d members at type index %#04x, size %d, flags [%s]" % (idx,
            name, count, field, v, ",".join(get_flags(property,cv_prop)))

def print_pointer(data, idx):
    fmt = "<HLL"
    fmtl = calcsize(fmt)
    (lf, utype, flags) = unpack(fmt,data[:fmtl])
    print "%#04x: Pointer to type at index %#04x, flags [%s]" % (idx, utype,
            ",".join(get_flags(flags,cv_ptr_flags)))

def print_fieldlist(data, idx):
    (main_lf,) = unpack("<H", data[:2])
    data = data[2:]
    print "%#04x: FieldList" % idx
    while data:
        # To keep fieldlist types aligned, CV format fills 
        # in unused space with values over 0xF0. The lower
        # four bits indicate how far ahead one should skip.
        # This leads to patterns in the file looking like:
        #    00 F3 F2 F1 [new type]
        while data and (ord(data[0]) > 0xF0):
            skp = ord(data[0]) & 0x0F
            data = data[skp:]
        if not data: break

        (lf,) = unpack("<H", data[:2])
        if lf == types['LF_MEMBER']:
            fmt = "<HHL"
            fmtl = calcsize(fmt)
            (lf,attr,index) = unpack(fmt, data[:fmtl])
            (v,name,n) = val(data[fmtl:])
            print "  member %s (type %#04x) offset %#04x" % (name,index,v)
            sz = fmtl + n + len(name) + 1
            data = data[sz:]
        elif lf == types['LF_ENUMERATE']:
            fmt = "<HH"
            fmtl = calcsize(fmt)
            (lf,attr) = unpack(fmt,data[:fmtl])
            (v,name,n) = val(data[fmtl:])
            print "  const %s (val %s)" % (name,repr(v))
            sz = fmtl + n + len(name) + 1
            data = data[sz:]
        elif lf == types['LF_BCLASS']:
            fmt = "<HHL"
            fmtl = calcsize(fmt)
            (lf,attr,index) = unpack(fmt,data[:fmtl])
            (v,_,n) = val(data[fmtl:])
            print "  bclass (type %#04x) offset %#04x" % (index,v)
            sz = fmtl + n
            data = data[sz:]
        elif lf == types['LF_VFUNCTAB']:
            fmt = "<HHL"
            fmtl = calcsize(fmt)
            (lf,pad,tp) = unpack(fmt,data[:fmtl])
            print "  virtual function table (type %#04x)" % (tp)
            sz = fmtl
            data = data[sz:]
        elif lf == types['LF_ONEMETHOD']:
            fmt = "<HHL"
            fmtl = calcsize(fmt)
            (lf,attr,index) = unpack(fmt,data[:fmtl])
            (v,name,n) = mval(data[fmtl:])
            print "  single method %s (type %#04x) vbase offset %#04x" % (name,index,v)
            sz = fmtl + n + len(name) + 1
            data = data[sz:]
        elif lf == types['LF_METHOD']:
            fmt = "<HHL"
            fmtl = calcsize(fmt)
            (lf,count,index) = unpack(fmt,data[:fmtl])
            name = null_terminate(data[fmtl:])
            print "  method list %s (type %#04x)" % (name,tp)
            sz = fmtl + len(name) + 1
            data = data[sz:]
        elif lf == types['LF_NESTTYPE']:
            fmt = "<HHL"
            fmtl = calcsize(fmt)
            (lf,pad,tp) = unpack(fmt,data[:fmtl])
            name = null_terminate(data[fmtl:])
            print "  nested type %s (type %#04x)" % (name,tp)
            sz = fmtl + len(name) + 1
            data = data[sz:]
        else:
            print "Unknown subfield type %#04x" % lf
            break

def print_union(data, idx):
    fmt = "<HHHL"
    fmtl = calcsize(fmt)
    (lf,count,prop,field) = unpack(fmt, data[:fmtl])
    (v,name,n) = val(data[fmtl:])
    print "%#04x: Union %s, %d members at type index %#04x, size %d, flags [%s]" % (idx, name,
            count, field, v, ",".join(get_flags(prop, cv_prop)))

def print_enum(data, idx):
    fmt = "<HHHLL"
    fmtl = calcsize(fmt)
    (lf,count,prop,utype,field) = unpack(fmt,data[:fmtl])
    name = null_terminate(data[fmtl:])
    print ("%#04x: Enum %s, %d members at type index "
           "%#04x, underlying type %#04x, flags [%s]" % (idx, name, count, field,
                    utype, ",".join(get_flags(prop,cv_prop))))

def print_array(data, idx):
    fmt = "<HLL"
    fmtl = calcsize(fmt)
    (lf,e_type,idx_type) = unpack(fmt, data[:fmtl])
    (v,name,n) = val(data[fmtl:])
    print "%#04x: Array of type %#04x indexed by type %#04x, size %d" % (idx,
            e_type, idx_type, v)

def print_bitfield(data, idx):
    fmt = "<HLcc"
    fmtl = calcsize(fmt)
    (lf,tp,length,pos) = unpack(fmt, data[:fmtl])
    length = ord(length) # struct module has no single-byte integer format
    pos = ord(pos)
    print "%#04x: Bitfield for type %#04x, %d bit(s) at position %d" % (idx, tp, length, pos)

def print_procedure(data, idx):
    fmt = "<HLccHL"
    fmtl = calcsize(fmt)
    (lf,rvtype,calltype,reserved,
        parmct,arglist) = unpack(fmt, data[:fmtl])
    calltype = ord(calltype)
    try:
        call_conv = cv_call_s[calltype]
    except KeyError:
        call_conv = "CV_CALL_UNKNOWN_%x" % calltype
        
    print ("%#04x: Procedure with return type %#04x, calling convention %s, "
           "%d parameters at type index %#04x" % (idx,rvtype,call_conv,
               parmct, arglist))

def print_arglist(data, idx):
    fmt = "<HL"
    fmtl = calcsize(fmt)
    (lf,count) = unpack(fmt, data[:fmtl])
    args_fmt = "<" + ("L" * count)
    args_fmtl = calcsize(args_fmt)
    args = unpack(args_fmt,data[fmtl:fmtl+args_fmtl])
    print "%#04x: Argument list, length %d" % (idx,count)
    for (i,arg) in zip(range(len(args)),args):
        print "  arg %d type %#04x" % (i,arg)

def print_modifier(data, idx):
    fmt = "<HLH"
    fmtl = calcsize(fmt)
    (lf,mtype,mflags) = unpack(fmt, data[:fmtl])
    print "%#04x: Modifier for type %#04x, modifiers [%s]" % (idx,mtype,
            ",".join(get_flags(mflags,cv_mod_flags)))

f = open(sys.argv[1])

tpiHdr = "<LlLLL"
tpiHsh = "<HHllllllll"

f = open(sys.argv[1])
(vers, hdr_size, timin, timax, tail_size) = unpack(tpiHdr, f.read(0x14))

(sn, snPad, cbHashKey, cHashBuckets, 
 hashValsOff, hashValsCb,
 tiOff, tiCb,
 hashAdjOff, hashAdjCb) = unpack(tpiHsh, f.read(0x24))

print ("HDR.vers                      = %lu\n"
    "HDR.cbHdr                     = 0x%08lX\n"
    "HDR.tiMin                     = 0x%08lX\n"
    "HDR.tiMax                     = 0x%08lX\n"
    "HDR.cbGprec                   = 0x%08lX\n"
    "HDR.tpihash.sn                = 0x%04hX\n"
    "HDR.tpihash.snPad             = 0x%04hX\n"
    "HDR.tpihash.cbHashKey         = 0x%08lX\n"
    "HDR.tpihash.cHashBuckets      = 0x%08lX\n"
    "HDR.tpihash.offcbHashVals.off = 0x%08lX\n"
    "HDR.tpihash.offcbHashVals.cb  = 0x%08lX\n"
    "HDR.tpihash.offcbTiOff.off    = 0x%08lX\n"
    "HDR.tpihash.offcbTiOff.cb     = 0x%08lX\n"
    "HDR.tpihash.offcbHashAdj.off  = 0x%08lX\n"
    "HDR.tpihash.offcbHashAdj.cb   = 0x%08lX\n") % (vers, hdr_size, 
        timin, timax, tail_size, sn, snPad, cbHashKey, cHashBuckets, 
        hashValsOff, hashValsCb, tiOff, tiCb, hashAdjOff, hashAdjCb)

tpi = {}
tpi_idx = timin
while True:
    dat = f.read(2)
    if dat == "": break
    (size,) = unpack("<H", dat)
    tpi[tpi_idx] = f.read(size)
    (tp,) = unpack("<H", tpi[tpi_idx][:2])
    if tp == types['LF_STRUCTURE']:
        print_structure(tpi[tpi_idx],tpi_idx)
    elif tp == types['LF_POINTER']:
        print_pointer(tpi[tpi_idx],tpi_idx)
    elif tp == types['LF_FIELDLIST']:
        print_fieldlist(tpi[tpi_idx],tpi_idx)
    elif tp == types['LF_UNION']:
        print_union(tpi[tpi_idx],tpi_idx)
    elif tp == types['LF_BITFIELD']:
        print_bitfield(tpi[tpi_idx],tpi_idx)
    elif tp == types['LF_ENUM']:
        print_enum(tpi[tpi_idx],tpi_idx)
    elif tp == types['LF_ARRAY']:
        print_array(tpi[tpi_idx],tpi_idx)
    elif tp == types['LF_PROCEDURE']:
        print_procedure(tpi[tpi_idx],tpi_idx)
    elif tp == types['LF_ARGLIST']:
        print_arglist(tpi[tpi_idx],tpi_idx)
    elif tp == types['LF_MODIFIER']:
        print_modifier(tpi[tpi_idx],tpi_idx)
    else:
        print "%#04x: %s" % (tpi_idx, types_s[tp])
    tpi_idx += 1

for k in sorted(tpi.keys()):
    print "%#04x: %s" % (k, " ".join(split_s(tpi[k].encode('hex'),2)))
