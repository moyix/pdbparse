#!/usr/bin/env python

import sys
import pdbparse

ARCH_PTR_SIZE = 4

ctype = {
    "T_32PINT4": "pointer to long",
    "T_32PRCHAR": "pointer to unsigned char",
    "T_32PUCHAR": "pointer to unsigned char",
    "T_32PULONG": "pointer to unsigned long",
    "T_32PLONG": "pointer to long",
    "T_32PUQUAD": "pointer to unsigned long long",
    "T_32PUSHORT": "pointer to unsigned short",
    "T_32PVOID": "pointer to void",
    "T_64PVOID": "pointer64 to void",
    "T_INT4": "long",
    "T_INT8": "long long",
    "T_LONG": "long",
    "T_QUAD": "long long",
    "T_RCHAR": "unsigned char",
    "T_REAL32": "float",
    "T_REAL64": "double",
    "T_REAL80": "long double",
    "T_SHORT": "short",
    "T_UCHAR": "unsigned char",
    "T_UINT4": "unsigned long",
    "T_ULONG": "unsigned long",
    "T_UQUAD": "unsigned long long",
    "T_USHORT": "unsigned short",
    "T_WCHAR": "wchar",
    "T_VOID": "void",
}

base_type_size = {
    "T_32PRCHAR": 4,
    "T_32PUCHAR": 4,
    "T_32PULONG": 4,
    "T_32PUQUAD": 4,
    "T_32PUSHORT": 4,
    "T_32PVOID": 4,
    "T_64PVOID": 8,
    "T_INT4": 4,
    "T_INT8": 8,
    "T_LONG": 4,
    "T_QUAD": 8,
    "T_RCHAR": 1,
    "T_REAL32": 4,
    "T_REAL64": 8,
    "T_REAL80": 10,
    "T_SHORT": 2,
    "T_UCHAR": 1,
    "T_UINT4": 4,
    "T_ULONG": 4,
    "T_UQUAD": 8,
    "T_USHORT": 2,
    "T_WCHAR": 2,
    "T_32PLONG": 4,
}


def get_size(lf):
    if isinstance(lf, str):
        return base_type_size[lf]
    elif (lf.leaf_type == "LF_STRUCTURE" or lf.leaf_type == "LF_ARRAY" or lf.leaf_type == "LF_UNION"):
        return lf.size
    elif lf.leaf_type == "LF_POINTER":
        return ARCH_PTR_SIZE
    elif lf.leaf_type == "LF_MODIFIER":
        return get_size(lf.modified_type)
    else:
        return -1


def get_tpname(lf):
    if isinstance(lf, str):
        try:
            tpname = ctype[lf]
        except KeyError:
            tpname = lf
    elif lf.leaf_type == "LF_STRUCTURE":
        tpname = lf.name
    elif lf.leaf_type == "LF_ENUM":
        tpname = lf.name
    elif lf.leaf_type == "LF_UNION":
        tpname = lf.name
    elif lf.leaf_type == "LF_POINTER":
        tpname = ptr_str(lf)
    elif lf.leaf_type == "LF_PROCEDURE":
        tpname = proc_str(lf)
    elif lf.leaf_type == "LF_MODIFIER":
        tpname = mod_str(lf)
    elif lf.leaf_type == "LF_ARRAY":
        tpname = arr_str(lf)
    elif lf.leaf_type == "LF_BITFIELD":
        tpname = bit_str(lf)
    else:
        tpname = lf.leaf_type
    return tpname


def bit_str(bitf):
    return "bitfield pos: %d len: %d [%s]" % (bitf.position, bitf.length, get_tpname(bitf.base_type))


def arr_str(arr):
    tpname = get_tpname(arr.element_type)
    count = arr.size / get_size(arr.element_type)
    return "array %s[%d]" % (tpname, count)


def mod_str(mod):
    tpname = get_tpname(mod.modified_type)
    modifiers = [m for m in ["const", "unaligned", "volatile"] if mod.modifier[m]]
    return "%s %s" % (" ".join(modifiers), tpname)


def ptr_str(ptr):
    tpname = get_tpname(ptr.utype)
    return "pointer to %s" % tpname


def proc_str(proc):
    argstrs = []
    for a in proc.arglist.arg_type:
        argstrs.append(get_tpname(a))
    return "function(%s)" % ", ".join(argstrs)


def memb_str(memb):
    off = memb.offset
    tpname = get_tpname(memb.index)
    return "%#x: %s (%s)" % (off, memb.name, tpname)


def struct_pretty_str(lf):
    return (lf.name + (", %#x bytes\n    " % lf.size) + "\n    ".join(memb_str(s) for s in lf.fieldlist.substructs))


def enum_pretty_str(enum):
    enumerated = []
    utypename = get_tpname(enum.utype)
    for e in enum.fieldlist.substructs:
        enumerated.append("%s = %d" % (e.name, e.enum_value))
    return (enum.name + (" (%s)\n    " % utypename) + "\n    ".join(enumerated))


pdb = pdbparse.parse(sys.argv[1])
structs = [
    s for s in pdb.streams[2].types.values()
    if (s.leaf_type == "LF_STRUCTURE" or s.leaf_type == "LF_UNION") and not s.prop.fwdref
]
enums = [e for e in pdb.streams[2].types.values() if e.leaf_type == "LF_ENUM" and not e.prop.fwdref]

print("*******  Structures  *******")
for s in structs:
    print(struct_pretty_str(s))

print("******* Enumerations *******")
for e in enums:
    print(enum_pretty_str(e))
