#!/usr/bin/env python

import sys
import tpi

ARCH_PTR_SIZE = 4

con_base_type = {
    "T_32PRCHAR": 'ULInt32("%s")',
    "T_32PUCHAR": 'ULInt32("%s")',
    "T_32PULONG": 'ULInt32("%s")',
    "T_32PUQUAD": 'ULInt32("%s")',
    "T_32PUSHORT": 'ULInt32("%s")',
    "T_32PVOID": 'ULInt32("%s")',
    "T_INT4": 'SLInt32("%s")',
    "T_LONG": 'SLInt32("%s")',
    "T_QUAD": 'SLInt64("%s")',
    "T_RCHAR": 'String("%s", 1)',
    "T_REAL64": 'SLInt64("%s")',
    "T_SHORT": 'SLInt16("%s")',
    "T_UCHAR": 'String("%s", 1)',
    "T_UINT4": 'ULInt32("%s")',
    "T_ULONG": 'ULInt32("%s")',
    "T_UQUAD": 'ULInt64("%s")',
    "T_USHORT": 'ULInt16("%s")',
}

base_type_size = {
    "T_32PRCHAR": 4,
    "T_32PUCHAR": 4,
    "T_32PULONG": 4,
    "T_32PUQUAD": 4,
    "T_32PUSHORT": 4,
    "T_32PVOID": 4,
    "T_INT4": 4,
    "T_LONG": 4,
    "T_QUAD": 8,
    "T_RCHAR": 1,
    "T_REAL64": 8,
    "T_SHORT": 2,
    "T_UCHAR": 1,
    "T_UINT4": 4,
    "T_ULONG": 4,
    "T_UQUAD": 8,
    "T_USHORT": 2,
}
def get_size(lf):
    if isinstance(lf,str):
        return base_type_size[lf]
    elif (lf.leaf_type == "LF_STRUCTURE" or
          lf.leaf_type == "LF_ARRAY" or
          lf.leaf_type == "LF_UNION"):
        return lf.size
    elif lf.leaf_type == "LF_POINTER":
        return ARCH_PTR_SIZE
    elif lf.leaf_type == "LF_MODIFIER":
        return get_size(lf.modified_type)
    else: return -1


def construct(lf, name=None):
    if isinstance(lf, str):
        return '%s' % (con_base_type[lf] % name)
    elif lf.leaf_type == 'LF_POINTER':
        if hasattr(lf.utype, 'name'):
            return 'ULInt32("%s-%s")' % (name or "ptr", lf.utype.name)
        else:
            return 'ULInt32("%s-%s_%s")' % (name or "ptr", lf.utype.leaf_type,
                lf.utype.tpi_idx)
    elif lf.leaf_type == 'LF_STRUCTURE':
        return 'Struct("%s", # %s\n%s\n)' % (name or lf.name, lf.name,
            construct(lf.fieldlist))
    elif lf.leaf_type == 'LF_FIELDLIST':
        return ',\n'.join(construct(l) for l in lf.substructs)
    elif lf.leaf_type == "LF_MEMBER":
        return construct(lf.index, lf.name)
    elif lf.leaf_type == "LF_BITFIELD":
        if lf.length == 1:
            return 'Flag("%s")' % name
        else:
            return 'Mask("%s", %d)' % (name, lf.length)
    elif lf.leaf_type == "LF_ARRAY":
        count = get_size(lf) / get_size(lf.element_type)
        return 'Array(%d, %s)' % (count, construct(lf.element_type, name or lf.name))
    else:
        return "Unimplemented %s" % lf.leaf_type

tpi_stream = tpi.parse_stream(open(sys.argv[1]))
structs = [ t for t in tpi_stream.types.values() 
                if t.leaf_type == 'LF_STRUCTURE' and not t.prop.fwdref ]

for s in structs:
    if s.name == "_EPROCESS": print construct(s)
