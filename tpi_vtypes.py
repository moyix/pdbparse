#!/usr/bin/env python

import pdbparse
import sys
from os.path import basename

ARCH_PTR_SIZE = 4

vtype  = {
    "T_32PINT4": "'pointer', ['long']",
    "T_32PRCHAR": "'pointer', ['unsigned char']",
    "T_32PUCHAR": "'pointer', ['unsigned char']",
    "T_32PULONG": "'pointer', ['unsigned long']",
    "T_32PLONG": "'pointer', ['long']",
    "T_32PUQUAD": "'pointer', ['unsigned long long']",
    "T_32PUSHORT": "'pointer', ['unsigned short']",
    "T_32PVOID": "'pointer', ['void']",
    "T_64PRCHAR": "'pointer64', ['unsigned char']",
    "T_64PUCHAR": "'pointer64', ['unsigned char']",
    "T_64PULONG": "'pointer64', ['unsigned long']",
    "T_64PLONG": "'pointer64', ['long']",
    "T_64PUQUAD": "'pointer64', ['unsigned long long']",
    "T_64PUSHORT": "'pointer64', ['unsigned short']",
    "T_64PVOID": "'pointer64', ['void']",
    "T_INT4": "'long'",
    "T_INT8": "'long long'",
    "T_LONG": "'long'",
    "T_QUAD": "'long long'",
    "T_RCHAR": "'unsigned char'",
    "T_REAL32": "'float'",
    "T_REAL64": "'double'",
    "T_REAL80": "'long double'",
    "T_SHORT": "'short'",
    "T_UCHAR": "'unsigned char'",
    "T_UINT4": "'unsigned long'",
    "T_ULONG": "'unsigned long'",
    "T_UQUAD": "'unsigned long long'",
    "T_USHORT": "'unsigned short'",
    "T_WCHAR": "'wchar'",
    "T_VOID": "'void'",
}
base_type_size = {
    "T_32PRCHAR": 4,
    "T_32PUCHAR": 4,
    "T_32PLONG": 4,
    "T_32PULONG": 4,
    "T_32PUQUAD": 4,
    "T_32PUSHORT": 4,
    "T_32PVOID": 4,
    "T_64PRCHAR": 8,
    "T_64PUCHAR": 8,
    "T_64PULONG": 8, 
    "T_64PLONG": 8,
    "T_64PUQUAD": 8,
    "T_64PUSHORT": 8,
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

def member_str(m):
    if isinstance(m, str):
        return "[%s]" % vtype[m]
    elif m.leaf_type == "LF_POINTER":
        return "['pointer', %s]" % member_str(m.utype)
    elif m.leaf_type == "LF_MODIFIER":
        return member_str(m.modified_type)
    elif m.leaf_type == "LF_ARRAY":
        count = m.size / get_size(m.element_type) 
        return "['array', %d, %s]" % (count, member_str(m.element_type))
    elif m.leaf_type == "LF_STRUCTURE":
        return "['%s']" % m.name
    elif m.leaf_type == "LF_UNION":
        return "['%s']" % m.name
    elif m.leaf_type == "LF_PROCEDURE":
        return "['void']"
    elif m.leaf_type == "LF_BITFIELD":
        # TODO: add in base type support here later
        return "['BitField', dict(start_bit = %d, end_bit = %d)]" % (m.position, m.position+m.length)
    elif m.leaf_type == "LF_ENUM":
        enum_membs = [ e for e in m.fieldlist.substructs if e.leaf_type == "LF_ENUMERATE" ]
        choices = {}
        for e in enum_membs:
            e_val = -1 if e.enum_value == '\xff' else e.enum_value
            choices[e_val] = e.name
        return "['Enumeration', dict(target = %s, choices = %s)]" % (vtype[m.utype], choices)
    else:
        return "[UNIMPLEMENTED %s]" % m.leaf_type

def print_vtype(lf):
    print "  '%s' : [ %#x, {" % (lf.name, lf.size)
    for s in lf.fieldlist.substructs:
        print "    '%s' : [ %#x, %s]," % (s.name, s.offset, member_str(s.index))
    print "} ],"


from optparse import OptionParser
op = OptionParser()
op.add_option("-i", "--include", dest="include",
                  help="include extra types in FILE", metavar="FILE")
op.add_option("-n", "--name", dest="name",
                  help="place types in a dict named NAME", metavar="NAME")
(opts, args) = op.parse_args()

if len(args) < 1:
    op.error("a PDB file is required")

pdb = pdbparse.parse(args[0])
types = args[1:]

if not types:
    structs = [ t for t in pdb.streams[2].types.values()
                if (t.leaf_type == 'LF_STRUCTURE' or t.leaf_type == "LF_UNION")
                and not t.prop.fwdref ]
else:
    structs = [ pdb.streams[2].structures[t] for t in types
                if not pdb.streams[2].structures[t].prop.fwdref ]

if opts.name:
    print "%s = {" % opts.name
else:
    print "%s_types = {" % basename(args[0]).split(".")[0]
for s in structs:
    print_vtype(s)
if opts.include:
    sys.stdout.write(open(opts.include).read())
print "}"

