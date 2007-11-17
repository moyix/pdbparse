#!/usr/bin/env python

import sys
import pdbparse

def typestr(lf):
    if lf.leaf_type == 'LF_POINTER':
        return "Pointer to " + typestr(lf.utype)
    elif lf.leaf_type == 'LF_STRUCTURE':
        return (lf.name + (", %d bytes\n    " % lf.size) + 
                "\n    ".join(typestr(s) for s in lf.fieldlist.substructs))
    elif lf.leaf_type == "LF_MEMBER":
        off = lf.offset
        if isinstance(lf.index, str):
            return "%d: " % off + lf.name + " (%s)" % lf.index
        elif lf.index.leaf_type == "LF_POINTER":
            if isinstance(lf.index.utype, str): tpname = lf.index.utype
            elif hasattr(lf.index.utype,'name'): tpname = lf.index.utype.name
            else: tpname = lf.index.utype.leaf_type
            return "%d: " % off + lf.name + " (Pointer to %s)" % tpname
        else:
            try: return "%d: " % off + lf.name + " (%s)" % lf.index.name
            except AttributeError: return "%d: " % off + lf.name + " (%s)" % lf.index.leaf_type
    else:
        return lf.leaf_type

pdb = pdbparse.parse(sys.argv[1])
structs = [ s for s in pdb.streams[2].types.values() if s.leaf_type == "LF_STRUCTURE" and not s.prop.fwdref ]

for s in structs:
    print typestr(s)
