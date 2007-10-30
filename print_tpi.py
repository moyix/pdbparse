#!/usr/bin/env python

import sys
import tpi

def typestr(lf):
    if lf.leaf_type == 'LF_POINTER':
        return "Pointer to " + typestr(lf.utype)
    elif lf.leaf_type == 'LF_STRUCTURE':
        return lf.name + "\n    " + "\n    ".join(typestr(s) for s in lf.fieldlist.substructs)
    elif lf.leaf_type == "LF_MEMBER":
        if isinstance(lf.index, str):
            return lf.name + " (%s)" % lf.index
        elif lf.index.leaf_type == "LF_POINTER":
            try: return lf.name + " (Pointer to %s)" % lf.index.utype.name
            except AttributeError: return lf.name + " (Pointer to %s)" % lf.index.utype.leaf_type
        else:
            try: return lf.name + " (%s)" % lf.index.name
            except AttributeError: return lf.name + " (%s)" % lf.index.leaf_type
    else:
        return lf.leaf_type

tpi_stream = tpi.parse_stream(open(sys.argv[1]))
structs = [ t for t in tpi_stream.types.values() 
                if t.leaf_type == 'LF_STRUCTURE' and not t.prop.fwdref ]

for s in structs:
    print typestr(s)
