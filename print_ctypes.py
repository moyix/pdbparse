#!/usr/bin/env python

import pdbparse
import random

# Topological sort, by Paul Harrison
# Found at:
#   http://www.logarithmic.net/pfh-files/blog/01208083168/sort.py
# License: Public domain
def topological_sort(graph):
    count = { }
    for node in graph:
        count[node] = 0
    for node in graph:
        for successor in graph[node]:
            count[successor] += 1

    ready = [ node for node in graph if count[node] == 0 ]
    
    result = [ ]
    while ready:
        node = ready.pop(-1)
        result.append(node)
        
        for successor in graph[node]:
            count[successor] -= 1
            if count[successor] == 0:
                ready.append(successor)
    
    return result

def rand_str(length):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    alphabet += alphabet.upper()
    return "".join(random.sample(alphabet,length))

ARCH_PTR_SIZE = 4

snames = {
    "LF_STRUCTURE": "struct",
    "LF_ENUM": "enum",
    "LF_UNION": "union",
}

ctype = {}
ptr_str = None
fptr_str = None
struct_pretty_str = None

# Microsoft Visual Studio "theme"
ctype_msvc  = {
    "T_32PINT4": "PLONG",
    "T_32PRCHAR": "PUCHAR",
    "T_32PUCHAR": "PUCHAR",
    "T_32PULONG": "PULONG",
    "T_32PLONG": "PLONG",
    "T_32PUQUAD": "PULONGLONG",
    "T_32PUSHORT": "PUSHORT",
    "T_32PVOID": "PVOID",
    "T_64PVOID": "PVOID",
    "T_INT4": "LONG",
    "T_INT8": "LONGLONG",
    "T_LONG": "LONG",
    "T_QUAD": "LONGLONG",
    "T_RCHAR": "UCHAR",
    "T_REAL32": "FLOAT",
    "T_REAL64": "DOUBLE",
    "T_REAL80": "long double",
    "T_SHORT": "SHORT",
    "T_UCHAR": "UCHAR",
    "T_UINT4": "ULONG",
    "T_ULONG": "ULONG",
    "T_UQUAD": "ULONGLONG",
    "T_USHORT": "USHORT",
    "T_WCHAR": "WCHAR",
    "T_VOID": "VOID",
}

# Introspection "theme" for a 32-bit target
ctype_intro  = {
    "T_32PINT4": "uint32_t",
    "T_32PRCHAR": "uint32_t",
    "T_32PUCHAR": "uint32_t",
    "T_32PULONG": "uint32_t",
    "T_32PLONG": "uint32_t",
    "T_32PUQUAD": "uint32_t",
    "T_32PUSHORT": "uint32_t",
    "T_32PVOID": "uint32_t",
    "T_64PVOID": "uint32_t",
    "T_INT4": "int32_t",
    "T_INT8": "int64_t",
    "T_LONG": "int32_t",
    "T_QUAD": "int64_t",
    "T_RCHAR": "uint8_t",
    "T_REAL32": "float",
    "T_REAL64": "double",
    "T_REAL80": "long double",
    "T_SHORT": "int16_t",
    "T_UCHAR": "uint8_t",
    "T_UINT4": "uint32_t",
    "T_ULONG": "uint32_t",
    "T_UQUAD": "uint64_t",
    "T_USHORT": "uint16_t",
    "T_WCHAR": "uint16_t",
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

def is_function_pointer(lf):
    if isinstance(lf, str):
        return False
    if lf.leaf_type == "LF_POINTER":
        return is_function_pointer(lf.utype)
    elif lf.leaf_type == "LF_PROCEDURE":
        return True
    else:
        return False

def is_inline_struct(lf):
    if isinstance(lf, str): return False
    if (lf.leaf_type == "LF_STRUCTURE" or
        lf.leaf_type == "LF_UNION" or
        lf.leaf_type == "LF_ENUM") and "unnamed" in lf.name:
        return True
    else:
        try:
            if "unnamed" in lf.name: print lf.leaf_type
        except:
            pass
    return False

def proc_arglist(proc):
    argstrs = []
    for a in proc.arglist.arg_type:
        argstrs.append(get_tpname(a))
    return argstrs

def fptr_str_intro(fptr,name):
    return "uint32_t %s" % name

def fptr_str_std(fptr,name):
    stars = ""
    while fptr.leaf_type == "LF_POINTER":
        stars += "*"
        fptr = fptr.utype
    ret_type = get_tpname(fptr.return_type)
    arglist = proc_arglist(fptr)
    return "%s (%s%s)(%s)" % (ret_type, stars, name, ", ".join(arglist))

def demangle(nm):
    if nm.startswith("_"): return nm[1:]
    else: return nm

def mangle(nm):
    if not nm.startswith("_"): return "_" + nm
    else: return nm

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

def get_basetype(lf):
    if isinstance(lf, str):
        return None
    elif (lf.leaf_type == "LF_STRUCTURE" or
          lf.leaf_type == "LF_ENUM" or
          lf.leaf_type == "LF_UNION"):
        return lf
    elif lf.leaf_type == "LF_POINTER":
        return get_basetype(lf.utype)
    elif lf.leaf_type == "LF_ARRAY":
        return get_basetype(lf.element_type)
    elif lf.leaf_type == "LF_MODIFIER":
        return get_basetype(lf.modified_type)
    else:
        return None

def get_tpname(lf, name=None):
    if isinstance(lf, str):
        try: tpname = ctype[lf]
        except KeyError: tpname = lf
        if name: tpname += " " + name
    elif (lf.leaf_type == "LF_STRUCTURE" or
          lf.leaf_type == "LF_ENUM" or
          lf.leaf_type == "LF_UNION"):
        tpname = demangle(lf.name)
        if name: tpname += " " + name
    elif lf.leaf_type == "LF_POINTER": tpname = ptr_str(lf,name)
    elif lf.leaf_type == "LF_PROCEDURE": tpname = proc_str(lf,name)
    elif lf.leaf_type == "LF_MODIFIER": tpname = mod_str(lf,name)
    elif lf.leaf_type == "LF_ARRAY": tpname = arr_str(lf,name)
    elif lf.leaf_type == "LF_BITFIELD": tpname = bit_str(lf,name)
    else:
        tpname = lf.leaf_type
        if name: tpname += " " + name
    return tpname

def bit_str(bitf, name):
    return "%s %s : %d" % (get_tpname(bitf.base_type), name, bitf.length)

def arr_str(arr, name):
    tpname = get_tpname(arr.element_type)
    sz = get_size(arr.element_type)
    if sz == 0:
        print "ERROR with array %s %s" % (tpname, name)
    count = arr.size / sz
    return "%s %s[%d]" % (tpname, name, count)

def mod_str(mod, name):
    tpname = get_tpname(mod.modified_type)
    modifiers = [ m for m in ["const","unaligned","volatile"] if mod.modifier[m]]
    tpname = "%s %s" % (" ".join(modifiers), tpname)
    if name: tpname += " " + name
    return tpname

def ptr_str_intro(ptr, name):
    if name:
        return "uint32_t %s" % name
    else:
        return "uint32_t"

def ptr_str_std(ptr, name):
    tpname = get_tpname(ptr.utype)
    if name:
        return "P%s %s" % (tpname, name)
    else:
        return "P%s" % tpname

def proc_str(proc, name):
    argstrs = proc_arglist(proc)
    ret_type = get_tpname(proc.return_type)
    if not name: name = "func_" + rand_str(5)
    return "%s (*%s)(%s)" % (ret_type, name, ", ".join(argstrs))

def memb_str(memb, indent=""):
    off = memb.offset
    if is_function_pointer(memb.index):
        tpname = fptr_str(memb.index, memb.name)
    elif is_inline_struct(memb.index):
        sname = snames[memb.index.leaf_type]
        tpname = sname + " {\n"
        tpname += flstr(memb.index,indent=indent+"    ")
        tpname += indent + "} " + memb.name
    else:
        tpname = get_tpname(memb.index, memb.name)
    return (off,"%s ; // offset %#x" % (tpname, off))

def unionize(member_list):
    new_mlist = []
    i = 0
    while i < len(member_list):
        off,s = member_list[i]
        if i+1 < len(member_list):
            next_off, _ = member_list[i+1]
            if off == next_off:
                union = []
                union.append(s)
                while off == next_off:
                    i += 1
                    off, s = member_list[i]
                    union.append(s)
                    if i+1 < len(member_list):
                        next_off, _ = member_list[i+1]
                    else:
                        break
                new_mlist.append(union)
            else: 
                new_mlist.append(s)
        else: 
            new_mlist.append(s)
        i += 1
    return new_mlist

def flstr(lf, indent=""):
    flstr = ""
    memb_strs = [ memb_str(s,indent) for s in lf.fieldlist.substructs if s.leaf_type == "LF_MEMBER" ]
    for m in unionize(memb_strs):
        if isinstance(m,list):
            flstr += indent + "union {\n"
            for um in m:
                um = um.splitlines()
                for u in um:
                    flstr += indent + u + "\n"
            flstr += indent + "};\n"
        else:
            flstr += indent + m + "\n"
    enum_membs = [ e for e in lf.fieldlist.substructs if e.leaf_type == "LF_ENUMERATE" ]
    for i,e in enumerate(enum_membs):
        e_val = -1 if e.enum_value == '\xff' else e.enum_value
        comma = "," if i < len(enum_membs) - 1 else ""
        flstr += indent + "%s = %s%s\n" % (e.name, e_val, comma)
    return flstr

def struct_dependencies(lf):
    deps = set()
    members = [ s for s in lf.fieldlist.substructs if s.leaf_type == "LF_MEMBER" ]
    for memb in members:
        base = get_basetype(memb.index)
        if base and not (memb.index.leaf_type =="LF_POINTER"):
            if is_inline_struct(base):
                deps = deps | struct_dependencies(base)
            else:
                deps.add(base)
    return deps

def struct_pretty_str_fwd(lf):
    print "struct %s { // %#x bytes" % (mangle(lf.name), lf.size)
    print flstr(lf, indent="    ")
    print "};"
    print

def struct_pretty_str_nofwd(lf):
    print "typedef struct %s { // %#x bytes" % (mangle(lf.name), lf.size)
    print flstr(lf, indent="    ")
    print "} %s, *P%s, **PP%s ;" % ((demangle(lf.name),)*3)
    print

def enum_pretty_str(enum):
    #if not enum.name.startswith("_"):
    #    name = "_" + enum.name
    #else: name = enum.name
    print "typedef enum %s {" % mangle(enum.name)
    print flstr(enum, indent="    ")
    print "} %s;" % demangle(enum.name)
    print

themes = {
    "msvc": ctype_msvc,
    "intro": ctype_intro,
}

theme_func = {
    "msvc": {
        "ptr_str": ptr_str_std,
        "fptr_str": fptr_str_std,
    },
    "intro": {
        "ptr_str": ptr_str_intro,
        "fptr_str": fptr_str_intro,
    },
}

if __name__ == "__main__":
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-t", "--theme", dest="theme",
                      help="theme to use for C types [%s]" % ", ".join(themes),
                      default="msvc")
    parser.add_option("-f", "--fwdrefs", dest="fwdrefs", action="store_true",
                      help="emit forward references", default=False)
    opts,args = parser.parse_args()
    ctype = themes[opts.theme]
    ptr_str = theme_func[opts.theme]["ptr_str"]
    fptr_str = theme_func[opts.theme]["fptr_str"]
    if opts.fwdrefs:
        struct_pretty_str = struct_pretty_str_fwd
    else:
        struct_pretty_str =  struct_pretty_str_nofwd

    if opts.fwdrefs:
        pdb = pdbparse.parse(args[0], fast_load=True)
        pdb.streams[2].load(elim_fwdrefs=False)
    else:
        pdb = pdbparse.parse(args[0])
        
    if opts.fwdrefs:
        fwdrefs = [ s for s in pdb.streams[2].types.values() if (s.leaf_type == "LF_STRUCTURE" or s.leaf_type == "LF_UNION") and s.prop.fwdref ]
        print "/******* Forward Refs *******/"
        for f in fwdrefs:
            print "struct %s;" % mangle(f.name)
            print "typedef struct %s %s;" % (mangle(f.name), demangle(f.name))
        print
        # Reload the file without fwdrefs as it messes up type sizes
        pdb = pdbparse.parse(args[0])

    structs = [ s for s in pdb.streams[2].types.values() if (s.leaf_type == "LF_STRUCTURE" or s.leaf_type == "LF_UNION") and not s.prop.fwdref ]
    enums = [ e for e in pdb.streams[2].types.values() if e.leaf_type == "LF_ENUM" and not e.prop.fwdref ]

    dep_graph = {}
    for s in structs:
        if "unnamed" in s.name: continue
        print s.name, [d.name for d in struct_dependencies(s)] 
        dep_graph[s] = struct_dependencies(s)
    dep_graph.update((e,[]) for e in enums)
    structs = topological_sort(dep_graph)
    structs.reverse()

    print "/******* Enumerations *******/"
    for e in enums:
        enum_pretty_str(e)

    print "/*******  Structures  *******/"
    for s in structs:
        if "unnamed" in s.name: continue
        if s.leaf_type == "LF_ENUM": continue
        struct_pretty_str(s)
