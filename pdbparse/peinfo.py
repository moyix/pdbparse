from pefile import PE
from pdbparse.dbgold import CV_RSDS_HEADER, CV_NB10_HEADER, DebugDirectoryType

def get_pe_debug_data(filename):
    try:
        pe = PE(filename)
    except IOError, e:
        print e
        sys.exit(-1)
    dbgstruct = pe.DIRECTORY_ENTRY_DEBUG[0].struct
    addr = dbgstruct.PointerToRawData
    sz = dbgstruct.SizeOfData
    f = open(filename)
    f.seek(addr)
    dbgdata = f.read(sz)
    f.close()
    return dbgdata, DebugDirectoryType._decode(dbgstruct.Type,{})

def get_dbg_fname(dbgdata):
    from pdbparse.dbgold import IMAGE_DEBUG_MISC
    dbgstruct = IMAGE_DEBUG_MISC.parse(dbgdata)
    
    return dbgstruct.Strings[0].split('\\')[-1]

def get_rsds(dbgdata):
    dbg = CV_RSDS_HEADER.parse(dbgdata)
    guidstr = "%08x%04x%04x%s%x" % (dbg.GUID.Data1, dbg.GUID.Data2, 
                              dbg.GUID.Data3, dbg.GUID.Data4.encode('hex'),
                              dbg.Age)
    filename = dbg.Filename.split('\\')[-1]
    return guidstr,filename

def get_nb10(dbgdata):
    dbg = CV_NB10_HEADER.parse(dbgdata)
    guidstr = "%x%x" % (dbg.Timestamp, dbg.Age)
    return guidstr,dbg.Filename

def get_pe_guid(filename):
    try:
        pe = PE(filename, fast_load=True)
    except IOError, e:
        print e
        sys.exit(-1)
    guidstr = "%x%x" % (pe.FILE_HEADER.TimeDateStamp,
                        pe.OPTIONAL_HEADER.SizeOfImage)
    return guidstr


