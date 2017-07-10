from pefile import PE, DEBUG_TYPE, DIRECTORY_ENTRY
import ntpath
from pdbparse.dbgold import CV_RSDS_HEADER, CV_NB10_HEADER, DebugDirectoryType

def get_pe_debug_data(filename):
    pe = PE(filename, fast_load=True)
    # we prefer CodeView data to misc
    type = u'IMAGE_DEBUG_TYPE_CODEVIEW'
    dbgdata = get_debug_data(pe, DEBUG_TYPE[type])
    if dbgdata is None:
        type = u'IMAGE_DEBUG_TYPE_MISC'
        dbgdata = get_debug_data(pe, DEBUG_TYPE[type])
        if dbgdata is None:
            type = None
    return dbgdata, type

def get_external_codeview(filename):
    pe = PE(filename, fast_load=True)
    dbgdata = get_debug_data(pe, DEBUG_TYPE[u'IMAGE_DEBUG_TYPE_CODEVIEW'])
    if dbgdata[:4] == u'RSDS':
        (guid,filename) = get_rsds(dbgdata)
    elif dbgdata[:4] == u'NB10':
        (guid,filename) = get_nb10(dbgdata)
    else:
        raise TypeError(u'Invalid CodeView signature: [%s]' % dbgdata[:4])
    guid = guid.upper()
    return guid, filename

def get_debug_data(pe, type=DEBUG_TYPE[u'IMAGE_DEBUG_TYPE_CODEVIEW']):
    retval = None
    if not hasattr(pe, u'DIRECTORY_ENTRY_DEBUG'):
        # fast loaded - load directory
        pe.parse_data_directories(DIRECTORY_ENTRY[u'IMAGE_DIRECTORY_ENTRY_DEBUG'])
    if not hasattr(pe, u'DIRECTORY_ENTRY_DEBUG'):
        raise PENoDebugDirectoryEntriesError()
    else:
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            off = entry.struct.PointerToRawData
            size = entry.struct.SizeOfData
            if entry.struct.Type == type:
                retval = pe.__data__[off:off+size]
                break
    return retval

def get_dbg_fname(dbgdata):
    from pdbparse.dbgold import IMAGE_DEBUG_MISC
    dbgstruct = IMAGE_DEBUG_MISC.parse(dbgdata)
    return ntpath.basename(dbgstruct.Strings[0])

def get_rsds(dbgdata):
    dbg = CV_RSDS_HEADER.parse(dbgdata)
    guidstr = "%08x%04x%04x%s%x" % (dbg.GUID.Data1, dbg.GUID.Data2, 
                              dbg.GUID.Data3, dbg.GUID.Data4.encode('hex'),
                              dbg.Age)
    return guidstr,ntpath.basename(dbg.Filename)

def get_nb10(dbgdata):
    dbg = CV_NB10_HEADER.parse(dbgdata)
    guidstr = "%x%x" % (dbg.Timestamp, dbg.Age)
    return guidstr,ntpath.basename(dbg.Filename)

def get_pe_guid(filename):
    try:
        pe = PE(filename, fast_load=True)
    except IOError as e:
        print (e)
        sys.exit(-1)
    guidstr = "%x%x" % (pe.FILE_HEADER.TimeDateStamp,
                        pe.OPTIONAL_HEADER.SizeOfImage)
    return guidstr


