#!/usr/bin/env python

import urllib2
import sys,os
from pefile import PE
from pdbparse.dbgold import CV_RSDS_HEADER, CV_NB10_HEADER, DebugDirectoryType

UA = "Microsoft-Symbol-Server/6.6.0007.5"

def get_pe_debug_data(filename):
    pe = PE(filename)
    dbgstruct = pe.DIRECTORY_ENTRY_DEBUG[0].struct
    addr = dbgstruct.PointerToRawData
    sz = dbgstruct.SizeOfData
    f = open(sys.argv[1])
    f.seek(addr)
    dbgdata = f.read(sz)
    f.close()
    return dbgdata, DebugDirectoryType._decode(dbgstruct.Type,{})

def download_file(guid,fname):
    url = "http://msdl.microsoft.com/download/symbols/%s/%s/" % (fname,guid)
    opener = urllib2.build_opener()
    tries = [ fname, fname[:-1] + '_', 'file.ptr' ]

    for t in tries:
        print url+t
        request = urllib2.Request(url+t)
        request.add_header('User-agent', UA)
        try:
            op = opener.open(request)
            f = open(t, 'w')
            f.write(op.read())
            f.close()
            op.close()
            print "Saved symbols to %s" % t
            return t
        except urllib2.HTTPError:
            pass
    return False

def get_dbg_fname(dbgdata):
    from pdbparse.dbgold import IMAGE_DEBUG_MISC
    dbgstruct = IMAGE_DEBUG_MISC.parse(dbgdata)
    
    return dbgstruct.Strings[0].split('\\')[-1]

def get_rsds(dbgdata):
    dbg = CV_RSDS_HEADER.parse(dbgdata)
    guidstr = "%x%x%x%s%x" % (dbg.GUID.Data1, dbg.GUID.Data2, 
                              dbg.GUID.Data3, dbg.GUID.Data4.encode('hex'),
                              dbg.Age)
    return guidstr,dbg.Filename

def get_nb10(dbgdata):
    dbg = CV_NB10_HEADER.parse(dbgdata)
    guidstr = "%x%x" % (dbg.Timestamp, dbg.Age)
    return guidstr,dbg.Filename

def get_pe_guid(filename):
    pe = PE(filename)
    guidstr = "%x%x" % (pe.FILE_HEADER.TimeDateStamp,
                        pe.OPTIONAL_HEADER.SizeOfImage)
    return guidstr


dbgdata, tp = get_pe_debug_data(sys.argv[1])
if tp == "IMAGE_DEBUG_TYPE_CODEVIEW":
    # XP+
    (guid,filename) = get_rsds(dbgdata)
    guid = guid.upper()
    saved_file = download_file(guid,filename)
elif tp == "IMAGE_DEBUG_TYPE_MISC":
    # Win2k
    # Get the .dbg file
    guid = get_pe_guid(sys.argv[1])
    filename = get_dbg_fname(dbgdata)
    saved_file = download_file(guid,filename)

    # Extract it if it's compressed
    if saved_file.endswith("_"):
        os.system("cabextract %s" % saved_file)
        saved_file = saved_file.replace('.db_','.dbg')

    from pdbparse.dbgold import DbgFile
    dbgfile = DbgFile.parse_stream(open(saved_file))
    cv_entry = [ d for d in dbgfile.IMAGE_DEBUG_DIRECTORY
                   if d.Type == "IMAGE_DEBUG_TYPE_CODEVIEW"][0]
    (guid,filename) = get_nb10(cv_entry.Data)
    saved_file = download_file(guid,filename)

if saved_file.endswith("_"):
    os.system("cabextract %s" % saved_file)
