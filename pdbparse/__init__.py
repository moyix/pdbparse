#!/usr/bin/env python

from struct import unpack,calcsize

PDB_STREAM_ROOT   = 0 # PDB root directory
PDB_STREAM_PDB    = 1 # PDB stream info
PDB_STREAM_TPI    = 2 # type info
PDB_STREAM_DBI    = 3 # debug info

_PDB7_SIGNATURE = 'Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0'
_PDB7_SIGNATURE_LEN = len(_PDB7_SIGNATURE)
_PDB7_FMT = "<%dsLLLLLL" % _PDB7_SIGNATURE_LEN
_PDB_FMT_SIZE = calcsize(_PDB7_FMT)

# Internal method to calculate the number of pages required
# to store a stream of size "length", given a page size of
# "pagesize"
def _pages(length, pagesize):
    num_pages = length / pagesize
    if (length % pagesize): num_pages += 1
    return num_pages

class PDBStream:
    """Base class for PDB stream types.

    data: the data that makes up this stream
    index: the index of this stream in the file
    page_size: the size of a page, in bytes, of the PDB file
        containing this stream

    The constructor signature here is valid for all subclasses.

    """
    def __init__(self, data, index, page_size=0x1000):
        self.data = data
        self.index = index
        self.page_size = page_size

class PDBRootStream(PDBStream):
    """Class representing the root stream of a PDB file.
    
    Parsed streams are available as a tuple of (size, [list of pages])
    describing each stream in the "streams" member of this class.

    """
    def __init__(self, data, index=PDB_STREAM_ROOT, page_size=0x1000):
        self.data = data
        self.index = index
        self.page_size = page_size
        
        (self.num_streams,) = unpack("<L", data[:4])
        
        # num_streams dwords giving stream sizes
        rs = data[4:]
        sizes = []
        for i in range(0,self.num_streams*4,4):
            (stream_size,) = unpack("<L",rs[i:i+4])
            sizes.append(stream_size)
        
        # Next comes a list of the pages that make up each stream
        rs = rs[self.num_streams*4:]
        page_lists = []
        pos = 0
        for i in range(self.num_streams):
            num_pages = _pages(sizes[i], self.page_size)

            if num_pages != 0:
                pages = unpack("<" + ("L"*num_pages),
                               rs[pos:pos+(num_pages*4)])
                page_lists.append(pages)
                pos += num_pages*4
            else:
                page_lists.append(())
        
        self.streams = zip(sizes, page_lists)

class PDBInfoStream(PDBStream):
    pass

class PDBTypeStream(PDBStream):
    pass

class PDBDebugStream(PDBStream):
    pass

# Class mappings for the stream types
_stream_types = {
    PDB_STREAM_ROOT: PDBRootStream,
    #PDB_STREAM_PDB: PDBInfoStream,
    #PDB_STREAM_TPI: PDBTypeStream,
    #PDB_STREAM_DBI: PDBDebugStream
}

class PDB7:
    """Class representing a Microsoft PDB file, version 7.

    This class loads and parses each stream contained in the
    file, and places it in the "streams" member.

    """
    def __init__(self, fname):
        self.fname = fname
        self.streams = []
        self.fp = open(fname, 'rb')
        (self.signature, self.page_size, alloc_table_ptr,
         self.num_file_pages, root_size, reserved,
         root_index) = unpack(_PDB7_FMT, self.fp.read(_PDB_FMT_SIZE))
        
        if self.signature != _PDB7_SIGNATURE:
            raise ValueError("Invalid signature for PDB version 7")
        
        # Read in the root stream
        num_root_pages = _pages(root_size, self.page_size)
        
        self.fp.seek(root_index * self.page_size)
        page_list_fmt = "<" + ("L" * num_root_pages)
        root_page_list = unpack(page_list_fmt,
            self.fp.read(num_root_pages * 4))
        root_stream_data = self.read(root_page_list, root_size)

        root_stream = PDBRootStream(root_stream_data,
            PDB_STREAM_ROOT, self.page_size)

        for i in range(len(root_stream.streams)):
            try:
                pdb_cls = _stream_types[i]
            except KeyError:
                pdb_cls = PDBStream
            stream_size, stream_pages = root_stream.streams[i]
            self.streams.append(
                pdb_cls(self.read(stream_pages, stream_size), i,
                    self.page_size))

    def read(self, pages, size=-1):
        """Read a portion of this PDB file, given a list of pages.
        
        pages: a list of page numbers that make up the data requested
        size: the number of bytes requested. Must be <= len(pages)*self.page_size
        
        """
        
        assert size <= len(pages)*self.page_size

        pos = self.fp.tell()
        s = ''
        for pn in pages:
           self.fp.seek(pn*self.page_size)
           s += self.fp.read(self.page_size)
        self.fp.seek(pos)
        if size == -1:
            return s
        else:
            return s[:size]
