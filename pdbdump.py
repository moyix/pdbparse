#!/usr/bin/env python

from os.path import basename
import pdbparse
import sys

pdb = pdbparse.parse(sys.argv[1], fast_load=True)
if len(sys.argv) > 2:
    streams = [ pdb.streams[int(i)] for i in sys.argv[2:] ]
else:
    streams = pdb.streams
    
for stream in streams:
    ofname = basename(pdb.fp.name) + ('.%03d' % stream.index)
    f = open(ofname, 'w')
    f.write(stream.data)
    f.close()
