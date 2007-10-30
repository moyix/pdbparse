#!/usr/bin/env python

from pdbparse import PDB7
from os.path import basename
import sys

pdb = PDB7(sys.argv[1])
if len(sys.argv) > 2:
    streams = [ pdb.streams[int(i)] for i in sys.argv[2:] ]
else:
    streams = pdb.streams
    
for stream in streams:
    ofname = basename(pdb.fname) + ('.%03d' % stream.index)
    f = open(ofname, 'w')
    f.write(stream.data)
    f.close()
