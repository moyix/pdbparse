#!/usr/bin/env python

import pdbparse
import sys

pdb = pdbparse.PDB7(sys.argv[1])
print(len(pdb.streams[2].data))
