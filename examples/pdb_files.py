#!/usr/bin/python
# coding: utf-8


import os
import sys
import pdbparse
from pdbparse.peinfo import *
from binascii import hexlify


if __name__ == u'__main__':
	pepath = sys.argv[1]
	pdbinfo = get_external_codeview(pepath)
	pdbpath = os.path.join(os.path.dirname(pepath), pdbinfo[1])

	print(pdbinfo[1])
	print(pdbinfo[0])

	p = pdbparse.parse(pdbpath, fast_load=True)	
	pdb = p.streams[pdbparse.PDB_STREAM_PDB]
	pdb.load()
	guidstr = (u'%08x%04x%04x%s%x' % (
		pdb.GUID.Data1, pdb.GUID.Data2, 
		pdb.GUID.Data3, pdb.GUID.Data4.encode('hex'),
		pdb.Age
	)).upper()

	print(guidstr)

	if pdbinfo[0] != guidstr:
		print(u'pdb not for this exe')
	else:
		dbi = p.streams[pdbparse.PDB_STREAM_DBI]
		dbi.load()

		i = 0
		for fns in dbi.modules:
			print(dbi.DBIExHeaders[i].objName)
			for fn in fns:
				print(u'    ' + fn)
			print(u'-')
			i += 1
