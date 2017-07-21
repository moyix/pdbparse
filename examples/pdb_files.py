#!/usr/bin/python
# coding: utf-8


import os
import sys
import pdbparse
from pdbparse.peinfo import *
from binascii import hexlify

def main (pepath):
	
	# Extract debug infos from PE. 
	guid, pdb_filename = get_external_codeview(pepath)
	print("PE debug infos : %s, %s" % (pdb_filename, guid))
	

	# Extract corresponding PDB. 
	pdbpath = os.path.join(os.path.dirname(pepath), pdb_filename)
	p = pdbparse.parse(pdbpath, fast_load=True)	
	pdb = p.streams[pdbparse.PDB_STREAM_PDB]
	pdb.load()
	guidstr = (u'%08x%04x%04x%s%x' % (
		pdb.GUID.Data1, pdb.GUID.Data2, 
		pdb.GUID.Data3, 
		binascii.hexlify(pdb.GUID.Data4).decode('ascii'),
		pdb.Age
	)).upper()
	print("PDB Guid : %s" % (guidstr))

	if guid != guidstr:
		print(u'pdb not for this exe')
		sys.exit(-1)
	else:
		dbi = p.streams[pdbparse.PDB_STREAM_DBI]
		dbi.load()

		for (i,fns) in enumerate(dbi.modules):
			module_name = dbi.DBIExHeaders[i].objName.decode('ascii')
			print("[%d] DBI Module : %s" % (i, module_name))
			for fn in fns:
				print(u'\t%s' % fn)
			print(u'-')	

if __name__ == u'__main__':
	pepath = sys.argv[1]
	main(pepath)


