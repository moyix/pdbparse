#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name='pdbparse',
      version='1.1',
      description='Python parser for Microsoft PDB files',
      author='Brendan Dolan-Gavitt',
      author_email='brendandg@gatech.edu',
      url='http://pdbparse.googlecode.com/',
      packages=['pdbparse'],
      install_requires = [
        'construct<=2.5.2', # last known release from https://github.com/tomerfiliba
        'pefile'
      ],
      classifiers=[
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
      ],
      ext_modules=[
        Extension('pdbparse._undname', ['src/undname.c'], export_symbols=['undname'])
      ],
      scripts=[
        'examples/pdb_dump.py',
        'examples/pdb_get_syscall_table.py',
        'examples/pdb_lookup.py',
        'examples/pdb_print_ctypes.py',
        'examples/pdb_print_gvars.py',
        'examples/pdb_print_tpi.py',
        'examples/pdb_tpi_vtypes.py',
        'examples/symchk.py',
      ]
     )
