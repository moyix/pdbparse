#!/usr/bin/env python

from distutils.core import setup, Extension

setup(name='pdbparse',
      version='1.1',
      description='Python parser for Microsoft PDB files',
      author='Brendan Dolan-Gavitt',
      author_email='brendandg@gatech.edu',
      url='http://pdbparse.googlecode.com/',
      packages=['pdbparse'],
      requires=['construct', 'pefile'],
      classifiers=[
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
      ],
      ext_modules=[
        Extension('pdbparse._undname', ['src/undname.c'], export_symbols=['undname'])
      ],
      scripts=[
        'examples/get_syscall_table.py',
        'examples/lookup.py',
        'examples/pdbdump.py',
        'examples/print_ctypes.py',
        'examples/print_gvars.py',
        'examples/print_tpi.py',
        'examples/symchk.py',
        'examples/tpi_closure.py',
        'examples/tpi_vtypes.py',
      ]
     )

