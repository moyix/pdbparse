#!/usr/bin/env python

from distutils.core import setup, Extension

setup(
    name = 'pdbparse',
    version = '1.4',
    description = 'Python parser for Microsoft PDB files',
    author = 'Brendan Dolan-Gavitt',
    author_email = 'brendandg@gatech.edu',
    url = 'https://github.com/moyix/pdbparse/',
    packages = ['pdbparse'],
    install_requires = ['construct>=2.9', 'pefile'],
    classifiers = [
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
    ],
    python_requires='>=3.8',
    ext_modules = [Extension('pdbparse._undname', sources = ['src/undname.c', 'src/undname_py.c'])],
    include_package_data=True,
    scripts = [
        'examples/pdb_dump.py',
        'examples/pdb_get_syscall_table.py',
        'examples/pdb_lookup.py',
        'examples/pdb_print_ctypes.py',
        'examples/pdb_print_gvars.py',
        'examples/pdb_print_tpi.py',
        'examples/pdb_tpi_vtypes.py',
        'examples/symchk.py',
    ])
