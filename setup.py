#!/usr/bin/env python

from distutils.core import setup

setup(name='pdbparse',
      version='1.0',
      description='Python parser for Microsoft PDB files',
      author='Brendan Dolan-Gavitt',
      author_email='brendandg@gatech.edu',
      url='http://pdbparse.googlecode.com/',
      packages=['pdbparse'],
      requires=['construct'],
      classifiers=[
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Operating System :: OS Independent',
      ],
     )

