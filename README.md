# pdbparse
Automatically exported from code.google.com/p/pdbparse

PDBparse is a GPL-licensed library for parsing Microsoft PDB files. Support for these is already available within Windows through the Debug Interface Access API, however, this interface is not usable on other operating systems.

PDB files are arranged into streams, each of which contains a specific bit of debug information; for example, stream 1 contains general information on the PDB file, and stream 2 contains information on data structures.

Currently, there is support for Microsoft PDB version 7 files (Vista and most Windows XP symbols) as well as version 2 (Windows 2000 and some XP symbols). The following streams are currently supported (see [StreamDescriptions](https://code.google.com/p/pdbparse/wiki/StreamDescriptions) for more information on these):

* Root Stream
* Info Stream
* Type Stream
* Debug Info Stream
* Global Symbol Stream
* OMAP Streams
* Section Header Streams
* FPOv1 Stream
* FPOv2 Stream 

The open-source library [Construct](http://construct.wikispaces.com/) is used to perform the low-level parsing, and is required to run the code. 
