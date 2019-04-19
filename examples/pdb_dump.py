#!/usr/bin/env python

from os.path import basename
import pdbparse
import sys


def main(pdbfilepath):
    pdb = pdbparse.parse(pdbfilepath, fast_load = True)
    if len(sys.argv) > 2:
        streams = [pdb.streams[int(i)] for i in sys.argv[2:]]
    else:
        streams = pdb.streams

    for stream in streams:
        ofname = basename(pdb.fp.name) + ('.%03d' % stream.index)
        with open(ofname, 'wb') as f:
            f.write(stream.data)


if __name__ == "__main__":
    main(sys.argv[1])
