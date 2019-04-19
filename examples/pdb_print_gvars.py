#!/usr/bin/env python
from __future__ import print_function

import sys
import pdbparse
from optparse import OptionParser

from pdbparse.pe import Sections
from pdbparse.omap import Omap


class DummyOmap(object):

    def remap(self, addr):
        return addr


def cstring(str):
    return str.split(b'\0')[0]


def main(filename, base_address):
    pdb = pdbparse.parse(filename)
    imgbase = int(base_address, 0)
    try:
        sects = pdb.STREAM_SECT_HDR_ORIG.sections
        omap = pdb.STREAM_OMAP_FROM_SRC
    except AttributeError as e:
        # In this case there is no OMAP, so we use the given section
        # headers and use the identity function for omap.remap
        sects = pdb.STREAM_SECT_HDR.sections
        omap = DummyOmap()

    gsyms = pdb.STREAM_GSYM

    for sym in gsyms.globals:
        try:
            off = sym.offset
            virt_base = sects[sym.segment - 1].VirtualAddress
            nm = cstring(sects[sym.segment - 1].Name)
            print("%s,%#x,%d,%s" % (sym.name, imgbase + omap.remap(off + virt_base), sym.symtype, nm))
        except IndexError as e:
            print("Skipping %s, segment %d does not exist" % (sym.name, sym.segment - 1), file = sys.stderr)
        except AttributeError as e:
            pass


if __name__ == '__main__':

    parser = OptionParser()
    (opts, args) = parser.parse_args()

    if len(args) != 2:
        parser.error("Need filename and base address")

    main(args[0], args[1])
