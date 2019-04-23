#!/usr/bin/env python
from __future__ import print_function
import sys, os

from pdbparse.symlookup import Lookup

if __name__ == "__main__":
    try:
        from IPython.frontend.terminal.embed import InteractiveShellEmbed
        ipy = True
    except ImportError:
        import code
        ipy = False

    if len(sys.argv) < 3 or len(sys.argv[1:]) % 2 != 0:
        print("usage: %s <pdb> <base> [[<pdb> <base>] ...]" % sys.argv[0], file = sys.stderr)
        sys.exit(1)

    mods = [(sys.argv[i], int(sys.argv[i + 1], 0)) for i in range(1, len(sys.argv) - 1, 2)]

    lobj = Lookup(mods)
    lookup = lobj.lookup

    banner = "Use lookup(addr) to resolve an address to its nearest symbol"
    if ipy:
        shell = InteractiveShellEmbed(banner2 = banner)
        shell()
    else:
        code.interact(banner = banner, local = locals())
