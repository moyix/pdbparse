#!/usr/bin/env python
''' 
Download debugging symbols from the Microsoft Symbol Server. 
Can use as an input an executable file OR a GUID+Age and filename.
Examples:

$ python symcheck.py -e ntoskrnl.exe

$ python symchk.py -g 32962337f0f646388b39535cd8dd70e82 -s ntoskrnl.pdb
The GUID+Age here corresponds to the kernel version of the xp-laptop-2005-* images
The Age value is 0x2.


Module Dependencies:
This script requires the following modules:
pefile - http://code.google.com/p/pefile/
construct - http://construct.wikispaces.com/
To decompress downloaded files you should also have cabextract on your system.
http://www.cabextract.org.uk/

License: 
GPL version 3
http://www.gnu.org/licenses/gpl.html

Miscellaneous References:
You can see an explanation of the URL format at:
http://jimmers.info/pdb.html
'''

import sys, os
import os.path
from pefile import PE
from shutil import copyfileobj

from pdbparse.peinfo import *

try:
    from urllib.parse import urlparse, urlencode
    from urllib.request import urlopen, Request, build_opener, FancyURLopener
    from urllib.error import HTTPError
except ImportError:
    from urlparse import urlparse
    from urllib import urlencode
    from urllib2 import urlopen, Request, HTTPError, build_opener
    from urllib import FancyURLopener

#SYM_URL = 'http://symbols.mozilla.org/firefox'
SYM_URLS = ['http://msdl.microsoft.com/download/symbols']
USER_AGENT = "Microsoft-Symbol-Server/6.11.0001.404"


class PDBOpener(FancyURLopener):
    version = USER_AGENT

    def http_error_default(self, url, fp, errcode, errmsg, headers):
        if errcode == 404:
            raise HTTPError(url, errcode, errmsg, headers, fp)
        else:
            FancyURLopener.http_error_default(url, fp, errcode, errmsg, headers)


lastprog = None


def progress(blocks, blocksz, totalsz):
    global lastprog
    if lastprog is None:
        print("Connected. Downloading data...")
    percent = int((100 * (blocks * blocksz) / float(totalsz)))
    if lastprog != percent and percent % 5 == 0: print("%d%%" % percent)
    lastprog = percent
    sys.stdout.flush()


def download_file(guid, fname, path = "", quiet = False):
    ''' 
    Download the symbols specified by guid and filename. Note that 'guid'
    must be the GUID from the executable with the dashes removed *AND* the
    Age field appended. The resulting file will be saved to the path argument,
    which default to the current directory.
    '''

    # A normal GUID is 32 bytes. With the age field appended
    # the GUID argument should therefore be longer to be valid.
    # Exception: old-style PEs without a debug section use
    # TimeDateStamp+SizeOfImage
    if len(guid) == 32:
        print("Warning: GUID is too short to be valid. Did you append the Age field?")

    for sym_url in SYM_URLS:
        url = sym_url + "/%s/%s/" % (fname, guid)
        opener = build_opener()

        # Whatever extension the user has supplied it must be replaced with .pd_
        tries = [fname[:-1] + '_', fname]

        for t in tries:
            if not quiet: print("Trying %s" % (url + t))
            outfile = os.path.join(path, t)
            try:
                hook = None if quiet else progress
                PDBOpener().retrieve(url + t, outfile, reporthook = hook)
                if not quiet:
                    print()
                    print("Saved symbols to %s" % (outfile))
                return outfile
            except HTTPError as e:
                if not quiet:
                    print("HTTP error %u" % (e.code))
    return None


def handle_pe(pe_file):
    dbgdata, tp = get_pe_debug_data(pe_file)
    if tp == "IMAGE_DEBUG_TYPE_CODEVIEW":
        # XP+
        if dbgdata[:4] == b"RSDS":
            (guid, filename) = get_rsds(dbgdata)
        elif dbgdata[:4] == b"NB10":
            (guid, filename) = get_nb10(dbgdata)
        else:
            print("ERR: CodeView section not NB10 or RSDS")
            return
        guid = guid.upper()
        saved_file = download_file(guid, filename)
    elif tp == "IMAGE_DEBUG_TYPE_MISC":
        # Win2k
        # Get the .dbg file
        guid = get_pe_guid(pe_file)
        guid = guid.upper()
        filename = get_dbg_fname(dbgdata)
        saved_file = download_file(guid, filename)

        # Extract it if it's compressed
        # Note: requires cabextract!
        if saved_file.endswith("_"):
            os.system("cabextract %s" % saved_file)
            saved_file = saved_file.replace('.db_', '.dbg')

        from pdbparse.dbgold import DbgFile
        dbgfile = DbgFile.parse_stream(open(saved_file, 'rb'))
        cv_entry = [d for d in dbgfile.IMAGE_DEBUG_DIRECTORY if d.Type == "IMAGE_DEBUG_TYPE_CODEVIEW"][0]
        if cv_entry.Data[:4] == b"NB09":
            return
        elif cv_entry.Data[:4] == b"NB10":
            (guid, filename) = get_nb10(cv_entry.Data)

            guid = guid.upper()
            saved_file = download_file(guid, filename)
        else:
            print("WARN: DBG file received from symbol server has unknown CodeView section")
            return
    else:
        print("Unknown type:", tp)
        return

    if saved_file != None and saved_file.endswith("_"):
        os.system("cabextract %s" % saved_file)


def get_pe_from_pe(filename, symname = None):
    guid = get_pe_guid(filename)
    if symname is None:
        symname = os.path.basename(filename)
    saved_file = download_file(guid, symname)
    if saved_file and saved_file.endswith("_"):
        os.system("cabextract %s" % saved_file)


def main():
    global SYM_URLS
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option('-e', '--executable', dest = 'exe', help = 'download symbols for an executable')
    parser.add_option('-p', '--pefile', dest = 'pe', help = 'download clean copy of an executable')
    parser.add_option('-g', '--guid', dest = 'guid', help = 'use GUID to download symbols [Note: requires -s]')
    parser.add_option(
        '-s',
        '--symbols',
        dest = 'symfile',
        metavar = 'FILENAME',
        help = 'use FILENAME to download symbols [Note: requires -g]')
    parser.add_option(
        '-u',
        '--url',
        dest = 'url',
        metavar = 'URL',
        help = ('use * separated URLs to search for symbols, e.g. ' +
                '"http://foo.com*http://bar.com". You may also set ' + 'the SYMPATH environment variable'))

    opts, args = parser.parse_args()

    if opts.url:
        SYM_URLS = opts.url.split('*')
    elif os.getenv('SYMPATH'):
        SYM_URLS = os.environ['SYMPATH'].split('*')

    if opts.exe:
        handle_pe(opts.exe)
    if opts.pe:
        get_pe_from_pe(opts.pe, symname = opts.symfile)
    if opts.guid and opts.symfile:
        saved_file = download_file(opts.guid, opts.symfile)
        if saved_file is not None:
            if saved_file.endswith("_"):
                os.system("cabextract %s" % saved_file)

    if not (opts.exe or opts.guid or opts.symfile or opts.pe) and args:
        for a in args:
            handle_pe(a)
    elif not (opts.exe or opts.guid or opts.symfile or opts.pe) and not args:
        parser.error("Must supply a PE file or specify by GUID")


if __name__ == "__main__":
    main()
