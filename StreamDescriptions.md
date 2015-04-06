# Root Stream #

This stream gives information where to find all other streams in the file. One curious discrepancy is that most PDB files will have two "root" streams: one specified in the overall file header (this one appears to be authoritative) and one stored in stream 0. It is currently unknown why two copies exist.

# Info Stream #

This stream gives general information on the PDB file, including the GUID and timestamp, which can be used to match a PDB with an executable.

# Type Stream #

This stream contains all data structures found in the program. It is documented in somewhat more detail in [this blog post](http://moyix.blogspot.com/2007/10/types-stream.html).

# Debug Info Stream #

This stream contains a great deal of useful information about the meaning of the various streams in the file. It lists the stream numbers for OMAP data, section headers, FPO information, and more, as well as what executable file ranges correspond to what object files.

# Global Symbol Stream #

This stream gives the offsets and (in private symbols) types of all global symbols in the module, including functions and global variables. The addresses given here are pre-OMAP translation, and so must be remapped using the OMAP\_FROM\_SRC stream.

# OMAP Streams #

OMAP data is used for translating addresses between one object layout and another. The [MSDN article on the topic](http://msdn.microsoft.com/en-us/library/windows/desktop/bb870605(v=vs.85).aspx) explains the exact procedure for this. If an executable has been rearranged for some reason, there will generally be two OMAP streams present: OMAP\_FROM\_SRC, which translates from the original addresses to the final module, and OMAP\_TO\_SRC, which does the reverse.

# Section Header Streams #

Some information in the PDB file (such as global address names) may be given in terms of an offset into a given section of the PE file. Thus, the section headers for the PE will generally be placed into a stream in the PDB as well. If the module has been remapped, the original (pre-OMAP) headers will also be included.

# FPOv1 Stream #

FPO data gives information on functions that use the Frame Pointer Omission optimization. Such functions do not use standard EBP-based frames, and their use can prevent correct stack walking. To enable stack walks, PDB files contain FPO information, which gives a debugger information on how to find the next stack frame from an FPO function.

The structures in this stream are documented in the [MSDN article FPO\_DATA](http://msdn.microsoft.com/en-us/library/windows/desktop/ms679352(v=vs.85).aspx).

# FPOv2 Stream #

This stream contains a newer version of the information found in the main FPO stream. A notable addition is the inclusion of "program strings", which are essentially short programs in a postfix language that describe how to transform the variables in one stack frame in order to get to the next. These look like:

`$T0 .raSearch = $eip $T0 ^ = $esp $T0 4 + = $ebx $T0 8 - ^ =`

They are described to some extent in the documentation for the [Google Breakpad symbol format](http://code.google.com/p/google-breakpad/wiki/SymbolFiles), and pdbparse contains an [evaluator for such expressions](http://code.google.com/p/pdbparse/source/browse/trunk/pdbparse/postfix_eval.py).