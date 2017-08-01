#ifndef UNDNAME_H
#define UNDNAME_H

#include "Python.h"

// wine C undname function
char *undname(char *buffer, char *mangled, int buflen, unsigned short int flags);

#ifdef PY3K
// Python module "_undname" entry point for Python3
PyMODINIT_FUNC PyInit__undname(void);
#else
// Python module "_undname" entry point for Python2
PyMODINIT_FUNC init_undname(void);
#endif

#endif