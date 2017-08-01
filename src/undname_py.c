#include "undname.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#if PY_MAJOR_VERSION >= 3
#define PY3K
#endif

static const char undname_doc[] = ""                                  \
"undname(mangled: str or bytes,flags : int) -> str \n\n"              \
"Undecorate mangled C++ names. Take a mangled str name and flags.\n"  \
"Return the unmangled name or None if it can not be undecorated.";

static PyObject* undname_py(PyObject* self,PyObject* args)
{
    Py_buffer mangled;
    PyObject *return_value;

    unsigned short int flags = 0;
    char *out;

    if (!PyArg_ParseTuple(args, "s*H:undname", &mangled, &flags))
        return Py_None;
        
    // passing NULL as buffer : dynamic allocation used
    out = undname(NULL, (char*) mangled.buf, (int) mangled.len, flags);
    if (!out)
        return Py_None;


    return_value = Py_BuildValue("s",out);
    Py_INCREF(return_value);

    // Discaring temporary unmangled bufferhelp
    free(out);

    return return_value;
}

static PyMethodDef undname_methods[] = {
    {"undname", undname_py, METH_VARARGS, undname_doc},
    {NULL, NULL, 0, NULL}
};



#ifdef PY3K
// module definition structure for python3
static struct PyModuleDef cUndnameModule =
{
    PyModuleDef_HEAD_INIT,
    "_undname",   /* name of module */
    "_undname module. Provide undname() function for symbol undecoration",       /* module documentation, may be NULL */
    -1,          /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    undname_methods
};

PyMODINIT_FUNC PyInit__undname(void)
{
    return PyModule_Create(&cUndnameModule);
}
#else
// module initializer for python2
PyMODINIT_FUNC init_undname(void) {
    Py_InitModule3("_undname", undname_methods, "_undname module. Provide undname() function for symbol undecoration");
}
#endif