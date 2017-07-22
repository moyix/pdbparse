#include "undname.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

// Should work as is on Python 2.7
#if PY_MAJOR_VERSION >= 3
#define IS_PY3K

#include "Python.h"
#include "bytesobject.h"


static PyObject* undname_py(PyObject* self,PyObject* args)
{
    Py_buffer buffer;
    Py_buffer mangled;
    PyObject *return_value;

    int buflen;
    unsigned short int flags;
    char *out;

    if (!PyArg_ParseTuple(args, "s*s*iH", &buffer, &mangled, &buflen, &flags));
        return NULL;

    Py_INCREF(buffer);
    Py_INCREF(mangled);
    out = undname(buffer->buf, mangled->buf, buflen, flags);
    if (!out)
        return NULL;
    Py_DECREF(buffer);
    Py_DECREF(mangled);

    return_value = Py_BuildValue("s",out);
    Py_INCREF(return_value);

    // Discaring temporary unmangled buffer
    free(out);

    return return_value;
}

static PyMethodDef undname_methods[] = {
    {"undname", (PyCFunction)undname_py, METH_VARARGS, "Undecorate mangled C++ names"},
    {NULL, NULL}
};


static struct PyModuleDef cUndnameModule =
{
    PyModuleDef_HEAD_INIT,
    "undname",   /* name of module */
    "",          /* module documentation, may be NULL */
    -1,          /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
    undname_methods
};

PyMODINIT_FUNC PyInit_undname(void)
{
    return PyModule_Create(&cUndnameModule);
}

#endif