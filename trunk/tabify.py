#!/usr/bin/env python
import sys

tabq = []
for line in sys.stdin:
    op = line.count("(")
    ed = line.count(")")
    for i in range(ed-op): tabq.pop()
    sys.stdout.write("".join(tabq) + line)
    for i in range(op-ed): tabq.append("    ")
