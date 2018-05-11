#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import sys
import operator


# Useful for very coarse version differentiation.
PY3 = sys.version_info[0] == 3

if PY3:
    indexbytes = operator.getitem
    intlist2bytes = bytes
    int2byte = operator.methodcaller('to_bytes', 1, 'big')

else:
    int2byte = chr
    range = xrange

    def indexbytes(buf, i):
        return ord(buf[i])

    def intlist2bytes(l):
        return b"".join(chr(c) for c in l)


