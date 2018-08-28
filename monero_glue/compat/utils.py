#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import sys


def memcpy(dst, dst_off, src, src_off, len):
    for i in range(len):
        dst[dst_off + i] = src[src_off + i]
    return dst


def unimport_begin():
    return set(sys.modules)


def unimport_end(mods):
    pass
