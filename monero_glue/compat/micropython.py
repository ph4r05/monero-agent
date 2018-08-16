#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


def const(x):
    return x


def stack_use(*args, **kwargs):
    return


def memcpy(dst, dst_off, src, src_off, len):
    for i in range(len):
        dst[dst_off + i] = src[src_off + i]
    return dst
