#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from pympler.asizeof import asizeof


def sizeof(a):
    """
    Deep sizeof()
    :param a:
    :return:
    """
    return asizeof(a)

