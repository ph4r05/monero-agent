#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


import collections


class CallTracker(object):
    """
    Tracks method invocations in the given object / module
    """
    def __init__(self, base, print_on_end=False):
        self.base = base
        self.t = collections.defaultdict(lambda: 0)
        self.print_on_end = print_on_end

    def __getattr__(self, name):
        def handler(*args, **kwargs):
            self.t[name] += 1
            return getattr(self.base, name)(*args, **kwargs)

        return handler

    def __del__(self):
        if self.print_on_end:
            k = sorted(self.t.keys())
            for kk in k:
                print('  %s: %s' % (kk, self.t[kk]))

    def call_tracker_get_call_stats(self):
        return self.t


