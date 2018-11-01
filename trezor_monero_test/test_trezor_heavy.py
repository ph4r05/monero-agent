#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from .test_trezor import TrezorTest


class TrezorTestHeavy(TrezorTest):
    def __init__(self, *args, **kwargs):
        super(TrezorTestHeavy, self).__init__(*args, **kwargs)
        self.test_only_tsx = True

    def get_testing_files(self):
        return self.get_trezor_tsx_tests_heavy()
