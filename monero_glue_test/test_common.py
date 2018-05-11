#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import unittest

import aiounittest

from monero_glue.xmr import crypto, common


class CommonTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(CommonTest, self).__init__(*args, **kwargs)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


