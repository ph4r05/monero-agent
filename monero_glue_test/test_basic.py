#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import base64
import unittest
import pkg_resources

import asyncio
import aiounittest

from mnero import mininero


__author__ = 'dusanklinec'


class Basetest(unittest.TestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(Basetest, self).__init__(*args, **kwargs)

    def test_base(self):
        mininero.b58encode(b'123')


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


