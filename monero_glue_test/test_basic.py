#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import unittest

import aiounittest


class Basetest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(Basetest, self).__init__(*args, **kwargs)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


