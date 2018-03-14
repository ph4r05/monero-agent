#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import random
import base64
import unittest
import pkg_resources
import requests
import asyncio
import aiounittest
import binascii


from monero_glue import b58_mnr


class Base58Test(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(Base58Test, self).__init__(*args, **kwargs)

    def test_base(self):
        """
        Simple b58 encode test
        :return:
        """
        self.assertIsNotNone(b58_mnr.b58encode(b''))
        self.assertIsNotNone(b58_mnr.b58encode(b'1234567890'))
        self.assertIsNotNone(b58_mnr.b58encode(b'1234567890'*50))
        self.assertEqual(
            b58_mnr.b58encode(
                b'123bec484c5d7f0246af520aab550452b5b6013733feabebd681c4a60d457b7fc12d5918e31d3c003da3c778592c07b398ad6f9'
                b'61a67082a75fd49394d51e69bbea9a6e386'),
            b'43tpGG9PKbwCpjRvNLn1jwXPpnacw2uVUcszAtgmDiVcZK4VgHwjJT9BJz1WGF9eMxSYASp8yNMkuLjeQfWqJn3CNWdWfzV')


if __name__ == "__main__":
    unittest.main()  # pragma: no cover

