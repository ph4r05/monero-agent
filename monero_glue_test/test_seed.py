#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
from binascii import unhexlify
import unittest

import aiounittest

from monero_glue.xmr import crypto
from monero_glue.xmr.sub.seed import SeedDerivation
from monero_glue.xmr.sub.xmr_net import NetworkTypes


class SeedTest(aiounittest.AsyncTestCase):
    """Simple seed tests"""

    def __init__(self, *args, **kwargs):
        super(SeedTest, self).__init__(*args, **kwargs)

    def recode_int(self, bts):
        return crypto.encodeint(crypto.decodeint(bts))

    def test_bip44_1(self):
        seed_wlist = "permit universe parent weapon amused modify essay borrow tobacco budget walnut lunch consider gallery ride amazing frog forget treat market chapter velvet useless topple"
        d = SeedDerivation.from_mnemonics(seed_wlist.split(" "))

        self.assertEqual(
            d.creds(network_type=NetworkTypes.MAINNET).address,
            b"42uUdtM9DyXTrGxYkyN8KW2myWJo5G71QiKyzheGHhRHY5khGGg4B7UfwzeQezzx65H9QPn2XtKqPHm7rRS1CQNpMFY3wud",
        )
        self.assertEqual(
            d.creds(network_type=NetworkTypes.TESTNET).address,
            b"9tT2891QWLdTrGxYkyN8KW2myWJo5G71QiKyzheGHhRHY5khGGg4B7UfwzeQezzx65H9QPn2XtKqPHm7rRS1CQNpMDDNrji",
        )

    def test_bip44_2(self):
        seed_wlist = "imitate lonely burden old genius trip identify wine walnut forget truly industry quarter october rug public stone rival photo more whip sample fix shrimp"
        d = SeedDerivation.from_mnemonics(seed_wlist.split(" "))

        self.assertEqual(
            d.creds(network_type=NetworkTypes.MAINNET).address,
            b"4AyUd1U6H3jSj2gbbaAyMm8wh3Xoah23x7Pm2SycZkURbHEbRoine8dE2QpJj5sEwp3YBy3z98K9t38Yzv4Fd8o69oTEnoB",
        )

    def test_slip0010_1(self):
        """
        https://github.com/satoshilabs/slips/blob/master/slip-0010.md
        :return:
        """
        seed = unhexlify(b"000102030405060708090a0b0c0d0e0f")

        d = SeedDerivation.from_master_seed(seed, slip0010=True, path="m")
        self.assertEqual(
            d.monero_master,
            self.recode_int(
                unhexlify(
                    b"2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"
                )
            ),
        )
        self.assertEqual(
            d.creds(network_type=NetworkTypes.MAINNET).address,
            b"44DybmHAKoojjhn4C57qqZeKQNXBGWznYhKuRHD3LvmyLCN2UxZfcTRLnCQASiyevEYg9szQqrdNeN6tXFa4xw484BSvd4r",
        )

        # m/0'
        d = SeedDerivation.from_master_seed(seed, slip0010=True, path="m/0'")
        self.assertEqual(
            d.monero_master,
            self.recode_int(
                unhexlify(
                    b"68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"
                )
            ),
        )

        # m/0'/1'/2'/2'/1000000000'
        d = SeedDerivation.from_master_seed(
            seed, slip0010=True, path="m/0'/1'/2'/2'/1000000000'"
        )
        self.assertEqual(
            d.monero_master,
            self.recode_int(
                unhexlify(
                    b"8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
                )
            ),
        )

    def test_slip0010_2(self):
        """
        https://github.com/satoshilabs/slips/blob/master/slip-0010.md
        :return:
        """
        seed = unhexlify(
            b"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        )

        # m'
        d = SeedDerivation.from_master_seed(seed, slip0010=True, path="m")
        self.assertEqual(
            d.monero_master,
            self.recode_int(
                unhexlify(
                    b"171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012"
                )
            ),
        )

        # m/0'
        d = SeedDerivation.from_master_seed(seed, slip0010=True, path="m/0'")
        self.assertEqual(
            d.monero_master,
            self.recode_int(
                unhexlify(
                    b"1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635"
                )
            ),
        )

        # m/0H/2147483647H/1H/2147483646H/2H
        d = SeedDerivation.from_master_seed(
            seed, slip0010=True, path="m/0'/2147483647'/1'/2147483646'/2'"
        )
        self.assertEqual(
            d.monero_master,
            self.recode_int(
                unhexlify(
                    b"551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d"
                )
            ),
        )

    def test_slip0010_3(self):
        seed_wlist = "permit universe parent weapon amused modify essay borrow tobacco budget walnut lunch consider gallery ride amazing frog forget treat market chapter velvet useless topple"
        d = SeedDerivation.from_mnemonics(seed_wlist.split(" "), slip0010=True)

        self.assertEqual(
            d.creds(network_type=NetworkTypes.MAINNET).address,
            b"497MP7bh5MkCZ1TiZZoYi84s39n5V5HpSgPvrqqUMqw6XcWDu4QhBs4VkqiPsNMhTUPAHHE6DUo9UUqpfSZfxkANPw44Fgn",
        )
        self.assertEqual(
            d.creds(network_type=NetworkTypes.TESTNET).address,
            b"9zetsNFxMirCZ1TiZZoYi84s39n5V5HpSgPvrqqUMqw6XcWDu4QhBs4VkqiPsNMhTUPAHHE6DUo9UUqpfSZfxkANPwbdsur",
        )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
