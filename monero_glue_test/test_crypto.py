#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
import unittest

import aiounittest
from monero_glue.xmr import common, crypto
from monero_glue.xmr.core import ec_py


class CryptoTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(CryptoTest, self).__init__(*args, **kwargs)

    def test_ed_crypto(self):
        sqr = ec_py.fe_expmod(ec_py.py_fe_sqrtm1, 2)
        self.assertEqual(sqr, ec_py.fe_mod(-1))
        self.assertEqual(
            ec_py.py_fe_A, ec_py.fe_mod(2 * (1 - ec_py.d) * ec_py.inv(1 + ec_py.py_d))
        )

        self.assertEqual(
            ec_py.fe_expmod(ec_py.py_fe_fffb1, 2),
            ec_py.fe_mod(-2 * ec_py.py_fe_A * (ec_py.py_fe_A + 2)),
        )
        self.assertEqual(
            ec_py.fe_expmod(ec_py.py_fe_fffb2, 2),
            ec_py.fe_mod(2 * ec_py.py_fe_A * (ec_py.py_fe_A + 2)),
        )
        self.assertEqual(
            ec_py.fe_expmod(ec_py.py_fe_fffb3, 2),
            ec_py.fe_mod(-ec_py.py_fe_sqrtm1 * ec_py.py_fe_A * (ec_py.py_fe_A + 2)),
        )
        self.assertEqual(
            ec_py.fe_expmod(ec_py.py_fe_fffb4, 2),
            ec_py.fe_mod(ec_py.py_fe_sqrtm1 * ec_py.py_fe_A * (ec_py.py_fe_A + 2)),
        )

    def test_encoding(self):
        point = bytes(
            [
                0x24,
                0x86,
                0x22,
                0x47,
                0x97,
                0xd0,
                0x5c,
                0xae,
                0x3c,
                0xba,
                0x4b,
                0xe0,
                0x43,
                0xbe,
                0x2d,
                0xb0,
                0xdf,
                0x38,
                0x1f,
                0x3f,
                0x19,
                0xcf,
                0xa1,
                0x13,
                0xf8,
                0x6a,
                0xb3,
                0x8e,
                0x3d,
                0x8d,
                0x2b,
                0xd0,
            ]
        )
        self.assertEqual(point, crypto.encodepoint(crypto.decodepoint(point)))
        self.assertTrue(
            crypto.point_eq(
                crypto.decodepoint(point),
                crypto.decodepoint(crypto.encodepoint(crypto.decodepoint(point))),
            )
        )

    def test_scalarmult_base(self):
        scalar = crypto.decodeint(
            bytes(
                [
                    0xa0,
                    0xee,
                    0xa4,
                    0x91,
                    0x40,
                    0xa3,
                    0xb0,
                    0x36,
                    0xda,
                    0x30,
                    0xea,
                    0xcf,
                    0x64,
                    0xbd,
                    0x9d,
                    0x56,
                    0xce,
                    0x3e,
                    0xf6,
                    0x8b,
                    0xa8,
                    0x2e,
                    0xf1,
                    0x35,
                    0x71,
                    0xec,
                    0x51,
                    0x1e,
                    0xdb,
                    0xcf,
                    0x83,
                    0x03,
                ]
            )
        )
        exp = bytes(
            [
                0x16,
                0xbb,
                0x4a,
                0x3c,
                0x44,
                0xe2,
                0xce,
                0xd5,
                0x11,
                0xfc,
                0x0d,
                0x4c,
                0xd8,
                0x6b,
                0x13,
                0xb3,
                0xaf,
                0x21,
                0xef,
                0xc9,
                0x9f,
                0xb0,
                0x35,
                0x61,
                0x99,
                0xfa,
                0xc4,
                0x89,
                0xf2,
                0x54,
                0x4c,
                0x09,
            ]
        )
        res = crypto.scalarmult_base(scalar)
        self.assertEqual(exp, crypto.encodepoint(res))
        self.assertTrue(crypto.point_eq(crypto.decodepoint(exp), res))

        scalar = crypto.decodeint(
            bytes(
                [
                    0xfd,
                    0x29,
                    0x0d,
                    0xce,
                    0x39,
                    0xf7,
                    0x81,
                    0xae,
                    0xbb,
                    0xdb,
                    0xd2,
                    0x45,
                    0x84,
                    0xed,
                    0x6d,
                    0x48,
                    0xbd,
                    0x30,
                    0x0d,
                    0xe1,
                    0x9d,
                    0x9c,
                    0x3d,
                    0xec,
                    0xfd,
                    0xa0,
                    0xa6,
                    0xe2,
                    0xc6,
                    0x75,
                    0x1d,
                    0x0f,
                ]
            )
        )
        exp = bytes(
            [
                0x12,
                0x3d,
                0xaf,
                0x90,
                0xfc,
                0x26,
                0xf1,
                0x3c,
                0x65,
                0x29,
                0xe6,
                0xb4,
                0x9b,
                0xfe,
                0xd4,
                0x98,
                0x99,
                0x5a,
                0xc3,
                0x83,
                0xef,
                0x19,
                0xc0,
                0xdb,
                0x67,
                0x71,
                0x14,
                0x3f,
                0x24,
                0xba,
                0x8d,
                0xd5,
            ]
        )
        res = crypto.scalarmult_base(scalar)
        self.assertEqual(exp, crypto.encodepoint(res))
        self.assertTrue(crypto.point_eq(crypto.decodepoint(exp), res))

    def test_scalarmult(self):
        priv = bytes(
            [
                0x34,
                0x82,
                0xfb,
                0x97,
                0x35,
                0xef,
                0x87,
                0x9f,
                0xca,
                0xe5,
                0xec,
                0x77,
                0x21,
                0xb5,
                0xd3,
                0x64,
                0x6e,
                0x15,
                0x5c,
                0x4f,
                0xb5,
                0x8d,
                0x6c,
                0xc1,
                0x1c,
                0x73,
                0x2c,
                0x9c,
                0x9b,
                0x76,
                0x62,
                0x0a,
            ]
        )
        pub = bytes(
            [
                0x24,
                0x86,
                0x22,
                0x47,
                0x97,
                0xd0,
                0x5c,
                0xae,
                0x3c,
                0xba,
                0x4b,
                0xe0,
                0x43,
                0xbe,
                0x2d,
                0xb0,
                0xdf,
                0x38,
                0x1f,
                0x3f,
                0x19,
                0xcf,
                0xa1,
                0x13,
                0xf8,
                0x6a,
                0xb3,
                0x8e,
                0x3d,
                0x8d,
                0x2b,
                0xd0,
            ]
        )
        exp = bytes(
            [
                0xad,
                0xcd,
                0x1f,
                0x58,
                0x81,
                0xf4,
                0x6f,
                0x25,
                0x49,
                0x00,
                0xa0,
                0x3c,
                0x65,
                0x4e,
                0x71,
                0x95,
                0x0a,
                0x88,
                0xa0,
                0x23,
                0x6f,
                0xa0,
                0xa3,
                0xa9,
                0x46,
                0xc9,
                0xb8,
                0xda,
                0xed,
                0x6e,
                0xf4,
                0x3d,
            ]
        )
        res = crypto.scalarmult(crypto.decodepoint(pub), crypto.decodeint(priv))
        self.assertEqual(exp, crypto.encodepoint(res))
        self.assertTrue(crypto.point_eq(crypto.decodepoint(exp), res))

    def test_cn_fast_hash(self):
        inp = bytes(
            [
                0x25,
                0x9e,
                0xf2,
                0xab,
                0xa8,
                0xfe,
                0xb4,
                0x73,
                0xcf,
                0x39,
                0x05,
                0x8a,
                0x0f,
                0xe3,
                0x0b,
                0x9f,
                0xf6,
                0xd2,
                0x45,
                0xb4,
                0x2b,
                0x68,
                0x26,
                0x68,
                0x7e,
                0xbd,
                0x6b,
                0x63,
                0x12,
                0x8a,
                0xff,
                0x64,
                0x05,
            ]
        )
        res = crypto.cn_fast_hash(inp)
        self.assertEqual(
            res,
            bytes(
                [
                    0x86,
                    0xdb,
                    0x87,
                    0xb8,
                    0x3f,
                    0xb1,
                    0x24,
                    0x6e,
                    0xfc,
                    0xa5,
                    0xf3,
                    0xb0,
                    0xdb,
                    0x09,
                    0xce,
                    0x3f,
                    0xa4,
                    0xd6,
                    0x05,
                    0xb0,
                    0xd1,
                    0x0e,
                    0x65,
                    0x07,
                    0xca,
                    0xc2,
                    0x53,
                    0xdd,
                    0x31,
                    0xa3,
                    0xec,
                    0x16,
                ]
            ),
        )

    def test_hash_to_scalar(self):
        inp = bytes(
            [
                0x25,
                0x9e,
                0xf2,
                0xab,
                0xa8,
                0xfe,
                0xb4,
                0x73,
                0xcf,
                0x39,
                0x05,
                0x8a,
                0x0f,
                0xe3,
                0x0b,
                0x9f,
                0xf6,
                0xd2,
                0x45,
                0xb4,
                0x2b,
                0x68,
                0x26,
                0x68,
                0x7e,
                0xbd,
                0x6b,
                0x63,
                0x12,
                0x8a,
                0xff,
                0x64,
                0x05,
            ]
        )
        res = crypto.hash_to_scalar(inp)
        exp = crypto.decodeint(binascii.unhexlify(
            b"9907925b254e12162609fc0dfd0fef2aa4d605b0d10e6507cac253dd31a3ec06"))
        self.assertTrue(crypto.sc_eq(res, exp))

    def test_hash_to_point(self):
        data = bytes(
            [
                0x42,
                0xf6,
                0x83,
                0x5b,
                0xf8,
                0x31,
                0x14,
                0xa1,
                0xf5,
                0xf6,
                0x07,
                0x6f,
                0xe7,
                0x9b,
                0xdf,
                0xa0,
                0xbd,
                0x67,
                0xc7,
                0x4b,
                0x88,
                0xf1,
                0x27,
                0xd5,
                0x45,
                0x72,
                0xd3,
                0x91,
                0x0d,
                0xd0,
                0x92,
                0x01,
            ]
        )
        res = crypto.hash_to_ec(data)
        res_p = crypto.encodepoint(res)
        self.assertEqual(
            res_p,
            bytes(
                [
                    0x54,
                    0x86,
                    0x3a,
                    0x04,
                    0x64,
                    0xc0,
                    0x08,
                    0xac,
                    0xc9,
                    0x9c,
                    0xff,
                    0xb1,
                    0x79,
                    0xbc,
                    0x6c,
                    0xf3,
                    0x4e,
                    0xb1,
                    0xbb,
                    0xdf,
                    0x6c,
                    0x29,
                    0xf7,
                    0xa0,
                    0x70,
                    0xa7,
                    0xc6,
                    0x37,
                    0x6a,
                    0xe3,
                    0x0a,
                    0xb5,
                ]
            ),
        )

    def test_derivation_to_scalar(self):
        derivation = bytes(
            [
                0xe7,
                0x20,
                0xa0,
                0x9f,
                0x2e,
                0x3a,
                0x0b,
                0xbf,
                0x4e,
                0x4b,
                0xa7,
                0xad,
                0x93,
                0x65,
                0x3b,
                0xb2,
                0x96,
                0x88,
                0x55,
                0x10,
                0x12,
                0x1f,
                0x80,
                0x6a,
                0xcb,
                0x2a,
                0x5f,
                0x91,
                0x68,
                0xfa,
                0xfa,
                0x01,
            ]
        )
        scalar = bytes(
            [
                0x25,
                0xd0,
                0x87,
                0x63,
                0x41,
                0x4c,
                0x37,
                0x9a,
                0xa9,
                0xcf,
                0x98,
                0x9c,
                0xdc,
                0xb3,
                0xca,
                0xdd,
                0x36,
                0xbd,
                0x51,
                0x93,
                0xb5,
                0x00,
                0x10,
                0x7d,
                0x6b,
                0xf5,
                0xf9,
                0x21,
                0xf1,
                0x8e,
                0x47,
                0x0e,
            ]
        )
        sc_int = crypto.derivation_to_scalar(crypto.decodepoint(derivation), 0)
        self.assertEqual(scalar, crypto.encodeint(sc_int))

    def test_generate_key_derivation(self):
        key_pub = crypto.decodepoint(
            bytes(
                [
                    0x77,
                    0x39,
                    0xc9,
                    0x5d,
                    0x32,
                    0x98,
                    0xe2,
                    0xf8,
                    0x73,
                    0x62,
                    0xdb,
                    0xa9,
                    0xe0,
                    0xe0,
                    0xb3,
                    0x98,
                    0x0a,
                    0x69,
                    0x2a,
                    0xe8,
                    0xe2,
                    0xf1,
                    0x67,
                    0x96,
                    0xb0,
                    0xe3,
                    0x82,
                    0x09,
                    0x8c,
                    0xd6,
                    0xbd,
                    0x83,
                ]
            )
        )
        key_priv = crypto.decodeint(
            bytes(
                [
                    0x34,
                    0x82,
                    0xfb,
                    0x97,
                    0x35,
                    0xef,
                    0x87,
                    0x9f,
                    0xca,
                    0xe5,
                    0xec,
                    0x77,
                    0x21,
                    0xb5,
                    0xd3,
                    0x64,
                    0x6e,
                    0x15,
                    0x5c,
                    0x4f,
                    0xb5,
                    0x8d,
                    0x6c,
                    0xc1,
                    0x1c,
                    0x73,
                    0x2c,
                    0x9c,
                    0x9b,
                    0x76,
                    0x62,
                    0x0a,
                ]
            )
        )
        deriv_exp = bytes(
            [
                0xfa,
                0x18,
                0x8a,
                0x45,
                0xa0,
                0xe4,
                0xda,
                0xcc,
                0xc0,
                0xe6,
                0xd4,
                0xf6,
                0xf6,
                0x85,
                0x8f,
                0xd4,
                0x63,
                0x92,
                0x10,
                0x4b,
                0xe7,
                0x41,
                0x83,
                0xec,
                0x00,
                0x47,
                0xe7,
                0xe9,
                0xf4,
                0xea,
                0xf7,
                0x39,
            ]
        )
        self.assertEqual(
            deriv_exp,
            crypto.encodepoint(crypto.generate_key_derivation(key_pub, key_priv)),
        )

    def test_h(self):
        H = bytes(
            [
                0x8b,
                0x65,
                0x59,
                0x70,
                0x15,
                0x37,
                0x99,
                0xaf,
                0x2a,
                0xea,
                0xdc,
                0x9f,
                0xf1,
                0xad,
                0xd0,
                0xea,
                0x6c,
                0x72,
                0x51,
                0xd5,
                0x41,
                0x54,
                0xcf,
                0xa9,
                0x2c,
                0x17,
                0x3a,
                0x0d,
                0xd3,
                0x9c,
                0x1f,
                0x94,
            ]
        )
        self.assertEqual(crypto.encodepoint(crypto.gen_H()), H)

    def test_h_pow(self):
        hp = crypto.gen_Hpow(10)
        self.assertEqual(crypto.encodepoint(hp[0]), crypto.encodepoint(crypto.gen_H()))
        for i in range(1, 10):
            crypto.check_ed25519point(hp[i])
            self.assertEqual(
                crypto.encodepoint(hp[i]),
                crypto.encodepoint(
                    crypto.scalarmult(crypto.gen_H(), crypto.sc_init(2 ** i))
                ),
            )

    def test_signature(self):
        for i in range(10):
            priv = crypto.random_scalar()
            data = crypto.cn_fast_hash(bytes(bytearray([i])))

            c, r, pub = crypto.generate_signature(data, priv)
            res = crypto.check_signature(data, c, r, pub)
            self.assertEqual(res, 1)

            res2 = crypto.check_signature(
                data, crypto.sc_add(c, crypto.sc_init(1)), r, pub
            )
            self.assertEqual(res2, 0)

    def test_edhex(self):
        inputs = [crypto.q - 2 ** 9, crypto.q - 10, 0, 100, 2 ** 200 + 10] + [
            common.rand.randrange(0, crypto.q - 2) for _ in range(20)
        ]

        for x in inputs:
            l = crypto.encode_ed25519(x)
            d = crypto.decode_ed25519(l)
            self.assertEqual(x, d)

    def test_modm(self):
        inputs = [crypto.l - 2 ** 9, crypto.l - 10, 0, 100, 2 ** 200 + 10] + [
            common.rand.randrange(0, crypto.l - 2) for _ in range(20)
        ]

        for x in inputs:
            l = crypto.encode_modm(x)
            d = crypto.decode_modm(l)
            self.assertEqual(x, d)

    def test_ge25519_double_scalarmult_vartime2(self):
        for i in range(10):
            ap = crypto.random_scalar()
            bp = crypto.random_scalar()
            A = crypto.scalarmult_base(ap)
            B = crypto.scalarmult_base(bp)
            a = crypto.random_scalar()
            b = crypto.random_scalar()

            R = crypto.ge_double_scalarmult_base_vartime2(a, A, b, B)
            R_exp = crypto.point_add(crypto.scalarmult(A, a), crypto.scalarmult(B, b))
            self.assertTrue(crypto.point_eq(R, R_exp))

    def test_ge25519_double_scalarmult_vartime(self):
        for i in range(10):
            ap = crypto.random_scalar()
            A = crypto.scalarmult_base(ap)
            a = crypto.random_scalar()
            b = crypto.random_scalar()

            R = crypto.ge_double_scalarmult_base_vartime(a, A, b)
            R_exp = crypto.point_add(crypto.scalarmult(A, a), crypto.scalarmult_base(b))
            self.assertTrue(crypto.point_eq(R, R_exp))

    def test_pointadd(self):
        a = crypto.random_scalar()
        A = crypto.scalarmult_base(a)
        A2 = crypto.point_add(A, A)
        A3 = crypto.point_add(A2, A)
        A4 = crypto.point_add(A3, A)
        A8 = crypto.scalarmult(A4, crypto.sc_init(2))

        A8p = crypto.point_mul8(A)
        self.assertTrue(crypto.point_eq(A8p, A8))
        self.assertTrue(crypto.point_eq(A4, crypto.scalarmult(A, crypto.sc_init(4))))
        self.assertTrue(crypto.point_eq(A3, crypto.scalarmult(A, crypto.sc_init(3))))
        

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
