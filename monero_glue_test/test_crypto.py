#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
from binascii import unhexlify
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
        point = unhexlify(
            b"2486224797d05cae3cba4be043be2db0df381f3f19cfa113f86ab38e3d8d2bd0"
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
            unhexlify(
                b"a0eea49140a3b036da30eacf64bd9d56ce3ef68ba82ef13571ec511edbcf8303"
            )
        )
        exp = unhexlify(
            b"16bb4a3c44e2ced511fc0d4cd86b13b3af21efc99fb0356199fac489f2544c09"
        )
        res = crypto.scalarmult_base(scalar)
        self.assertEqual(exp, crypto.encodepoint(res))
        self.assertTrue(crypto.point_eq(crypto.decodepoint(exp), res))

        scalar = crypto.decodeint(
            unhexlify(
                b"fd290dce39f781aebbdbd24584ed6d48bd300de19d9c3decfda0a6e2c6751d0f"
            )
        )
        exp = unhexlify(
            b"123daf90fc26f13c6529e6b49bfed498995ac383ef19c0db6771143f24ba8dd5"
        )
        res = crypto.scalarmult_base(scalar)
        self.assertEqual(exp, crypto.encodepoint(res))
        self.assertTrue(crypto.point_eq(crypto.decodepoint(exp), res))

    def test_scalarmult(self):
        priv = unhexlify(
            b"3482fb9735ef879fcae5ec7721b5d3646e155c4fb58d6cc11c732c9c9b76620a"
        )
        pub = unhexlify(
            b"2486224797d05cae3cba4be043be2db0df381f3f19cfa113f86ab38e3d8d2bd0"
        )
        exp = unhexlify(
            b"adcd1f5881f46f254900a03c654e71950a88a0236fa0a3a946c9b8daed6ef43d"
        )
        res = crypto.scalarmult(crypto.decodepoint(pub), crypto.decodeint(priv))
        self.assertEqual(exp, crypto.encodepoint(res))
        self.assertTrue(crypto.point_eq(crypto.decodepoint(exp), res))

    def test_cn_fast_hash(self):
        inp = unhexlify(
            b"259ef2aba8feb473cf39058a0fe30b9ff6d245b42b6826687ebd6b63128aff6405"
        )
        res = crypto.cn_fast_hash(inp)
        self.assertEqual(
            res,
            unhexlify(
                b"86db87b83fb1246efca5f3b0db09ce3fa4d605b0d10e6507cac253dd31a3ec16"
            ),
        )

    def test_hash_to_scalar(self):
        inp = unhexlify(
            b"259ef2aba8feb473cf39058a0fe30b9ff6d245b42b6826687ebd6b63128aff6405"
        )
        res = crypto.hash_to_scalar(inp)
        exp = crypto.decodeint(binascii.unhexlify(
            b"9907925b254e12162609fc0dfd0fef2aa4d605b0d10e6507cac253dd31a3ec06"))
        self.assertTrue(crypto.sc_eq(res, exp))

    def test_hash_to_point(self):
        data = unhexlify(
            b"42f6835bf83114a1f5f6076fe79bdfa0bd67c74b88f127d54572d3910dd09201"
        )
        res = crypto.hash_to_point(data)
        res_p = crypto.encodepoint(res)
        self.assertEqual(
            res_p,
            unhexlify(
                b"54863a0464c008acc99cffb179bc6cf34eb1bbdf6c29f7a070a7c6376ae30ab5"
            ),
        )

    def test_derivation_to_scalar(self):
        derivation = unhexlify(
            b"e720a09f2e3a0bbf4e4ba7ad93653bb296885510121f806acb2a5f9168fafa01"
        )
        scalar = unhexlify(
            b"25d08763414c379aa9cf989cdcb3cadd36bd5193b500107d6bf5f921f18e470e"
        )
        sc_int = crypto.derivation_to_scalar(crypto.decodepoint(derivation), 0)
        self.assertEqual(scalar, crypto.encodeint(sc_int))

    def test_generate_key_derivation(self):
        key_pub = crypto.decodepoint(
            unhexlify(
                b"7739c95d3298e2f87362dba9e0e0b3980a692ae8e2f16796b0e382098cd6bd83"
            )
        )
        key_priv = crypto.decodeint(
            unhexlify(
                b"3482fb9735ef879fcae5ec7721b5d3646e155c4fb58d6cc11c732c9c9b76620a"
            )
        )
        deriv_exp = unhexlify(
            b"fa188a45a0e4daccc0e6d4f6f6858fd46392104be74183ec0047e7e9f4eaf739"
        )
        self.assertEqual(
            deriv_exp,
            crypto.encodepoint(crypto.generate_key_derivation(key_pub, key_priv)),
        )

    def test_h(self):
        H = unhexlify(
            b"8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
        )
        self.assertEqual(crypto.encodepoint(crypto.xmr_H()), H)

    def test_h_pow(self):
        hp = crypto.gen_Hpow(10)
        self.assertEqual(crypto.encodepoint(hp[0]), crypto.encodepoint(crypto.xmr_H()))
        for i in range(1, 10):
            crypto.check_ed25519point(hp[i])
            self.assertEqual(
                crypto.encodepoint(hp[i]),
                crypto.encodepoint(
                    crypto.scalarmult(crypto.xmr_H(), crypto.sc_init(2 ** i))
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

    def test_sc_inversion(self):
        res = crypto.new_scalar()
        inp = crypto.decodeint(
            unhexlify(
                b"3482fb9735ef879fcae5ec7721b5d3646e155c4fb58d6cc11c732c9c9b76620a"
            )
        )

        crypto.sc_inv_into(res, inp)
        self.assertEqual(
            binascii.hexlify(crypto.encodeint(res)),
            b"bcf365a551e6358f3f281a6241d4a25eded60230b60a1d48c67b51a85e33d70e",
        )
        

if __name__ == "__main__":
    unittest.main()  # pragma: no cover
