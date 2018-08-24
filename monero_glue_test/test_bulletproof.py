#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
from binascii import unhexlify
import unittest

import aiounittest
from monero_serialize.xmrtypes import Bulletproof

from monero_glue.xmr import crypto
from monero_glue.xmr import bulletproof as bp


class BulletproofTest(aiounittest.AsyncTestCase):
    """Simple tests"""

    def __init__(self, *args, **kwargs):
        super(BulletproofTest, self).__init__(*args, **kwargs)

    def can_test(self):
        return crypto.get_backend().has_crypto_into_functions()

    def skip_if_cannot_test(self):
        if not self.can_test():
            self.skipTest("Crypto backend does not implement required functions")

    def test_constants(self):
        """
        Bulletproof constants testing
        :return:
        """
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        Gi, Hi = bp.init_exponents()
        res = bp.init_constants()

    def mask_consistency_check(self, bpi):
        self.assertEqual(bpi.sL(0), bpi.sL(0))
        self.assertEqual(bpi.sL(1), bpi.sL(1))
        self.assertEqual(bpi.sL(63), bpi.sL(63))
        self.assertNotEqual(bpi.sL(1), bpi.sL(0))

        self.assertEqual(bpi.sR(0), bpi.sR(0))
        self.assertEqual(bpi.sR(1), bpi.sR(1))
        self.assertEqual(bpi.sR(63), bpi.sR(63))
        self.assertNotEqual(bpi.sR(1), bpi.sR(0))

        self.assertNotEqual(bpi.sL(0), bpi.sR(0))
        self.assertNotEqual(bpi.sL(1), bpi.sR(1))
        self.assertNotEqual(bpi.sL(63), bpi.sR(63))

        bpi.init_vct()
        ve1 = bp._ensure_dst_key()
        ve2 = bp._ensure_dst_key()
        bpi.vector_exponent(bpi.v_aL, bpi.v_aR, ve1)
        bpi.vector_exponent(bpi.v_aL, bpi.v_aR, ve2)

        bpi.vector_exponent(bpi.v_sL, bpi.v_sR, ve1)
        bpi.vector_exponent(bpi.v_sL, bpi.v_sR, ve2)
        self.assertEqual(ve1, ve2)

    def test_masks(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        bpi.proof_sec = bytearray(32)
        bpi.value_enc = crypto.encodeint(crypto.sc_init(123))
        bpi.gamma_enc = crypto.encodeint(crypto.sc_init(432))
        self.mask_consistency_check(bpi)

        # Randomized masks
        bpi.use_det_masks = False
        self.mask_consistency_check(bpi)

    def test_verify_testnet(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()

        # fmt: off
        bp_proof = Bulletproof(
            V=[bytes(
                [0x67, 0x54, 0xbf, 0x40, 0xcb, 0x45, 0x63, 0x0d, 0x4b, 0xea, 0x08, 0x9e, 0xd7, 0x86, 0xec, 0x3c, 0xe5,
                 0xbd, 0x4e, 0xed, 0x8f, 0xf3, 0x25, 0x76, 0xae, 0xca, 0xb8, 0x9e, 0xf2, 0x5e, 0x41, 0x16])],
            A=bytes(
                [0x96, 0x10, 0x17, 0x66, 0x87, 0x7e, 0xef, 0x97, 0xb3, 0x82, 0xfb, 0x8e, 0x0c, 0x2a, 0x93, 0x68, 0x9e,
                 0x05, 0x22, 0x07, 0xe3, 0x30, 0x94, 0x20, 0x58, 0x6f, 0x5d, 0x01, 0x6d, 0x4e, 0xd5, 0x88]),
            S=bytes(
                [0x50, 0x51, 0x38, 0x32, 0x96, 0x20, 0x7c, 0xc9, 0x60, 0x4d, 0xac, 0x7c, 0x7c, 0x21, 0xf9, 0xad, 0x1c,
                 0xc2, 0x2d, 0xee, 0x88, 0x7b, 0xa2, 0xe2, 0x61, 0x81, 0x46, 0xf5, 0x99, 0xc3, 0x12, 0x57]),
            T1=bytes(
                [0x1a, 0x7d, 0x06, 0x51, 0x41, 0xe6, 0x12, 0xbe, 0xad, 0xd7, 0x68, 0x60, 0x85, 0xfc, 0xc4, 0x86, 0x0b,
                 0x39, 0x4b, 0x06, 0xf7, 0xca, 0xb3, 0x29, 0xdf, 0x1d, 0xbf, 0x96, 0x5f, 0xbe, 0x8c, 0x87]),
            T2=bytes(
                [0x57, 0xae, 0x91, 0x04, 0xfa, 0xac, 0xf3, 0x73, 0x75, 0xf2, 0x83, 0xd6, 0x9a, 0xcb, 0xef, 0xe4, 0xfc,
                 0xe5, 0x37, 0x55, 0x52, 0x09, 0xb5, 0x60, 0x6d, 0xab, 0x46, 0x85, 0x01, 0x23, 0x9e, 0x47]),
            taux=bytes(
                [0x44, 0x7a, 0x87, 0xd9, 0x5f, 0x1b, 0x17, 0xed, 0x53, 0x7f, 0xc1, 0x4f, 0x91, 0x9b, 0xca, 0x68, 0xce,
                 0x20, 0x43, 0xc0, 0x88, 0xf1, 0xdf, 0x12, 0x7b, 0xd7, 0x7f, 0xe0, 0x27, 0xef, 0xef, 0x0d]),
            mu=bytes(
                [0x32, 0xf9, 0xe4, 0xe1, 0xc2, 0xd8, 0xe4, 0xb0, 0x0d, 0x49, 0xd1, 0x02, 0xbc, 0xcc, 0xf7, 0xa2, 0x5a,
                 0xc7, 0x28, 0xf3, 0x05, 0xb5, 0x64, 0x2e, 0xde, 0xcf, 0x01, 0x61, 0xb8, 0x62, 0xfb, 0x0d]),
            L=[
                bytes([0xde, 0x71, 0xca, 0x09, 0xf9, 0xd9, 0x1f, 0xa2, 0xae, 0xdf, 0x39, 0x49, 0x04, 0xaa, 0x6b, 0x58,
                       0x67, 0x9d, 0x61, 0xa6, 0xfa, 0xec, 0x81, 0xf6, 0x4c, 0x15, 0x09, 0x9d, 0x10, 0x21, 0xff, 0x39]),
                bytes([0x90, 0x47, 0xbf, 0xf0, 0x1f, 0x72, 0x47, 0x4e, 0xd5, 0x58, 0xfb, 0xc1, 0x16, 0x43, 0xb7, 0xd8,
                       0xb1, 0x00, 0xa4, 0xa3, 0x19, 0x9b, 0xda, 0x5b, 0x27, 0xd3, 0x6c, 0x5a, 0x87, 0xf8, 0xf0, 0x28]),
                bytes([0x03, 0x45, 0xef, 0x57, 0x19, 0x8b, 0xc7, 0x38, 0xb7, 0xcb, 0x9c, 0xe7, 0xe8, 0x23, 0x27, 0xbb,
                       0xd3, 0x54, 0xcb, 0x38, 0x3c, 0x24, 0x8a, 0x60, 0x11, 0x20, 0x92, 0x99, 0xec, 0x35, 0x71, 0x9f]),
                bytes([0x7a, 0xb6, 0x36, 0x42, 0x36, 0x83, 0xf3, 0xa6, 0xc1, 0x24, 0xc5, 0x63, 0xb0, 0x4c, 0x8b, 0xef,
                       0x7c, 0x77, 0x25, 0x83, 0xa8, 0xbb, 0x8b, 0x57, 0x75, 0x1c, 0xb6, 0xd7, 0xca, 0xc9, 0x0d, 0x78]),
                bytes([0x9d, 0x79, 0x66, 0x21, 0x64, 0x72, 0x97, 0x08, 0xa0, 0x5a, 0x94, 0x5a, 0x94, 0x7b, 0x11, 0xeb,
                       0x4e, 0xe9, 0x43, 0x2f, 0x08, 0xa2, 0x57, 0xa5, 0xd5, 0x99, 0xb0, 0xa7, 0xde, 0x78, 0x80, 0xb7]),
                bytes([0x9f, 0x88, 0x5c, 0xa5, 0xeb, 0x08, 0xef, 0x1a, 0xcf, 0xbb, 0x1d, 0x04, 0xc5, 0x47, 0x24, 0x37,
                       0x49, 0xe4, 0x4e, 0x9c, 0x5d, 0x56, 0xd0, 0x97, 0xfd, 0x8a, 0xe3, 0x23, 0x1d, 0xab, 0x16, 0x03]),
            ],
            R=[
                bytes([0xae, 0x89, 0xeb, 0xa8, 0x5b, 0xd5, 0x65, 0xd6, 0x9f, 0x2a, 0xfd, 0x04, 0x66, 0xad, 0xb1, 0xf3,
                       0x5e, 0xf6, 0x60, 0xa7, 0x26, 0x94, 0x3b, 0x72, 0x5a, 0x5c, 0x80, 0xfa, 0x0f, 0x75, 0x48, 0x27]),
                bytes([0xc9, 0x1a, 0x61, 0x70, 0x6d, 0xea, 0xea, 0xb2, 0x42, 0xff, 0x27, 0x3b, 0x8e, 0x94, 0x07, 0x75,
                       0x40, 0x7d, 0x33, 0xde, 0xfc, 0xbd, 0x53, 0xa0, 0x2a, 0xf9, 0x0c, 0x36, 0xb0, 0xdd, 0xbe, 0x8d]),
                bytes([0xb7, 0x39, 0x7a, 0x0e, 0xa1, 0x42, 0x0f, 0x94, 0x62, 0x24, 0xcf, 0x54, 0x75, 0xe3, 0x0b, 0x0f,
                       0xfb, 0xcb, 0x67, 0x7b, 0xbc, 0x98, 0x36, 0x01, 0x9f, 0x73, 0xa0, 0x70, 0xa1, 0x7e, 0xf0, 0xcf]),
                bytes([0x40, 0x06, 0xd4, 0xfa, 0x22, 0x7c, 0x82, 0xbf, 0xe8, 0xe0, 0x35, 0x13, 0x28, 0xa2, 0xb9, 0x51,
                       0xa3, 0x37, 0x34, 0xc0, 0xa6, 0x43, 0xd6, 0xb7, 0x7a, 0x40, 0xae, 0xf9, 0x36, 0x0e, 0xe3, 0xcc]),
                bytes([0x88, 0x38, 0x64, 0xe9, 0x63, 0xe3, 0x33, 0xd9, 0xf6, 0xca, 0x47, 0xc4, 0xc7, 0x36, 0x70, 0x01,
                       0xd2, 0xe4, 0x8c, 0x9f, 0x25, 0xc2, 0xce, 0xcf, 0x81, 0x89, 0x4f, 0x24, 0xcb, 0xb8, 0x40, 0x73]),
                bytes([0xdc, 0x35, 0x65, 0xed, 0x6b, 0xb0, 0xa7, 0x1a, 0x1b, 0xf3, 0xd6, 0xfb, 0x47, 0x00, 0x48, 0x00,
                       0x20, 0x6d, 0xd4, 0xeb, 0xff, 0xb9, 0xdc, 0x43, 0x30, 0x8a, 0x90, 0xfe, 0x43, 0x74, 0x75, 0x68]),
            ],
            a=bytes(
                [0xb4, 0x8e, 0xc2, 0x31, 0xce, 0x05, 0x9a, 0x7a, 0xbc, 0x82, 0x8c, 0x30, 0xb3, 0xe3, 0x80, 0x86, 0x05,
                 0xb8, 0x4c, 0x93, 0x9a, 0x8e, 0xce, 0x39, 0x0f, 0xb6, 0xee, 0x28, 0xf6, 0x7e, 0xd5, 0x07]),
            b=bytes(
                [0x47, 0x10, 0x62, 0xc2, 0xad, 0xc7, 0xe2, 0xc9, 0x14, 0x6f, 0xf4, 0xd1, 0xfe, 0x52, 0xa9, 0x1a, 0xe4,
                 0xb6, 0xd0, 0x25, 0x4b, 0x19, 0x80, 0x7c, 0xcd, 0x62, 0x62, 0x1d, 0x97, 0x20, 0x71, 0x0b]),
            t=bytes(
                [0x47, 0x06, 0xea, 0x76, 0x8f, 0xdb, 0xa3, 0x15, 0xe0, 0x2c, 0x6b, 0x25, 0xa1, 0xf7, 0x3c, 0xc8, 0x1d,
                 0x97, 0xa6, 0x52, 0x48, 0x75, 0x37, 0xf9, 0x1e, 0x14, 0xac, 0xb1, 0x2a, 0x34, 0xc6, 0x06])
        )
        # fmt: on

        self.assertTrue(bpi.verify_testnet(bp_proof))

    def test_verify(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()

        # fmt: off
        bp_proof = Bulletproof(
            V=[
                unhexlify(b"3c705e1da4bbe43a0535a5ad3a8e6c148fb8c1a4118ba6b65412b2fe6511b261"),
            ],
            A=unhexlify(b"fd0336a21efd088edc4634153f6795ff18707815d32d6e07abfd52dbceaf65b5"),
            S=unhexlify(b"3716a1ece9ad971ab9339aae011c343e4aadeee8b7316c928deb4a1678b4d540"),
            T1=unhexlify(b"744a9ec79e7dcd263fc2e4e828b885ae3286e4dcca0fc43d1ad0f82bb5e84097"),
            T2=unhexlify(b"5d61e98dce355faaa7498e3b3453e4a25c40a002596dfe8066b804963fb70de3"),
            taux=unhexlify(b"2cc0207a5d8c0ce4f56fe381f451a44d6f1123516b3ee34c84c5bd73681e950b"),
            mu=unhexlify(b"35554b56e85392ba9ef955019cdd0336b44e361f50eba6c8aa1b8e520ee32a03"),
            L=[unhexlify(b"511e4e6c210dff90ce6dd9b42f99922d052a6d3a233ee1dcd247355fc2d1c6f3"),
               unhexlify(b"a1d4a8f563f5beb5301df7f9b77cac6cb1750f41e32a87c448035476fabd95fb"),
               unhexlify(b"f35d024182a47b2f1c6fd63a81e261de4a4c6304c08081c8f6be7ea376403de6"),
               unhexlify(b"55f3c43c4e4b739b0c5b778594d89a0b8898dadcc344d33f0b9ebb17c6902c56"),
               unhexlify(b"f284735fb774f653686cba437ed79e3a220491ba63b87154b02fb50531b22793"),
               unhexlify(b"01aa0cb066bc7e4fd8da3a0a822c0bc40f6568b9ff7c3c22c2bbd506444ae079"),
               ],
            R=[unhexlify(b"8e202216359b2883edc516546d03aa6308b3403fcf78e771508aa17fb15dafd9"),
               unhexlify(b"0dc6d53f7651cd1efdc434af1ab732ef96ff2a2df00ba41fe746edd1261e7303"),
               unhexlify(b"0bf935f41ef1a97f8f75321f164a1951b3a6e12a4099a6751d6158abccb3b613"),
               unhexlify(b"45f3ef0dae0bdac2f19142bffc57db12cf9dd2a6038d317467491788ff53ba88"),
               unhexlify(b"bbfcf74131f8cb51db3ff1d25f01a8b27cbc8ad2b5a22ea53f196e82f68aef37"),
               unhexlify(b"ca5a73f4770c0fd6bcce7d13f61bea6d0947840dd13c832544d37f75c875d0ae"),
               ],
            a=unhexlify(b"f77e9ce6aa4e2ee83b437d18c1683ec50cdfe43d0d05af2094cbb5a5e79c5f09"),
            b=unhexlify(b"1ab637c922e87d9690f9b6d754d501277ca14935f69197cbf64b7f83f5a07e01"),
            t=unhexlify(b"9e7e8ca9e482d8ab601139fa862649328c00aac2e567aefdefc1c41b505cf202")
        )
        # fmt: on

        self.assertTrue(bpi.verify(bp_proof))

    def test_prove_testnet(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        val = crypto.sc_init(123)
        mask = crypto.sc_init(432)

        bp_res = bpi.prove_testnet(val, mask)
        bpi.verify_testnet(bp_res)

        try:
            bp_res.S[0] += 1
            bpi.verify(bp_res)
            self.fail("Verification should have failed")
        except:
            pass

    def test_prove_testnet_2(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        val = crypto.sc_init((1 << 30) - 1 + 16)
        mask = crypto.random_scalar()

        bp_res = bpi.prove_testnet(val, mask)
        bpi.verify_testnet(bp_res)

    def test_verify_batch_1(self):
        self.skip_if_cannot_test()
        proof1 = Bulletproof(
            V=[
                unhexlify(b"3c705e1da4bbe43a0535a5ad3a8e6c148fb8c1a4118ba6b65412b2fe6511b261"),
            ],
            A=unhexlify(b"8c05311efed953678c15c5abd6a7b4bc5de8146e1543e380fe07dc598df65084"),
            S=unhexlify(b"cf2435426c841e094d53ac1f900b4aeaf0678f6e75806da8b250e72d6b0db9fe"),
            T1=unhexlify(b"49e8d85264d5dfcdf50dc25fab6b2033925ff4cbf5fcf60ef38005aa17513b82"),
            T2=unhexlify(b"48803cbf46e21d0a4c887678cc59b2ef4ae6f8fa5e799d406590b648ac8201be"),
            taux=unhexlify(b"081f957b19e44ba9b7b24655fe3922daabfc1bab1c673e07dc2338f3e82ae301"),
            mu=unhexlify(b"84941385ca48731745006054eae175370a5f4de141f253f0f5c80169ba6ab806"),
            L=[unhexlify(b"f500b583f2632b4b8df16ff7a0b385f269d2af7697d0d880455e541e87cf7275"),
               unhexlify(b"48a9d34e919cef59f23d7f37bc065f65fa04eeeb16a23f189686068b94acca4c"),
               unhexlify(b"6b86649c1c3bdfd2b4127940d90d573dd5545edba42bf0bddccde32d4c3d31a9"),
               unhexlify(b"b5563c4953a2a038df85fd9fa9effc28e0a8d4fdbb0afd79f87c728e3baf26d6"),
               unhexlify(b"405c833acbc49260342efebfeb1d6d3f78bb14880dff91d2da6b48492b5c93e5"),
               unhexlify(b"3984b85b3aa86fce40be26a1906a5030e1c1f1f4c9754274ad653e8ccb19d77a"),
               ],
            R=[unhexlify(b"ec998c442b4f34ffd2c04cb841830f3327c2bd5155ab6b85831a2b007ac2241e"),
               unhexlify(b"176082c148ff8cb89e87eab5e1949482829a55cdf0bd0ad7de97dc3b96e51702"),
               unhexlify(b"e34bd13d7a3c2dea113e97ca2bd3b9f661242d378ddac04d7cc2c09ea5d3714c"),
               unhexlify(b"286d1b72503e0641eae2c986f00344130e1756dfe002c8b06f0df1e62cbefc70"),
               unhexlify(b"152948ab81532772646d40f44192da69122ae14c20b9fd0b52d969764d374a77"),
               unhexlify(b"6c97a306c3f03f15454fda896a6feb508c029463310d2d0205b55271db68df30"),
               ],
            a=unhexlify(b"8b25662dcd953095b799389336c1a9a4afc8540a250252b188d6311e2857e208"),
            b=unhexlify(b"64c38a82dc5e629168b0284e00d40df80b5d72fdf443e19e8a890d49692faa0d"),
            t=unhexlify(b"328effcadf4324536545ec9fc44216eb1041ef8474fa0f54b62b36ee08be4f0b")
        )

        proof2 = Bulletproof(
            V=[
                unhexlify(b"3c705e1da4bbe43a0535a5ad3a8e6c148fb8c1a4118ba6b65412b2fe6511b261"),
            ],
            A=unhexlify(b"7372db75c0d9d409524924fff5dd13e867eb4c5789f3f5cc6ef860be68d5e4e5"),
            S=unhexlify(b"be8f2d87ace0a528056d567881e74f44817a811e110cdb3890376262a2084ab3"),
            T1=unhexlify(b"8dfc541c379efbe6000bb2339c3a52288ffa4300fcc0f0f0de777e54b5488160"),
            T2=unhexlify(b"cf7d046c86c33bea6c5167bb6482c0a31332989dc9493eacc04a07deb6536953"),
            taux=unhexlify(b"abaaf209cc9a800d933d51bb398b81ee7284efc9c92727066a640fdccc954009"),
            mu=unhexlify(b"ec743e23abb555dca26164a86614306f117a733fcd395eb8675411cd31915608"),
            L=[unhexlify(b"0ee1acc28126656eaf0934314a97e1cf2232a13f5636d319a233cedd58b2882f"),
               unhexlify(b"cc3d2ec5635de569343bea37fc46a93413ae66bf803a4333f427f79f341d1696"),
               unhexlify(b"518c80669bed0960fd03e802a9e837e1aa4a4910bb5853067447d7d22eaca325"),
               unhexlify(b"251a586e8e79a5d767b89931e012acdae317c13c434a6f5f121e44b3b59240b2"),
               unhexlify(b"09b41426e6c9808f6a58ded987cc39936f703f136b50493dd1c92c9b1ec4e7fc"),
               unhexlify(b"984d1369c3c7f2687eebca26395576810c66623408958efde4f36b0bb63a2475"),
               ],
            R=[unhexlify(b"31768a0465315ff0dd1ea2228ae8c34d1474e873a863362feab7b050f29a211a"),
               unhexlify(b"27d1b2533ed78d3dacc396afa50fa533cffc5d1563b679a4049a482436718d3c"),
               unhexlify(b"a49388b042c8a4c6526054661fac1706cf450181ec1f9eed005b283614ec7f95"),
               unhexlify(b"3f053243fe16f8fd302395c125ffedd93831829b13abbb195bf69fc139069de9"),
               unhexlify(b"5a32d7f7132043d1f0cc8cd88cce94e5241337ed616c35a1d753436b2d1c4a93"),
               unhexlify(b"bbd7f9b3031cf41b613a9ee726de9693457238b4be6317083d278e00717f8c14"),
               ],
            a=unhexlify(b"83d8d128f35aa02fc063792df9f4e9de0d4e58b8c6e7c449a672d6e4286ee309"),
            b=unhexlify(b"741d679f1dfe749f7d1ede687f8dd48f7fd3b5a52a5e6a453488d5e25b3fff0e"),
            t=unhexlify(b"88331e9fd7573135016629f337240225f9c0a5b70bad4157ad60d4260feb2b03")
        )

        bpi = bp.BulletProofBuilder()
        bpi.verify_batch([proof1, proof2])

    def test_prove_random_masks(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        bpi.use_det_masks = False  # trully randomly generated mask vectors
        val = crypto.sc_init((1 << 30) - 1 + 16)
        mask = crypto.random_scalar()

        bp_res = bpi.prove(val, mask)
        bpi.verify(bp_res)

    def test_prove_testnet_random_masks(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        bpi.use_det_masks = False  # trully randomly generated mask vectors
        val = crypto.sc_init((1 << 30) - 1 + 16)
        mask = crypto.random_scalar()

        bp_res = bpi.prove_testnet(val, mask)
        bpi.verify_testnet(bp_res)

    def test_multiexp(self):
        self.skip_if_cannot_test()
        scalars = [0, 1, 2, 3, 4, 99]
        point_base = [0, 2, 4, 7, 12, 18]
        scalar_sc = [crypto.sc_init(x) for x in scalars]
        points = [crypto.scalarmult_base(crypto.sc_init(x)) for x in point_base]

        muex = bp.MultiExp(scalars=[crypto.encodeint(x) for x in scalar_sc],
                           point_fnc=lambda i, d: crypto.encodepoint(points[i]))

        self.assertEqual(len(muex), len(scalars))
        res = bp.multiexp(None, muex)
        res2 = bp.vector_exponent_custom(
            A=bp.KeyVEval(3, lambda i, d: crypto.encodepoint(crypto.scalarmult_base(crypto.sc_init(point_base[i])))),
            B=bp.KeyVEval(3, lambda i, d: crypto.encodepoint(crypto.scalarmult_base(crypto.sc_init(point_base[3+i])))),
            a=bp.KeyVEval(3, lambda i, d: crypto.encodeint(crypto.sc_init(scalars[i]))),
            b=bp.KeyVEval(3, lambda i, d: crypto.encodeint(crypto.sc_init(scalars[i+3]))),
        )
        self.assertEqual(res, res2)

    def test_prove_batch(self):
        self.skip_if_cannot_test()
        bpi = bp.BulletProofBuilder()
        sv = [crypto.sc_init(123), crypto.sc_init(768)]
        gamma = [crypto.sc_init(456), crypto.sc_init(901)]
        proof = bpi.prove_batch(sv, gamma)
        bpi.verify_batch([proof])


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
