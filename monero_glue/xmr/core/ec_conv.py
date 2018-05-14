#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from monero_glue.xmr.core.ec_base import *
from monero_glue.xmr.core import ec_py


def ge25519_to_point(ge):
    """
    Converts Trezor-crypto point to pyec
    :param ge:
    :return:
    """
    return (
        decode_ed25519(ge.x),
        decode_ed25519(ge.y),
        decode_ed25519(ge.z),
        decode_ed25519(ge.t),
    )


def ge25519_from_point(p):
    """
    Converts py EC point to trezor-crypto point ge25519_t
    :param p:
    :return:
    """
    return tty.Ge25519(
        x=tty.FE(*encode_ed25519(p[0])),
        y=tty.FE(*encode_ed25519(p[1])),
        z=tty.FE(*encode_ed25519(p[2])),
        t=tty.FE(*encode_ed25519(p[3])),
    )


def sc_to_modm(sc):
    """
    Scalar value to modm in trezor crypto
    :param sc:
    :return:
    """
    return tty.MODM(*encode_modm(sc))


def sc_from_modm(modm):
    """
    Decodes modm to scalar value
    :param modm:
    :return:
    """
    return ec_py.decodeint(modm.data)

