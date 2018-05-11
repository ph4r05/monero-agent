import ctypes as ct
import os
from . import trezor_types as tt


# Open Trezor-crypto
CLIB = ct.cdll.LoadLibrary(os.path.join(os.path.dirname(__file__), './libtrezor-crypto.so'))

# Functions
CLIB.random_init.restype = ct.c_int

CLIB.ge25519_pack.argtypes = [tt.KEY_BUFF, ct.POINTER(tt.Ge25519)]
CLIB.ge25519_unpack_vartime.argtypes = [ct.POINTER(tt.Ge25519), tt.KEY_BUFF]

CLIB.contract256_modm.argtypes = [tt.KEY_BUFF, tt.MODM]
CLIB.expand256_modm.argtypes = [tt.MODM, ct.c_void_p, ct.c_size_t]

CLIB.xmr_hash_to_ec.argtypes = [ct.c_void_p, ct.c_size_t, ct.POINTER(tt.Ge25519)]


# void xmr_gen_range_sig(xmr_range_sig_t * sig, xmr_key_t * C, xmr_key_t * mask, xmr_amount amount, bignum256modm * last_mask);
CLIB.xmr_gen_range_sig.argtypes = [ct.POINTER(tt.XmrRangeSig), ct.POINTER(tt.XmrKey), ct.POINTER(tt.XmrKey),
                                   tt.XmrAmount, ct.POINTER(tt.MODM)]


#
# Wrappers
#

def init_lib():
    """
    Initializes Trezor crypto library
    :return:
    """
    res = CLIB.random_init()
    if res < 0:
        raise ValueError('Library initialization error: %s' % res)
    return res


def ge25519_pack(p):
    buff = tt.KEY_BUFF()
    CLIB.ge25519_pack(buff, p)
    return bytes(bytearray(buff))


def ge25519_unpack_vartime(buff):
    pt = tt.Ge25519()
    buff = tt.KEY_BUFF(*buff)
    r = CLIB.ge25519_unpack_vartime(ct.byref(pt), buff)
    if r != 1:
        raise ValueError('Point decoding error')
    return pt


def expand256_modm(buff):
    m = tt.MODM()
    CLIB.expand256_modm(m, buff, len(buff))
    return m


def contract256_modm(sc):
    buff = tt.KEY_BUFF()
    CLIB.contract256_modm(buff, sc)
    return bytes(bytearray(buff))


def xmr_hash_to_ec(buff):
    """
    Hash_to_ec wrapper
    Accepts python byte array.

    :param buff:
    :return:
    """
    pt = tt.Ge25519()
    CLIB.xmr_hash_to_ec(buff, len(buff), ct.byref(pt))
    return pt


def gen_range_proof(amount, last_mask):
    """
    Trezor crypto range proof
    :param amount:
    :param last_mask:
    :return:
    """
    rsig = tt.XmrRangeSig()
    C = tt.XmrKey()
    mask = tt.XmrKey()
    last_mask_ptr = ct.byref(last_mask) if last_mask else None

    CLIB.xmr_gen_range_sig(ct.byref(rsig), ct.byref(C), ct.byref(mask), amount, last_mask_ptr)

    return rsig, C, mask







