import ctypes as ct
import os
from . import trezor_types as tt


# Open Trezor-crypto
CLIB = ct.cdll.LoadLibrary(os.path.join(os.path.dirname(__file__), './libtrezor-crypto.so'))

# Functions
CLIB.xmr_hash_to_ec.argtypes = [ct.c_void_p, ct.c_size_t, ct.POINTER(tt.Ge25519)]

# void xmr_gen_range_sig(xmr_range_sig_t * sig, xmr_key_t * C, xmr_key_t * mask, xmr_amount amount, bignum256modm * last_mask);
CLIB.xmr_gen_range_sig.argtypes = [ct.POINTER(tt.XmrRangeSig), ct.POINTER(tt.XmrKey), ct.POINTER(tt.XmrKey),
                                   tt.XmrAmount, ct.POINTER(tt.MODM)]


#
# Wrappers
#


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







