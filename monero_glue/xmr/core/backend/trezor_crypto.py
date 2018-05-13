import ctypes as ct
import os
from . import trezor_types as tt


# Open Trezor-crypto
CLIB = ct.cdll.LoadLibrary(os.path.join(os.path.dirname(__file__), './libtrezor-crypto.so'))

# Functions
CLIB.random_init.restype = ct.c_int


#
# MODM / scalar values
#


CLIB.contract256_modm.argtypes = [tt.KEY_BUFF, tt.MODM]
CLIB.expand256_modm.argtypes = [tt.MODM, ct.c_void_p, ct.c_size_t]
CLIB.add256_modm.argtypes = [tt.MODM, tt.MODM, tt.MODM]
CLIB.neg256_modm.argtypes = [tt.MODM, tt.MODM]
CLIB.sub256_modm.argtypes = [tt.MODM, tt.MODM, tt.MODM]
CLIB.mul256_modm.argtypes = [tt.MODM, tt.MODM, tt.MODM]
CLIB.reduce256_modm.argtypes = [tt.MODM]
CLIB.barrett_reduce256_modm.argtypes = [tt.MODM, tt.MODM, tt.MODM]
CLIB.set256_modm.argtypes = [tt.MODM, ct.c_uint64]

CLIB.eq256_modm.argtypes = [tt.MODM, tt.MODM]
CLIB.eq256_modm.restype = ct.c_int

CLIB.cmp256_modm.argtypes = [tt.MODM, tt.MODM]
CLIB.cmp256_modm.restype = ct.c_int

CLIB.iszero256_modm.argtypes = [tt.MODM]
CLIB.iszero256_modm.restype = ct.c_int

CLIB.copy256_modm.argtypes = [tt.MODM, tt.MODM]

CLIB.check256_modm.argtypes = [tt.MODM]
CLIB.check256_modm.restype = ct.c_int

CLIB.mulsub256_modm.argtypes = [tt.MODM, tt.MODM, tt.MODM, tt.MODM]


#
# FE
#


CLIB.curve25519_copy.argtypes = [tt.FE, tt.FE]
CLIB.curve25519_add.argtypes = [tt.FE, tt.FE, tt.FE]
CLIB.curve25519_add_after_basic.argtypes = [tt.FE, tt.FE, tt.FE]
CLIB.curve25519_add_reduce.argtypes = [tt.FE, tt.FE, tt.FE]
CLIB.curve25519_sub.argtypes = [tt.FE, tt.FE, tt.FE]
CLIB.curve25519_scalar_product.argtypes = [tt.FE, tt.FE, ct.c_uint32]
CLIB.curve25519_sub_after_basic.argtypes = [tt.FE, tt.FE, tt.FE]
CLIB.curve25519_sub_reduce.argtypes = [tt.FE, tt.FE, tt.FE]
CLIB.curve25519_neg.argtypes = [tt.FE, tt.FE]
CLIB.curve25519_mul.argtypes = [tt.FE, tt.FE, tt.FE]
CLIB.curve25519_square.argtypes = [tt.FE, tt.FE]
CLIB.curve25519_square_times.argtypes = [tt.FE, tt.FE, ct.c_int]
CLIB.curve25519_expand.argtypes = [tt.FE, tt.KEY_BUFF]
CLIB.curve25519_contract.argtypes = [tt.KEY_BUFF, tt.FE]
CLIB.curve25519_recip.argtypes = [tt.FE, tt.FE]

CLIB.curve25519_set.argtypes = [tt.FE, ct.c_uint32]
CLIB.curve25519_isnegative.argtypes = [tt.FE]
CLIB.curve25519_isnonzero.argtypes = [tt.FE]
CLIB.curve25519_reduce.argtypes = [tt.FE, tt.FE]
CLIB.curve25519_expand_reduce.argtypes = [tt.FE, tt.KEY_BUFF]

CLIB.curve25519_isnegative.restype = ct.c_int
CLIB.curve25519_isnonzero.restype = ct.c_int


#
# GE
#


CLIB.ed25519_verify.argtypes = [ct.c_char_p, ct.c_char_p, ct.c_size_t]
CLIB.ge25519_p1p1_to_partial.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_p1p1)]
CLIB.ge25519_p1p1_to_full.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_p1p1)]
CLIB.ge25519_full_to_pniels.argtypes = [ct.POINTER(tt.Ge25519_pniels), ct.POINTER(tt.Ge25519)]

CLIB.ge25519_double_p1p1.argtypes = [ct.POINTER(tt.Ge25519_p1p1), ct.POINTER(tt.Ge25519)]
CLIB.ge25519_nielsadd2_p1p1.argtypes = [ct.POINTER(tt.Ge25519_p1p1), ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_niels), ct.c_char]
CLIB.ge25519_pnielsadd_p1p1.argtypes = [ct.POINTER(tt.Ge25519_p1p1), ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_pniels), ct.c_char]
CLIB.ge25519_double_partial.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)]
CLIB.ge25519_double.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)]
CLIB.ge25519_nielsadd2.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_niels)]
CLIB.ge25519_pnielsadd.argtypes = [ct.POINTER(tt.Ge25519_pniels), ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_pniels)]
CLIB.ge25519_pack.argtypes = [tt.KEY_BUFF, ct.POINTER(tt.Ge25519)]
CLIB.ge25519_unpack_negative_vartime.argtypes = [ct.POINTER(tt.Ge25519), tt.KEY_BUFF]
CLIB.ge25519_set_neutral.argtypes = [ct.POINTER(tt.Ge25519)]
CLIB.ge25519_double_scalarmult_vartime.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM, tt.MODM]
CLIB.ge25519_scalarmult.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM]
CLIB.ge25519_check.argtypes = [ct.POINTER(tt.Ge25519)]
CLIB.ge25519_eq.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)]
CLIB.ge25519_copy.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)]
CLIB.ge25519_set_base.argtypes = [ct.POINTER(tt.Ge25519)]
CLIB.ge25519_mul8.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)]
CLIB.ge25519_neg_partial.argtypes = [ct.POINTER(tt.Ge25519)]
CLIB.ge25519_neg_full.argtypes = [ct.POINTER(tt.Ge25519)]
CLIB.ge25519_reduce.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)]
CLIB.ge25519_norm.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)]
CLIB.ge25519_add.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), ct.c_char]
CLIB.ge25519_fromfe_frombytes_vartime.argtypes = [ct.POINTER(tt.Ge25519), tt.KEY_BUFF]
CLIB.ge25519_unpack_vartime.argtypes = [ct.POINTER(tt.Ge25519), tt.KEY_BUFF]
CLIB.ge25519_scalarmult_base_wrapper.argtypes = [ct.POINTER(tt.Ge25519), tt.MODM]
CLIB.ge25519_scalarmult_wrapper.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM]
CLIB.ge25519_set_xmr_h.argtypes = [ct.POINTER(tt.Ge25519)]

CLIB.ed25519_verify.restype = ct.c_int
CLIB.ge25519_unpack_negative_vartime.restype = ct.c_int
CLIB.ge25519_check.restype = ct.c_int
CLIB.ge25519_eq.restype = ct.c_int
CLIB.ge25519_unpack_vartime.restype = ct.c_int


#
# XMR
#


CLIB.xmr_random_scalar.argtypes = [tt.MODM]
CLIB.xmr_fast_hash.argtypes = [ct.c_void_p, ct.c_size_t, tt.KEY_BUFF]

# CLIB.xmr_hasher_init.argtypes = [Hasher * hasher]
# CLIB.xmr_hasher_update.argtypes = [Hasher * hasher, ct.c_void_p, ct.c_size_t]
# CLIB.xmr_hasher_final.argtypes = [Hasher * hasher, uint8_t * hash]

CLIB.xmr_hash_to_scalar.argtypes = [ct.c_void_p, ct.c_size_t, tt.MODM]
CLIB.xmr_hash_to_ec.argtypes = [ct.c_void_p, ct.c_size_t, ct.POINTER(tt.Ge25519)]
CLIB.xmr_derivation_to_scalar.argtypes = [tt.MODM, ct.POINTER(tt.Ge25519), ct.c_uint32]
CLIB.xmr_generate_key_derivation.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM]
CLIB.xmr_derive_private_key.argtypes = [tt.MODM, ct.POINTER(tt.Ge25519), ct.c_uint32, tt.MODM]
CLIB.xmr_derive_public_key.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), ct.c_uint32, ct.POINTER(tt.Ge25519)]
CLIB.xmr_gen_c.argtypes = [ct.POINTER(tt.Ge25519), tt.MODM, ct.c_uint64]
CLIB.xmr_add_keys1.argtypes = [ct.POINTER(tt.Ge25519), tt.MODM, tt.MODM, ct.POINTER(tt.Ge25519)]
CLIB.xmr_add_keys2.argtypes = [ct.POINTER(tt.Ge25519), tt.MODM, ct.POINTER(tt.Ge25519), tt.MODM, ct.POINTER(tt.Ge25519)]
CLIB.xmr_get_subaddress_secret_key.argtypes = [tt.MODM, ct.c_uint32, ct.c_uint32, tt.MODM]


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


#
# SC
#


def expand256_modm(r, buff):
    CLIB.expand256_modm(r, buff, len(buff))
    return r


def contract256_modm(buff, sc):
    CLIB.contract256_modm(buff, sc)
    return bytes(bytearray(buff))


def add256_modm(r, a, b):
    CLIB.add256_modm(r, a, b)
    return r


def neg256_modm(r, a):
    CLIB.neg256_modm(r, a)
    return r


def sub256_modm(r, a, b):
    CLIB.sub256_modm(r, a, b)
    return r


def mul256_modm(r, a, b):
    CLIB.mul256_modm(r, a, b)
    return r


def reduce256_modm(a):
    CLIB.reduce256_modm(a)
    return a


def barrett_reduce256_modm(r, a, b):
    CLIB.barrett_reduce256_modm(r, a, b)
    return r


def set256_modm(a, b):
    CLIB.set256_modm(a, ct.c_uint64(b))


def init256_modm(r, a):
    CLIB.set256_modm(r, ct.c_uint64(a))
    return r


def eq256_modm(a, b):
    return CLIB.eq256_modm(a, b)


def cmp256_modm(a, b):
    return CLIB.cmp256_modm(a, b)


def iszero256_modm(a, b):
    return CLIB.iszero256_modm(a, b)


def copy256_modm(a, b):
    return CLIB.copy256_modm(a, b)


def clone256_modm(a):
    r = tt.MODM()
    CLIB.copy256_modm(r, a)
    return r


def check256_modm(a):
    return CLIB.copy256_modm(a)


def mulsub256_modm(r, a, b, c):
    CLIB.mulsub256_modm(r, a, b, c)
    return r


def expand256_modm_r(buff):
    m = tt.MODM()
    CLIB.expand256_modm(m, buff, len(buff))
    return m


def contract256_modm_r(sc):
    buff = tt.KEY_BUFF()
    CLIB.contract256_modm(buff, sc)
    return bytes(bytearray(buff))


def add256_modm_r(a, b):
    r = tt.MODM()
    CLIB.add256_modm(r, a, b)
    return r


def neg256_modm_r(a):
    r = tt.MODM()
    CLIB.neg256_modm(r, a)
    return r


def sub256_modm_r(a, b):
    r = tt.MODM()
    CLIB.sub256_modm(r, a, b)
    return r


def mul256_modm_r(a, b):
    r = tt.MODM()
    CLIB.mul256_modm(r, a, b)
    return r


def barrett_reduce256_modm_r(a, b):
    r = tt.MODM()
    CLIB.barrett_reduce256_modm(r, a, b)
    return r


def init256_modm_r(a):
    r = tt.MODM()
    CLIB.set256_modm(r, ct.c_uint64(a))
    return r


def mulsub256_modm_r(a, b, c):
    r = tt.MODM()
    CLIB.mulsub256_modm(r, a, b, c)
    return r


#
# FE
#


def curve25519_copy(a, b):
    return CLIB.curve25519_copy(ct.byref(a), ct.byref(b))


def curve25519_clone(a):
    r = tt.Ge25519()
    CLIB.curve25519_copy(ct.byref(r), ct.byref(a))
    return r


#
# GE
#


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


#
# XMR
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







