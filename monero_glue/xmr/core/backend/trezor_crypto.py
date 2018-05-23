import ctypes as ct
import os
from . import trezor_types as tt
from .trezor_types import *


# Loaded library instance
CLIB = None


def open_lib(lib_path=None, try_env=True):
    """
    Opens the library
    :param lib_path:
    :param try_env:
    :return:
    """
    global CLIB

    # Open Trezor-crypto
    if lib_path is None and try_env:
        lib_path = os.getenv('LIBTREZOR_CRYPTO_PATH', None)
    if lib_path is None:
        lib_path = os.path.join(os.path.dirname(__file__), './libtrezor-crypto.so')
    if lib_path is None or not os.path.exists(lib_path):
        raise FileNotFoundError('Trezor-Crypto lib not found')

    CLIB = ct.cdll.LoadLibrary(lib_path)

    # Functions
    CLIB.random_init.restype = ct.c_int
    CLIB.random_buffer.argtypes = [ct.c_void_p, ct.c_size_t]
    CLIB.random_uniform.argtypes = [ct.c_uint32]
    CLIB.random_uniform.restype = ct.c_uint32
    CLIB.random32.restype = ct.c_uint32

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
    CLIB.get256_modm.argtypes = [ct.POINTER(ct.c_uint64), tt.MODM]
    CLIB.get256_modm.restype = ct.c_int

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
    CLIB.muladd256_modm.argtypes = [tt.MODM, tt.MODM, tt.MODM, tt.MODM]

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
    CLIB.ge25519_double_scalarmult_vartime2.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM, ct.POINTER(tt.Ge25519), tt.MODM]
    CLIB.ge25519_scalarmult.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM]
    CLIB.ge25519_check.argtypes = [ct.POINTER(tt.Ge25519)]
    CLIB.ge25519_fromfe_check.argtypes = [ct.POINTER(tt.Ge25519)]
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
    CLIB.ge25519_fromfe_check.restype = ct.c_int
    CLIB.ge25519_eq.restype = ct.c_int
    CLIB.ge25519_unpack_vartime.restype = ct.c_int

    #
    # XMR
    #

    CLIB.xmr_random_scalar.argtypes = [tt.MODM]
    CLIB.xmr_fast_hash.argtypes = [tt.KEY_BUFF, ct.c_void_p, ct.c_size_t]

    CLIB.xmr_hasher_init.argtypes = [ct.POINTER(tt.Hasher)]
    CLIB.xmr_hasher_update.argtypes = [ct.POINTER(tt.Hasher), ct.c_void_p, ct.c_size_t]
    CLIB.xmr_hasher_final.argtypes = [ct.POINTER(tt.Hasher), tt.KEY_BUFF]
    CLIB.xmr_hasher_copy.argtypes = [ct.POINTER(tt.Hasher), ct.POINTER(tt.Hasher)]

    CLIB.xmr_hash_to_scalar.argtypes = [tt.MODM, ct.c_void_p, ct.c_size_t]
    CLIB.xmr_hash_to_ec.argtypes = [ct.POINTER(tt.Ge25519), ct.c_void_p, ct.c_size_t]
    CLIB.xmr_derivation_to_scalar.argtypes = [tt.MODM, ct.POINTER(tt.Ge25519), ct.c_uint32]
    CLIB.xmr_generate_key_derivation.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM]
    CLIB.xmr_derive_private_key.argtypes = [tt.MODM, ct.POINTER(tt.Ge25519), ct.c_uint32, tt.MODM]
    CLIB.xmr_derive_public_key.argtypes = [ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), ct.c_uint32, ct.POINTER(tt.Ge25519)]
    CLIB.xmr_gen_c.argtypes = [ct.POINTER(tt.Ge25519), tt.MODM, ct.c_uint64]
    CLIB.xmr_add_keys2.argtypes = [ct.POINTER(tt.Ge25519), tt.MODM, tt.MODM, ct.POINTER(tt.Ge25519)]
    CLIB.xmr_add_keys2_vartime.argtypes = [ct.POINTER(tt.Ge25519), tt.MODM, tt.MODM, ct.POINTER(tt.Ge25519)]
    CLIB.xmr_add_keys3.argtypes = [ct.POINTER(tt.Ge25519), tt.MODM, ct.POINTER(tt.Ge25519), tt.MODM, ct.POINTER(tt.Ge25519)]
    CLIB.xmr_add_keys3_vartime.argtypes = [ct.POINTER(tt.Ge25519), tt.MODM, ct.POINTER(tt.Ge25519), tt.MODM, ct.POINTER(tt.Ge25519)]
    CLIB.xmr_get_subaddress_secret_key.argtypes = [tt.MODM, ct.c_uint32, ct.c_uint32, tt.MODM]
    CLIB.xmr_gen_range_sig.argtypes = [ct.POINTER(tt.XmrRangeSig), ct.POINTER(tt.Ge25519), tt.MODM, tt.XmrAmount, ct.POINTER(tt.MODM)]

    init_lib()

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


def random_buffer(sz):
    buff = (ct.c_uint8 * sz)()
    CLIB.random_buffer(ct.byref(buff), sz)
    return bytes(buff)

random_buffer_r = random_buffer


#
# SC
#


def expand256_modm(r, buff):
    CLIB.expand256_modm(r, buff, len(buff))
    return r


def contract256_modm(buff, sc):
    CLIB.contract256_modm(buff, sc)
    return bytes(buff)


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


def get256_modm(a, b):
    return CLIB.get256_modm(a, b)


def get256_modm_r(a):
    r = ct.c_uint64()
    res = CLIB.get256_modm(ct.byref(r), a)
    if not res:
        raise ValueError('Get256_modm failed')
    return r.value


def init256_modm(r, a):
    CLIB.set256_modm(r, ct.c_uint64(a))
    return r


def eq256_modm(a, b):
    return CLIB.eq256_modm(a, b)


def cmp256_modm(a, b):
    return CLIB.cmp256_modm(a, b)


def iszero256_modm(a):
    return CLIB.iszero256_modm(a)


def copy256_modm(a, b):
    return CLIB.copy256_modm(a, b)


def clone256_modm(a):
    r = tt.MODM()
    CLIB.copy256_modm(r, a)
    return r


def check256_modm(a):
    return CLIB.check256_modm(a)


def mulsub256_modm(r, a, b, c):
    CLIB.mulsub256_modm(r, a, b, c)
    return r


def muladd256_modm(r, a, b, c):
    CLIB.muladd256_modm(r, a, b, c)
    return r


def expand256_modm_r(buff):
    m = tt.MODM()
    CLIB.expand256_modm(m, bytes(buff), len(buff))
    return m


def contract256_modm_r(sc):
    buff = tt.KEY_BUFF()
    CLIB.contract256_modm(buff, sc)
    return bytes(buff)


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


def muladd256_modm_r(a, b, c):
    r = tt.MODM()
    CLIB.muladd256_modm(r, a, b, c)
    return r


#
# FE
#


def curve25519_clone(a):
    r = tt.Ge25519()
    CLIB.curve25519_copy(r, a)
    return r


def curve25519_copy(r, a):
    return CLIB.curve25519_copy(r, a)


def curve25519_copy_r(a):
    r = tt.FE()
    CLIB.curve25519_copy(r, a)
    return r


def curve25519_add(r, a, b):
    return CLIB.curve25519_add(r, a, b)


def curve25519_add_r(a, b):
    r = tt.FE()
    CLIB.curve25519_add(r, a, b)
    return r


def curve25519_add_after_basic(r, a, b):
    return CLIB.curve25519_add_after_basic(r, a, b)


def curve25519_add_after_basic_r(a, b):
    r = tt.FE()
    CLIB.curve25519_add_after_basic(r, a, b)
    return r


def curve25519_add_reduce(r, a, b):
    return CLIB.curve25519_add_reduce(r, a, b)


def curve25519_add_reduce_r(a, b):
    r = tt.FE()
    CLIB.curve25519_add_reduce(r, a, b)
    return r


def curve25519_sub(r, a, b):
    return CLIB.curve25519_sub(r, a, b)


def curve25519_sub_r(a, b):
    r = tt.FE()
    CLIB.curve25519_sub(r, a, b)
    return r


def curve25519_scalar_product(r, a, b):
    return CLIB.curve25519_scalar_product(r, a, b)


def curve25519_scalar_product_r(a, b):
    r = tt.FE()
    CLIB.curve25519_scalar_product(r, a, b)
    return r


def curve25519_sub_after_basic(r, a, b):
    return CLIB.curve25519_sub_after_basic(r, a, b)


def curve25519_sub_after_basic_r(a, b):
    r = tt.FE()
    CLIB.curve25519_sub_after_basic(r, a, b)
    return r


def curve25519_sub_reduce(r, a, b):
    return CLIB.curve25519_sub_reduce(r, a, b)


def curve25519_sub_reduce_r(a, b):
    r = tt.FE()
    CLIB.curve25519_sub_reduce(r, a, b)
    return r


def curve25519_neg(r, a):
    return CLIB.curve25519_neg(r, a)


def curve25519_neg_r(a):
    r = tt.FE()
    CLIB.curve25519_neg(r, a)
    return r


def curve25519_mul(r, a, b):
    return CLIB.curve25519_mul(r, a, b)


def curve25519_mul_r(a, b):
    r = tt.FE()
    CLIB.curve25519_mul(r, a, b)
    return r


def curve25519_square(r, a):
    return CLIB.curve25519_square(r, a)


def curve25519_square_r(a):
    r = tt.FE()
    CLIB.curve25519_square(r, a)
    return r


def curve25519_square_times(r, a, b):
    return CLIB.curve25519_square_times(r, a, b)


def curve25519_square_times_r(a, b):
    r = tt.FE()
    CLIB.curve25519_square_times(r, a, b)
    return r


def curve25519_expand(r, a):
    a = tt.KEY_BUFF(*a)
    return CLIB.curve25519_expand(r, a)


def curve25519_expand_r(a):
    r = tt.FE()
    a = tt.KEY_BUFF(*a)
    CLIB.curve25519_expand(r, a)
    return r


def curve25519_contract(r, a):
    return CLIB.curve25519_contract(r, a)


def curve25519_contract_r(a):
    r = tt.KEY_BUFF()
    CLIB.curve25519_contract(r, a)
    return bytes(r)


def curve25519_recip(r, a):
    return CLIB.curve25519_recip(r, a)


def curve25519_recip_r(a):
    r = tt.FE()
    CLIB.curve25519_recip(r, a)
    return r


def curve25519_set(r, a):
    return CLIB.curve25519_set(r, a)


def curve25519_set_r(a):
    r = tt.FE()
    CLIB.curve25519_set(r, a)
    return r


def curve25519_set_d(r):
    return CLIB.curve25519_set_d(r)


def curve25519_set_d_r():
    r = tt.FE()
    CLIB.curve25519_set_d(r)
    return r


def curve25519_isnegative(a):
    return CLIB.curve25519_isnegative(a)


def curve25519_isnonzero(a):
    return CLIB.curve25519_isnonzero(a)


def curve25519_reduce(r, a):
    return CLIB.curve25519_reduce(r, a)


def curve25519_reduce_r(a):
    r = tt.FE()
    CLIB.curve25519_reduce(r, a)
    return r


def curve25519_expand_reduce(r, a):
    return CLIB.curve25519_expand_reduce(r, a)


def curve25519_expand_reduce_r(a):
    r = tt.FE()
    CLIB.curve25519_expand_reduce(r, a)
    return r


#
# GE
#


def ed25519_verify(a, b, c):
    return CLIB.ed25519_verify(a, b, c)


def ge25519_p1p1_to_partial(r, a):
    return CLIB.ge25519_p1p1_to_partial(ct.byref(r), ct.byref(a))


def ge25519_p1p1_to_partial_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_p1p1_to_partial(ct.byref(r), ct.byref(a))
    return r


def ge25519_p1p1_to_full(r, a):
    return CLIB.ge25519_p1p1_to_full(ct.byref(r), ct.byref(a))


def ge25519_p1p1_to_full_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_p1p1_to_full(ct.byref(r), ct.byref(a))
    return r


def ge25519_full_to_pniels(r, a):
    return CLIB.ge25519_full_to_pniels(ct.byref(r), ct.byref(a))


def ge25519_full_to_pniels_r(a):
    r = tt.Ge25519_pniels()
    CLIB.ge25519_full_to_pniels(ct.byref(r), ct.byref(a))
    return r


def ge25519_double_p1p1(r, a):
    return CLIB.ge25519_double_p1p1(ct.byref(r), ct.byref(a))


def ge25519_double_p1p1_r(a):
    r = tt.Ge25519_p1p1()
    CLIB.ge25519_double_p1p1(ct.byref(r), ct.byref(a))
    return r


def ge25519_nielsadd2_p1p1(r, a, b, c):
    return CLIB.ge25519_nielsadd2_p1p1(ct.byref(r), ct.byref(a), ct.byref(b), c)


def ge25519_nielsadd2_p1p1_r(a, b, c):
    r = tt.Ge25519_p1p1()
    CLIB.ge25519_nielsadd2_p1p1(ct.byref(r), ct.byref(a), ct.byref(b), c)
    return r


def ge25519_pnielsadd_p1p1(r, a, b, c):
    return CLIB.ge25519_pnielsadd_p1p1(ct.byref(r), ct.byref(a), ct.byref(b), c)


def ge25519_pnielsadd_p1p1_r(a, b, c):
    r = tt.Ge25519_p1p1()
    CLIB.ge25519_pnielsadd_p1p1(ct.byref(r), ct.byref(a), ct.byref(b), c)
    return r


def ge25519_double_partial(r, a):
    return CLIB.ge25519_double_partial(ct.byref(r), ct.byref(a))


def ge25519_double_partial_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_double_partial(ct.byref(r), ct.byref(a))
    return r


def ge25519_double(r, a):
    return CLIB.ge25519_double(ct.byref(r), ct.byref(a))


def ge25519_double_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_double(ct.byref(r), ct.byref(a))
    return r


def ge25519_nielsadd2(r, a):
    return CLIB.ge25519_nielsadd2(ct.byref(r), ct.byref(a))


def ge25519_nielsadd2_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_nielsadd2(ct.byref(r), ct.byref(a))
    return r


def ge25519_pnielsadd(r, a, b):
    return CLIB.ge25519_pnielsadd(ct.byref(r), ct.byref(a), ct.byref(b))


def ge25519_pnielsadd_r(a, b):
    r = tt.Ge25519_pniels()
    CLIB.ge25519_pnielsadd(ct.byref(r), ct.byref(a), ct.byref(b))
    return r


def ge25519_pack(r, a):
    return CLIB.ge25519_pack(r, ct.byref(a))


def ge25519_pack_r(a):
    r = tt.KEY_BUFF()
    CLIB.ge25519_pack(r, ct.byref(a))
    return bytes(r)


def ge25519_unpack_negative_vartime(a, b):
    b = tt.KEY_BUFF(*b)
    return CLIB.ge25519_unpack_negative_vartime(ct.byref(a), b)


def ge25519_set_neutral(r):
    return CLIB.ge25519_set_neutral(ct.byref(r))


def ge25519_set_neutral_r():
    r = tt.Ge25519()
    CLIB.ge25519_set_neutral(ct.byref(r))
    return r


def ge25519_double_scalarmult_vartime(r, a, b, c):
    return CLIB.ge25519_double_scalarmult_vartime(ct.byref(r), ct.byref(a), b, c)


def ge25519_double_scalarmult_vartime_r(a, b, c):
    r = tt.Ge25519()
    CLIB.ge25519_double_scalarmult_vartime(ct.byref(r), ct.byref(a), b, c)
    return r


def ge25519_double_scalarmult_vartime2(r, a, b, c, d):
    return CLIB.ge25519_double_scalarmult_vartime2(ct.byref(r), ct.byref(a), b, ct.byref(c), d)


def ge25519_double_scalarmult_vartime2_r(a, b, c, d):
    r = tt.Ge25519()
    CLIB.ge25519_double_scalarmult_vartime2(ct.byref(r), ct.byref(a), b, ct.byref(c), d)
    return r


def ge25519_scalarmult(r, a, b):
    return CLIB.ge25519_scalarmult(ct.byref(r), ct.byref(a), b)


def ge25519_scalarmult_r(a, b):
    r = tt.Ge25519()
    CLIB.ge25519_scalarmult(ct.byref(r), ct.byref(a), b)
    return r


def ge25519_check(a):
    return CLIB.ge25519_check(ct.byref(a))


def ge25519_fromfe_check(a):
    return CLIB.ge25519_fromfe_check(ct.byref(a))


def ge25519_eq(a, b):
    return CLIB.ge25519_eq(ct.byref(a), ct.byref(b))


def ge25519_copy(r, a):
    return CLIB.ge25519_copy(ct.byref(r), ct.byref(a))


def ge25519_copy_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_copy(ct.byref(r), ct.byref(a))
    return r


def ge25519_set_base(r):
    return CLIB.ge25519_set_base(ct.byref(r))


def ge25519_set_base_r():
    r = tt.Ge25519()
    CLIB.ge25519_set_base(ct.byref(r))
    return r


def ge25519_mul8(r, a):
    return CLIB.ge25519_mul8(ct.byref(r), ct.byref(a))


def ge25519_mul8_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_mul8(ct.byref(r), ct.byref(a))
    return r


def ge25519_neg_partial(r):
    return CLIB.ge25519_neg_partial(ct.byref(r))


def ge25519_neg_partial_r():
    r = tt.Ge25519()
    CLIB.ge25519_neg_partial(ct.byref(r))
    return r


def ge25519_neg_full(r):
    return CLIB.ge25519_neg_full(ct.byref(r))


def ge25519_neg_full_r():
    r = tt.Ge25519()
    CLIB.ge25519_neg_full(ct.byref(r))
    return r


def ge25519_reduce(r, a):
    return CLIB.ge25519_reduce(ct.byref(r), ct.byref(a))


def ge25519_reduce_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_reduce(ct.byref(r), ct.byref(a))
    return r


def ge25519_norm(r, a):
    return CLIB.ge25519_norm(ct.byref(r), ct.byref(a))


def ge25519_norm_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_norm(ct.byref(r), ct.byref(a))
    return r


def ge25519_add(r, a, b, c):
    return CLIB.ge25519_add(ct.byref(r), ct.byref(a), ct.byref(b), c)


def ge25519_add_r(a, b, c):
    r = tt.Ge25519()
    CLIB.ge25519_add(ct.byref(r), ct.byref(a), ct.byref(b), c)
    return r


def ge25519_fromfe_frombytes_vartime(r, a):
    a = tt.KEY_BUFF(*a)
    return CLIB.ge25519_fromfe_frombytes_vartime(ct.byref(r), a)


def ge25519_fromfe_frombytes_vartime_r(a):
    a = tt.KEY_BUFF(*a)
    r = tt.Ge25519()
    CLIB.ge25519_fromfe_frombytes_vartime(ct.byref(r), a)
    return r


def ge25519_unpack_vartime(a, b):
    b = tt.KEY_BUFF(*b)
    return CLIB.ge25519_unpack_vartime(ct.byref(a), b)


def ge25519_unpack_vartime_r(buff):
    pt = tt.Ge25519()
    #buff = tt.KEY_BUFF(*buff)
    r = CLIB.ge25519_unpack_vartime(ct.byref(pt), buff)
    if r != 1:
        raise ValueError('Point decoding error')
    return pt


def ge25519_scalarmult_base_wrapper(r, a):
    return CLIB.ge25519_scalarmult_base_wrapper(ct.byref(r), a)


def ge25519_scalarmult_base_wrapper_r(a):
    r = tt.Ge25519()
    CLIB.ge25519_scalarmult_base_wrapper(ct.byref(r), a)
    return r


def ge25519_scalarmult_wrapper(r, a, b):
    return CLIB.ge25519_scalarmult_wrapper(ct.byref(r), ct.byref(a), b)


def ge25519_scalarmult_wrapper_r(a, b):
    r = tt.Ge25519()
    CLIB.ge25519_scalarmult_wrapper(ct.byref(r), ct.byref(a), b)
    return r


def ge25519_set_xmr_h(r):
    return CLIB.ge25519_set_xmr_h(ct.byref(r))


def ge25519_set_xmr_h_r():
    r = tt.Ge25519()
    CLIB.ge25519_set_xmr_h(ct.byref(r))
    return r


def xmr_random_scalar(r):
    return CLIB.xmr_random_scalar(r)


def xmr_random_scalar_r():
    r = tt.MODM()
    CLIB.xmr_random_scalar(r)
    return r


def xmr_fast_hash(r, a, b):
    return CLIB.xmr_fast_hash(r, bytes(a), b)


def xmr_fast_hash_r(a):
    r = tt.KEY_BUFF()
    CLIB.xmr_fast_hash(r, bytes(a), len(a))
    return bytes(r)


def xmr_hasher_init_r():
    h = tt.Hasher()
    CLIB.xmr_hasher_init(ct.byref(h))
    return h


def xmr_hasher_update(h, buff):
    CLIB.xmr_hasher_update(ct.byref(h), bytes(buff), len(buff))


def xmr_hasher_final_r(h):
    r = tt.KEY_BUFF()
    CLIB.xmr_hasher_final(ct.byref(h), r)
    return bytes(r)


def xmr_hasher_copy_r(h):
    hd = tt.Hasher()
    CLIB.xmr_hasher_copy(ct.byref(hd), ct.byref(h))
    return hd


def xmr_hash_to_scalar(r, a):
    return CLIB.xmr_hash_to_scalar(r, bytes(a), len(a))


def xmr_hash_to_scalar_r(a):
    r = tt.MODM()
    CLIB.xmr_hash_to_scalar(r, bytes(a), len(a))
    return r


def xmr_hash_to_ec(r, a):
    return CLIB.xmr_hash_to_ec(ct.byref(r), bytes(a), len(a))


def xmr_hash_to_ec_r(a):
    r = tt.Ge25519()
    CLIB.xmr_hash_to_ec(ct.byref(r), bytes(a), len(a))
    return r


def xmr_derivation_to_scalar(r, a, b):
    return CLIB.xmr_derivation_to_scalar(r, ct.byref(a), b)


def xmr_derivation_to_scalar_r(a, b):
    r = tt.MODM()
    CLIB.xmr_derivation_to_scalar(r, ct.byref(a), b)
    return r


def xmr_generate_key_derivation(r, a, b):
    return CLIB.xmr_generate_key_derivation(ct.byref(r), ct.byref(a), b)


def xmr_generate_key_derivation_r(a, b):
    r = tt.Ge25519()
    CLIB.xmr_generate_key_derivation(ct.byref(r), ct.byref(a), b)
    return r


def xmr_derive_private_key(r, a, b, c):
    return CLIB.xmr_derive_private_key(r, ct.byref(a), b, c)


def xmr_derive_private_key_r(a, b, c):
    r = tt.MODM()
    CLIB.xmr_derive_private_key(r, ct.byref(a), b, c)
    return r


def xmr_derive_public_key(r, a, b, c):
    return CLIB.xmr_derive_public_key(ct.byref(r), ct.byref(a), b, ct.byref(c))


def xmr_derive_public_key_r(a, b, c):
    r = tt.Ge25519()
    CLIB.xmr_derive_public_key(ct.byref(r), ct.byref(a), b, ct.byref(c))
    return r


def xmr_gen_c(r, a, b):
    return CLIB.xmr_gen_c(ct.byref(r), a, b)


def xmr_gen_c_r(a, b):
    r = tt.Ge25519()
    CLIB.xmr_gen_c(ct.byref(r), a, b)
    return r


def xmr_add_keys2(r, a, b, c):
    return CLIB.xmr_add_keys2(ct.byref(r), a, b, ct.byref(c))


def xmr_add_keys2_r(a, b, c):
    r = tt.Ge25519()
    CLIB.xmr_add_keys2(ct.byref(r), a, b, ct.byref(c))
    return r


def xmr_add_keys2_vartime(r, a, b, c):
    return CLIB.xmr_add_keys2_vartime(ct.byref(r), a, b, ct.byref(c))


def xmr_add_keys2_vartime_r(a, b, c):
    r = tt.Ge25519()
    CLIB.xmr_add_keys2_vartime(ct.byref(r), a, b, ct.byref(c))
    return r


def xmr_add_keys3(r, a, b, c, d):
    return CLIB.xmr_add_keys3(ct.byref(r), a, ct.byref(b), c, ct.byref(d))


def xmr_add_keys3_r(a, b, c, d):
    r = tt.Ge25519()
    CLIB.xmr_add_keys3(ct.byref(r), a, ct.byref(b), c, ct.byref(d))
    return r


def xmr_add_keys3_vartime(r, a, b, c, d):
    return CLIB.xmr_add_keys3_vartime(ct.byref(r), a, ct.byref(b), c, ct.byref(d))


def xmr_add_keys3_vartime_r(a, b, c, d):
    r = tt.Ge25519()
    CLIB.xmr_add_keys3_vartime(ct.byref(r), a, ct.byref(b), c, ct.byref(d))
    return r


def xmr_get_subaddress_secret_key(r, a, b, c):
    return CLIB.xmr_get_subaddress_secret_key(r, a, b, c)


def xmr_get_subaddress_secret_key_r(a, b, c):
    r = tt.MODM()
    CLIB.xmr_get_subaddress_secret_key(r, a, b, c)
    return r


#
# XMR
#


def gen_range_proof(amount, last_mask):
    """
    Trezor crypto range proof
    :param amount:
    :param last_mask:
    :return:
    """
    rsig = tt.XmrRangeSig()
    C = tt.Ge25519()
    mask = tt.MODM()
    last_mask_ptr = ct.byref(last_mask) if last_mask else None

    CLIB.xmr_gen_range_sig(ct.byref(rsig), ct.byref(C), mask, amount, last_mask_ptr)

    return C, mask, rsig

