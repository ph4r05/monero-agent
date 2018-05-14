import ctypes as ct
from monero_glue.xmr.core.backend import trezor_types as tt

# 1. regex the Header file to CLIB.METHOD.argtypes=[]
# 2. replace the argtypes wiht our types
# 3. regex the method list to the buff list of methods
# 4. put return value as the first element if the return elem is not None
# CLIB\.(.+?)\.argtypes\s*=\s*\[(.+?)\]


buff = [
    ['curve25519_copy', tt.FE, tt.FE],
    ['curve25519_add', tt.FE, tt.FE, tt.FE],
    ['curve25519_add_after_basic', tt.FE, tt.FE, tt.FE],
    ['curve25519_add_reduce', tt.FE, tt.FE, tt.FE],
    ['curve25519_sub', tt.FE, tt.FE, tt.FE],
    ['curve25519_scalar_product', tt.FE, tt.FE, ct.c_uint32],
    ['curve25519_sub_after_basic', tt.FE, tt.FE, tt.FE],
    ['curve25519_sub_reduce', tt.FE, tt.FE, tt.FE],
    ['curve25519_neg', tt.FE, tt.FE],
    ['curve25519_mul', tt.FE, tt.FE, tt.FE],
    ['curve25519_square', tt.FE, tt.FE],
    ['curve25519_square_times', tt.FE, tt.FE, ct.c_int],
    ['curve25519_expand', tt.FE, tt.KEY_BUFF],
    ['curve25519_contract', tt.KEY_BUFF, tt.FE],
    ['curve25519_recip', tt.FE, tt.FE],

    ['curve25519_set', tt.FE, ct.c_uint32],
    [ct.c_int, 'curve25519_isnegative', tt.FE],
    [ct.c_int, 'curve25519_isnonzero', tt.FE],
    ['curve25519_reduce', tt.FE, tt.FE],
    ['curve25519_expand_reduce', tt.FE, tt.KEY_BUFF],

    [ct.c_int, 'ed25519_verify', ct.c_char_p, ct.c_char_p, ct.c_size_t],
    ['ge25519_p1p1_to_partial', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_p1p1)],
    ['ge25519_p1p1_to_full', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_p1p1)],
    ['ge25519_full_to_pniels', ct.POINTER(tt.Ge25519_pniels), ct.POINTER(tt.Ge25519)],

    ['ge25519_double_p1p1', ct.POINTER(tt.Ge25519_p1p1), ct.POINTER(tt.Ge25519)],
    ['ge25519_nielsadd2_p1p1', ct.POINTER(tt.Ge25519_p1p1), ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_niels), ct.c_char],
    ['ge25519_pnielsadd_p1p1', ct.POINTER(tt.Ge25519_p1p1), ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_pniels), ct.c_char],
    ['ge25519_double_partial', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)],
    ['ge25519_double', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)],
    ['ge25519_nielsadd2', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_niels)],
    ['ge25519_pnielsadd', ct.POINTER(tt.Ge25519_pniels), ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519_pniels)],
    ['ge25519_pack', tt.KEY_BUFF, ct.POINTER(tt.Ge25519)],
    [ct.c_int, 'ge25519_unpack_negative_vartime', ct.POINTER(tt.Ge25519), tt.KEY_BUFF],
    ['ge25519_set_neutral', ct.POINTER(tt.Ge25519)],
    ['ge25519_double_scalarmult_vartime', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM, tt.MODM],
    ['ge25519_scalarmult', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM],
    [ct.c_int, 'ge25519_check', ct.POINTER(tt.Ge25519)],
    [ct.c_int, 'ge25519_eq', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)],
    ['ge25519_copy', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)],
    ['ge25519_set_base', ct.POINTER(tt.Ge25519)],
    ['ge25519_mul8', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)],
    ['ge25519_neg_partial', ct.POINTER(tt.Ge25519)],
    ['ge25519_neg_full', ct.POINTER(tt.Ge25519)],
    ['ge25519_reduce', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)],
    ['ge25519_norm', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519)],
    ['ge25519_add', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), ct.c_char],
    ['ge25519_fromfe_frombytes_vartime', ct.POINTER(tt.Ge25519), tt.KEY_BUFF],
    [ct.c_int, 'ge25519_unpack_vartime', ct.POINTER(tt.Ge25519), tt.KEY_BUFF],
    ['ge25519_scalarmult_base_wrapper', ct.POINTER(tt.Ge25519), tt.MODM],
    ['ge25519_scalarmult_wrapper', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM],
    ['ge25519_set_xmr_h', ct.POINTER(tt.Ge25519)],


    ['xmr_random_scalar', tt.MODM],
    ['xmr_fast_hash', tt.KEY_BUFF, ct.c_void_p, ct.c_size_t],

    ['xmr_hash_to_scalar', tt.MODM, ct.c_void_p, ct.c_size_t],
    ['xmr_hash_to_ec', ct.POINTER(tt.Ge25519), ct.c_void_p, ct.c_size_t],
    ['xmr_derivation_to_scalar', tt.MODM, ct.POINTER(tt.Ge25519), ct.c_uint32],
    ['xmr_generate_key_derivation', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), tt.MODM],
    ['xmr_derive_private_key', tt.MODM, ct.POINTER(tt.Ge25519), ct.c_uint32, tt.MODM],
    ['xmr_derive_public_key', ct.POINTER(tt.Ge25519), ct.POINTER(tt.Ge25519), ct.c_uint32, ct.POINTER(tt.Ge25519)],
    ['xmr_gen_c', ct.POINTER(tt.Ge25519), tt.MODM, ct.c_uint64],
    ['xmr_add_keys1', ct.POINTER(tt.Ge25519), tt.MODM, tt.MODM, ct.POINTER(tt.Ge25519)],
    ['xmr_add_keys2', ct.POINTER(tt.Ge25519), tt.MODM, ct.POINTER(tt.Ge25519), tt.MODM, ct.POINTER(tt.Ge25519)],
    ['xmr_get_subaddress_secret_key', tt.MODM, ct.c_uint32, ct.c_uint32, tt.MODM],
]


args = ['r', 'a', 'b', 'c', 'd', 'e', 'f', 'h']
for xx in buff:
    ret_arg = xx[0] if not isinstance(xx[0], str) else None
    arg_off = 0
    if ret_arg is not None:
        xx = xx[1:]
        arg_off = 1

    arg_len = len(xx[1:])
    arg_str = ', '.join(args[arg_off:arg_len+arg_off])
    cargs = xx[1:]
    arg_par = ', '.join([('ct.byref(%s)' % args[ii+arg_off]) if isinstance(x, type(ct.POINTER(tt.Ge25519))) else args[ii+arg_off] for ii, x in enumerate(cargs)])
    tpl = 'def %s(%s): \n' % (xx[0], arg_str)
    tpl += '    return CLIB.%s(%s)\n' % (xx[0], arg_par)
    tpl += '\n'
    print(tpl)

    # _r version guess
    if ret_arg is not None:
        continue

    arg_off += 1
    arg_len = len(xx[2:])  # assume first param is output
    arg_str = ', '.join(args[arg_off:arg_len + arg_off])
    cargs = xx[1:]
    arg_par = ', '.join(
        [('ct.byref(%s)' % args[ii + arg_off-1]) if isinstance(x, type(ct.POINTER(tt.Ge25519))) else args[ii + arg_off-1]
         for ii, x in enumerate(cargs)])

    rarg = None
    rarg_type = cargs[0]
    if isinstance(cargs[0], type(ct.POINTER(tt.Ge25519))):
        rarg_type = cargs[0]._type_

    if rarg_type == tt.Ge25519:
        rarg = 'tt.Ge25519()'
    elif rarg_type == tt.Ge25519_pniels:
        rarg = 'tt.Ge25519_pniels()'
    elif rarg_type == tt.Ge25519_niels:
        rarg = 'tt.Ge25519_niels()'
    elif rarg_type == tt.Ge25519_p1p1:
        rarg = 'tt.Ge25519_p1p1()'
    elif rarg_type == tt.MODM:
        rarg = 'tt.MODM()'
    elif rarg_type == tt.FE:
        rarg = 'tt.FE()'

    tpl = 'def %s_r(%s): \n' % (xx[0], arg_str)
    tpl += '    r = %s\n' % (rarg if rarg is not None else ' None  # TODO: fix')
    tpl += '    CLIB.%s(%s)\n' % (xx[0], arg_par)
    tpl += '    return r\n'
    tpl += '\n'
    print(tpl)

