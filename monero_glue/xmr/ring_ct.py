#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018

import logging

from monero_glue.compat import gc
from monero_glue.compat.utils import memcpy
from monero_glue.xmr import bulletproof, crypto, mlsag2, monero
from monero_serialize import xmrtypes

logger = logging.getLogger(__name__)
ATOMS = 64


def d2b(n, digits):
    b = [0] * digits
    i = 0
    while n:
        b[i] = n & 1
        i = i + 1
        n >>= 1
    return b


def sum_Ci(Cis):
    """
    Sums points
    :param Cis:
    :return:
    """
    CSum = crypto.identity()
    for i in Cis:
        CSum = crypto.point_add(CSum, i)
    return CSum


def bp_size(outputs):
    M, logM = 1, 0
    while M <= 16 and M < outputs:
        logM += 1
        M = 1 << logM

    return 32 * (21 + outputs + 2 * logM)


async def prove_range_bp(amount, last_mask=None):
    mask = last_mask if last_mask is not None else crypto.random_scalar()
    bp_proof = await prove_range_bp_batch([amount], [mask])

    C = crypto.decodepoint(bp_proof.V[0])
    C = crypto.point_mul8(C)

    gc.collect()

    # Return as struct as the hash(BP_struct) != hash(BP_serialized)
    # as the original hashing does not take vector lengths into account which are dynamic
    # in the serialization scheme (and thus extraneous)
    return C, mask, bp_proof


async def prove_range_bp_batch(amounts, masks):
    from monero_glue.xmr import bulletproof as bp

    bpi = bp.BulletProofBuilder()
    bp_proof = bpi.prove_batch([crypto.sc_init(a) for a in amounts], masks)
    del (bpi, bp)
    gc.collect()

    return bp_proof


async def verify_bp(bp_proof, amounts=None, masks=None):
    from monero_glue.xmr import bulletproof as bp

    if amounts:
        bp_proof.V = []
        for i in range(len(amounts)):
            C = crypto.gen_c(masks[i], amounts[i])
            crypto.scalarmult_into(C, C, crypto.sc_inv_eight())
            bp_proof.V.append(crypto.encodepoint(C))

    bpi = bp.BulletProofBuilder()
    res = bpi.verify(bp_proof)
    gc.collect()

    # Return as struct as the hash(BP_struct) != hash(BP_serialized)
    # as the original hashing does not take vector lengths into account which are dynamic
    # in the serialization scheme (and thus extraneous)
    return res


def bp_comm_to_v(C):
    """
    Commitment to proof.V
    In mainnet it holds C = 8V
    :param C:
    :return:
    """
    return crypto.point_mulinv8(C)


def prove_range_chunked(amount, last_mask=None):
    a = crypto.sc_init(0)
    si = crypto.sc_init(0)
    c = crypto.sc_init(0)
    ee = crypto.sc_init(0)
    tmp_ai = crypto.sc_init(0)
    tmp_alpha = crypto.sc_init(0)

    C_acc = crypto.identity()
    C_h = crypto.xmr_H()
    C_tmp = crypto.identity()
    L = crypto.identity()
    Zero = crypto.identity()
    kck = crypto.get_keccak()

    ai = bytearray(32 * 64)
    alphai = bytearray(32 * 64)
    buff = bytearray(32)

    Cis = bytearray(32 * 64)
    s0s = bytearray(32 * 64)
    s1s = bytearray(32 * 64)
    ee_bin = bytearray(32)

    for ii in range(64):
        crypto.random_scalar_into(tmp_ai)
        if last_mask is not None and ii == 63:
            crypto.sc_sub_into(tmp_ai, last_mask, a)

        crypto.sc_add_into(a, a, tmp_ai)
        crypto.random_scalar_into(tmp_alpha)

        crypto.scalarmult_base_into(L, tmp_alpha)
        crypto.scalarmult_base_into(C_tmp, tmp_ai)

        # C_tmp += &Zero if BB(ii) == 0 else &C_h
        crypto.point_add_into(C_tmp, C_tmp, Zero if ((amount >> ii) & 1) == 0 else C_h)
        crypto.point_add_into(C_acc, C_acc, C_tmp)

        # Set Ci[ii] to sigs
        crypto.encodepoint_into(Cis, C_tmp, ii << 5)
        crypto.encodeint_into(ai, tmp_ai, ii << 5)
        crypto.encodeint_into(alphai, tmp_alpha, ii << 5)

        if ((amount >> ii) & 1) == 0:
            crypto.random_scalar_into(si)
            crypto.encodepoint_into(buff, L)
            crypto.hash_to_scalar_into(c, buff)

            crypto.point_sub_into(C_tmp, C_tmp, C_h)
            crypto.add_keys2_into(L, si, c, C_tmp)

            crypto.encodeint_into(s1s, si, ii << 5)

        crypto.encodepoint_into(buff, L)
        kck.update(buff)

        crypto.point_double_into(C_h, C_h)

    # Compute ee
    tmp_ee = kck.digest()
    crypto.decodeint_into(ee, tmp_ee)
    del (tmp_ee, kck)

    C_h = crypto.xmr_H()
    gc.collect()

    # Second pass, s0, s1
    for ii in range(64):
        crypto.decodeint_into(tmp_alpha, alphai, ii << 5)
        crypto.decodeint_into(tmp_ai, ai, ii << 5)

        if ((amount >> ii) & 1) == 0:
            crypto.sc_mulsub_into(si, tmp_ai, ee, tmp_alpha)
            crypto.encodeint_into(s0s, si, ii << 5)

        else:
            crypto.random_scalar_into(si)
            crypto.encodeint_into(s0s, si, ii << 5)

            crypto.decodepoint_into(C_tmp, Cis, ii << 5)
            crypto.add_keys2_into(L, si, ee, C_tmp)
            crypto.encodepoint_into(buff, L)
            crypto.hash_to_scalar_into(c, buff)

            crypto.sc_mulsub_into(si, tmp_ai, c, tmp_alpha)
            crypto.encodeint_into(s1s, si, ii << 5)

        crypto.point_double_into(C_h, C_h)

    crypto.encodeint_into(ee_bin, ee)

    del (ai, alphai, buff, tmp_ai, tmp_alpha, si, c, ee, C_tmp, C_h, L, Zero)
    gc.collect()

    return C_acc, a, [s0s, s1s, ee_bin, Cis]


def prove_range(
    amount,
    last_mask=None,
    mem_opt=True,
    backend_impl=False,
    decode=False,
    byte_enc=False,
    rsig=None,
):
    """
    Range proof generator.
    In order to minimize the memory consumption and CPU usage during transaction generation the returned values
    are returned encoded.

    :param amount:
    :param last_mask:
    :param mem_opt: memory optimized
    :param backend_impl: backend implementation, if available
    :param decode: decodes output
    :param byte_enc: decodes output
    :param rsig: buffer for rsig
    :return:
    """
    if backend_impl and crypto.get_backend().has_rangeproof_borromean():
        if byte_enc and decode:
            raise ValueError("Conflicting options byte_enc, decode")

        C, a, R = crypto.prove_range(amount, last_mask)[:3]  # backend returns encoded
        if not byte_enc:
            R = monero.inflate_rsig(R)
        if decode:
            R = monero.inflate_rsig(R)
            R = monero.recode_rangesig(R, encode=False)

        return C, a, R

    ret = None
    if not mem_opt:
        ret = prove_range_orig(amount, last_mask=last_mask)
    else:
        ret = prove_range_mem(amount, last_mask=last_mask)

    # Encoding
    C, a, R = ret[:3]
    if byte_enc:
        R = monero.recode_rangesig(R, encode=True)
        R = monero.flatten_rsig(R)
    elif not decode:
        R = monero.recode_rangesig(R, encode=True)

    return C, a, R


def prove_range_orig(amount, last_mask=None):
    """
    Gives C, and mask such that \sumCi = C
    c.f. http:#eprint.iacr.org/2015/1098 section 5.1

    Ci is a commitment to either 0 or 2^i, i=0,...,63
    thus this proves that "amount" is in [0, 2^ATOMS]
    mask is a such that C = aG + bH, and b = amount
    :param amount:
    :param last_mask: ai[ATOMS-1] will be computed as \sum_{i=0}^{ATOMS-2} a_i - last_mask
    :return: sumCi, mask, RangeSig.
        sumCi is Pedersen commitment on the amount value. sumCi = aG + amount*H
        mask is "a" from the Pedersent commitment above.
    """
    bb = d2b(amount, ATOMS)  # gives binary form of bb in "digits" binary digits
    logger.info("amount, amount in binary %s %s" % (amount, bb))
    ai = [None] * len(bb)
    Ci = [None] * len(bb)
    CiH = [None] * len(bb)  # this is like Ci - 2^i H
    H2 = crypto.gen_Hpow(ATOMS)
    a = crypto.sc_0()
    for i in range(0, ATOMS):
        ai[i] = crypto.random_scalar()
        if last_mask is not None and i == ATOMS - 1:
            ai[i] = crypto.sc_sub(last_mask, a)

        a = crypto.sc_add(
            a, ai[i]
        )  # creating the total mask since you have to pass this to receiver...
        if bb[i] == 0:
            Ci[i] = crypto.scalarmult_base(ai[i])
        if bb[i] == 1:
            Ci[i] = crypto.point_add(crypto.scalarmult_base(ai[i]), H2[i])
        CiH[i] = crypto.point_sub(Ci[i], H2[i])

    A = xmrtypes.BoroSig()
    A.s0, A.s1, A.ee = mlsag2.gen_borromean(ai, Ci, CiH, bb)

    R = xmrtypes.RangeSig()
    R.asig = A
    R.Ci = Ci

    C = sum_Ci(Ci)
    return C, a, R


def prove_range_mem(amount, last_mask=None):
    """
    Memory optimized range proof.

    Gives C, and mask such that \sumCi = C
    c.f. http:#eprint.iacr.org/2015/1098 section 5.1

    Ci is a commitment to either 0 or 2^i, i=0,...,63
    thus this proves that "amount" is in [0, 2^ATOMS]
    mask is a such that C = aG + bH, and b = amount
    :param amount:
    :param last_mask: ai[ATOMS-1] will be computed as \sum_{i=0}^{ATOMS-2} a_i - last_mask
    :return: sumCi, mask, RangeSig.
        sumCi is Pedersen commitment on the amount value. sumCi = aG + amount*H
        mask is "a" from the Pedersent commitment above.
    """
    n = ATOMS
    bb = d2b(amount, n)  # gives binary form of bb in "digits" binary digits
    ai = [None] * len(bb)
    Ci = [None] * len(bb)
    a = crypto.sc_0()

    C = crypto.identity()
    alpha = mlsag2.key_zero_vector(n)
    s1 = mlsag2.key_zero_vector(n)
    c_H = crypto.xmr_H()
    kck = crypto.get_keccak()  # ee computation

    # First pass, generates: ai, alpha, Ci, ee, s1
    for ii in range(n):
        ai[ii] = crypto.random_scalar()
        if last_mask is not None and ii == ATOMS - 1:
            ai[ii] = crypto.sc_sub(last_mask, a)

        a = crypto.sc_add(
            a, ai[ii]
        )  # creating the total mask since you have to pass this to receiver...

        alpha[ii] = crypto.random_scalar()
        L = crypto.scalarmult_base(alpha[ii])

        if bb[ii] == 0:
            Ci[ii] = crypto.scalarmult_base(ai[ii])
        else:
            Ci[ii] = crypto.point_add(crypto.scalarmult_base(ai[ii]), c_H)
        C = crypto.point_add(C, Ci[ii])

        if bb[ii] == 0:
            s1[ii] = crypto.random_scalar()
            c = crypto.hash_to_scalar(crypto.encodepoint(L))
            L = crypto.add_keys2(s1[ii], c, crypto.point_sub(Ci[ii], c_H))
            kck.update(crypto.encodepoint(L))

        else:
            kck.update(crypto.encodepoint(L))

        c_H = crypto.point_double(c_H)

    # Compute ee, memory cleanup
    ee = crypto.decodeint(kck.digest())
    del kck

    # Second phase computes: s0, s1
    c_H = crypto.xmr_H()
    s0 = mlsag2.key_zero_vector(n)

    for jj in range(n):
        if not bb[jj]:
            s0[jj] = crypto.sc_mulsub(ai[jj], ee, alpha[jj])

        else:
            s0[jj] = crypto.random_scalar()
            LL = crypto.add_keys2(s0[jj], ee, Ci[jj])
            cc = crypto.hash_to_scalar(crypto.encodepoint(LL))
            s1[jj] = crypto.sc_mulsub(ai[jj], cc, alpha[jj])
        c_H = crypto.point_double(c_H)

    A = xmrtypes.BoroSig()
    A.s0, A.s1, A.ee = s0, s1, ee

    R = xmrtypes.RangeSig()
    R.asig = A
    R.Ci = Ci

    return C, a, R


def ver_range(C=None, rsig=None, use_bulletproof=False, decode=True):
    """
    Verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    :param C:
    :param rsig:
    :param use_bulletproof: bulletproof
    :param decode: decodes encoded range proof
    :return:
    """
    n = ATOMS
    CiH = [None] * n
    C_tmp = crypto.identity()
    c_H = crypto.xmr_H()

    if decode and not use_bulletproof:
        rsig = monero.recode_rangesig(rsig, encode=False, copy=True)

    if not use_bulletproof:
        for i in range(0, n):
            CiH[i] = crypto.point_sub(rsig.Ci[i], c_H)
            C_tmp = crypto.point_add(C_tmp, rsig.Ci[i])
            c_H = crypto.point_double(c_H)

        if C is not None and not crypto.point_eq(C_tmp, C):
            return 0

    if use_bulletproof:
        bp = bulletproof.BulletProofBuilder()
        return bp.verify(rsig)

    return mlsag2.ver_borromean(rsig.Ci, CiH, rsig.asig.s0, rsig.asig.s1, rsig.asig.ee)


# Ring-ct MG sigs
# Prove:
#   c.f. http:#eprint.iacr.org/2015/1098 section 4. definition 10.
#   This does the MG sig on the "dest" part of the given key matrix, and
#   the last row is the sum of input commitments from that column - sum output commitments
#   this shows that sum inputs = sum outputs
# Ver:
#   verifies the above sig is created corretly


def ecdh_encode(unmasked, receiver_pk=None, derivation=None, v2=False, dest=None):
    """
    Elliptic Curve Diffie-Helman: encodes and decodes the amount b and mask a
    where C= aG + bH
    :param unmasked:
    :param receiver_pk:
    :param derivation:
    :return:
    """
    rv = xmrtypes.EcdhTuple() if dest is None else dest
    if derivation is None:
        esk = crypto.random_scalar()
        rv.senderPk = crypto.scalarmult_base(esk)
        derivation = crypto.encodepoint(crypto.scalarmult(receiver_pk, esk))

    return ecdh_encdec(unmasked, None, derivation, v2=v2, enc=True, dest=rv)


def ecdh_decode(masked, receiver_sk=None, derivation=None, v2=False, dest=None):
    """
    Elliptic Curve Diffie-Helman: encodes and decodes the amount b and mask a
    where C= aG + bH
    """
    return ecdh_encdec(masked, receiver_sk, derivation, v2=v2, enc=False, dest=dest)


def ecdh_encdec(masked, receiver_sk=None, derivation=None, v2=False, enc=True, dest=None):
    """
    Elliptic Curve Diffie-Helman: encodes and decodes the amount b and mask a
    where C= aG + bH
    """
    rv = xmrtypes.EcdhTuple() if dest is None else dest
    if derivation is None:
        derivation = crypto.scalarmult(masked.senderPk, receiver_sk)

    if v2:
        amnt = masked.amount
        rv.mask = monero.commitment_mask(derivation)
        rv.amount = bytearray(32)
        crypto.encodeint_into(rv.amount, amnt)
        crypto.xor8(rv.amount, monero.ecdh_hash(derivation))
        rv.amount = crypto.decodeint(rv.amount)
        return rv

    else:
        amount_key_hash_single = crypto.hash_to_scalar(derivation)
        amount_key_hash_double = crypto.hash_to_scalar(
            crypto.encodeint(amount_key_hash_single)
        )

        sc_fnc = crypto.sc_add if enc else crypto.sc_sub
        rv.mask = sc_fnc(masked.mask, amount_key_hash_single)
        rv.amount = sc_fnc(masked.amount, amount_key_hash_double)
        return rv


#
# RingCT protocol
#


def decode_rct(rv, sk, i):
    """
    c.f. http:#eprint.iacr.org/2015/1098 section 5.1.1
    Uses the attached ecdh info to find the amounts represented by each output commitment
    must know the destination private key to find the correct amount, else will return a random number

    :param rv:
    :param sk:
    :param i:
    :return:
    """
    decodedTuple = ecdh_decode(rv.ecdhInfo[i], sk)
    mask = decodedTuple.mask
    amount = decodedTuple.amount
    C = rv.outPk[i].mask
    H = crypto.xmr_H()
    Ctmp = crypto.point_add(crypto.scalarmult_base(mask), crypto.scalarmult(H, amount))
    if not crypto.point_eq(crypto.point_sub(C, Ctmp), crypto.identity()):
        logger.warning("warning, amount decoded incorrectly, will be unable to spend")
    return amount


#
# Key image import / export
#


def generate_ring_signature(prefix_hash, image, pubs, sec, sec_idx, test=False):
    """
    Generates ring signature with key image.
    void crypto_ops::generate_ring_signature()
    """
    if test:
        t = crypto.scalarmult_base(sec)
        if not crypto.point_eq(t, pubs[sec_idx]):
            raise ValueError("Invalid sec key")

        k_i = monero.generate_key_image(crypto.encodepoint(pubs[sec_idx]), sec)
        if not crypto.point_eq(k_i, image):
            raise ValueError("Key image invalid")
        for k in pubs:
            crypto.ge_frombytes_vartime_check(k)

    image_unp = crypto.ge_frombytes_vartime(image)
    image_pre = crypto.ge_dsm_precomp(image_unp)

    buff_off = len(prefix_hash)
    buff = bytearray(buff_off + 2 * 32 * len(pubs))
    memcpy(buff, 0, prefix_hash, 0, buff_off)
    mvbuff = memoryview(buff)

    sum = crypto.sc_0()
    k = crypto.sc_0()
    sig = []
    for i in range(len(pubs)):
        sig.append([crypto.sc_0(), crypto.sc_0()])  # c, r

    for i in range(len(pubs)):
        if i == sec_idx:
            k = crypto.random_scalar()
            tmp3 = crypto.scalarmult_base(k)
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp3)
            buff_off += 32

            tmp3 = crypto.hash_to_point(crypto.encodepoint(pubs[i]))
            tmp2 = crypto.scalarmult(tmp3, k)
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
            buff_off += 32

        else:
            sig[i] = [crypto.random_scalar(), crypto.random_scalar()]
            tmp3 = crypto.ge_frombytes_vartime(pubs[i])
            tmp2 = crypto.ge_double_scalarmult_base_vartime(sig[i][0], tmp3, sig[i][1])
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
            buff_off += 32

            tmp3 = crypto.hash_to_point(crypto.encodepoint(tmp3))
            tmp2 = crypto.ge_double_scalarmult_precomp_vartime(
                sig[i][1], tmp3, sig[i][0], image_pre
            )
            crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
            buff_off += 32

            sum = crypto.sc_add(sum, sig[i][0])

    h = crypto.hash_to_scalar(buff)
    sig[sec_idx][0] = crypto.sc_sub(h, sum)
    sig[sec_idx][1] = crypto.sc_mulsub(sig[sec_idx][0], sec, k)
    return sig


def check_ring_singature(prefix_hash, image, pubs, sig):
    """
    Checks ring signature generated with generate_ring_signature
    """
    image_unp = crypto.ge_frombytes_vartime(image)
    image_pre = crypto.ge_dsm_precomp(image_unp)

    buff_off = len(prefix_hash)
    buff = bytearray(buff_off + 2 * 32 * len(pubs))
    memcpy(buff, 0, prefix_hash, 0, buff_off)
    mvbuff = memoryview(buff)

    sum = crypto.sc_0()
    for i in range(len(pubs)):
        if crypto.sc_check(sig[i][0]) != 0 or crypto.sc_check(sig[i][1]) != 0:
            return False

        tmp3 = crypto.ge_frombytes_vartime(pubs[i])
        tmp2 = crypto.ge_double_scalarmult_base_vartime(sig[i][0], tmp3, sig[i][1])
        crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
        buff_off += 32

        tmp3 = crypto.hash_to_point(crypto.encodepoint(pubs[i]))
        tmp2 = crypto.ge_double_scalarmult_precomp_vartime(
            sig[i][1], tmp3, sig[i][0], image_pre
        )
        crypto.encodepoint_into(mvbuff[buff_off : buff_off + 32], tmp2)
        buff_off += 32

        sum = crypto.sc_add(sum, sig[i][0])

    h = crypto.hash_to_scalar(buff)
    h = crypto.sc_sub(h, sum)
    return crypto.sc_isnonzero(h) == 0


def export_key_image(
    creds,
    subaddresses,
    pkey,
    tx_pub_key,
    additional_tx_pub_keys,
    out_idx,
    test=True,
    verify=True,
):
    """
    Generates key image for the TXO + signature for the key image
    """
    r = monero.generate_key_image_helper(
        creds, subaddresses, pkey, tx_pub_key, additional_tx_pub_keys, out_idx
    )
    xi, ki, recv_derivation = r[:3]

    phash = crypto.encodepoint(ki)
    sig = generate_ring_signature(phash, ki, [pkey], xi, 0, test)

    if verify:
        if check_ring_singature(phash, ki, [pkey], sig) != 1:
            raise ValueError("Signature error")

    return ki, sig
