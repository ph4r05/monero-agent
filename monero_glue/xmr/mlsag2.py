#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018
# see https://eprint.iacr.org/2015/1098.pdf

import logging
from monero_glue.xmr import crypto, common
from monero_serialize import xmrtypes

logger = logging.getLogger(__name__)


def key_zero_vector(rows):
    """
    Empty key vector
    :param rows:
    :return:
    """
    vct = []
    for i in range(rows):
        vct.append(crypto.sc_0())
    return vct


def key_vector(rows):
    """
    Empty key vector
    :param rows:
    :return:
    """
    return [None] * rows


def key_matrix(rows, cols):
    """
    first index is columns (so slightly backward from math)
    :param rows:
    :param cols:
    :return:
    """
    rv = [None] * cols
    for i in range(0, cols):
        rv[i] = key_vector(rows)
    return rv


def hash_key_vector(v):
    """
    Hashes key vector
    :param v:
    :return:
    """
    return [crypto.hash_to_ec(vi) for vi in v]


def scalar_mult_base_vector(v):
    """
    Creates vector of points from scalars
    :param v:
    :return:
    """
    return [crypto.scalarmult_base(a) for a in v]


def key_image_vector(x):
    """
    Takes as input a keyvector, returns the keyimage-vector
    TODO: use crypto for generating key images
    :param x:
    :return:
    """
    return [crypto.scalarmult(crypto.hash_to_ec(crypto.scalarmult_base(xx)), xx) for xx in x]


def scalar_gen_vector(n):
    """
    Generates vector of scalars
    :param n:
    :return:
    """
    return [crypto.random_scalar() for i in range(0, n)]


def scalar_gen_matrix(r, c):
    """
    Generates matrix of scalars
    :param r:
    :param c:
    :return:
    """
    rv = key_matrix(r, c)
    for i in range(0, c):
        rv[i] = scalar_gen_vector(r)
    return rv


def decode_points(vct):
    """
    Decodes vector of points
    :param vct:
    :return:
    """
    return [crypto.decodepoint(x) for x in vct]


def copy_ct_key(ct):
    """
    Ct key copy
    :param ct:
    :return:
    """
    return xmrtypes.CtKey(mask=ct.mask, dest=ct.dest)


def copy_ct_keys(vct):
    """
    Copy of the CtKey vector
    :param vct:
    :return:
    """
    return [copy_ct_key(x) for x in vct]


def decode_ct_keys_points(vct, copy=False):
    """
    Decodes CtKeys vector as points
    :param vct:
    :param copy:
    :return:
    """
    rvct = copy_ct_keys(vct) if copy else vct
    for i in range(len(rvct)):
        rvct[i].mask = crypto.decodepoint(rvct[i].mask)
        rvct[i].dest = crypto.decodepoint(rvct[i].dest)
    return rvct


def decode_ct_keys_matrix_points(mxt, copy=False):
    """
    Decodes CtKeys matrix as points
    :param vct:
    :param copy:
    :return:
    """
    rmxt = key_matrix(len(mxt), len(mxt[0])) if copy else mxt
    for i in range(len(mxt)):
        cur = decode_ct_keys_points(mxt[i], copy)
        if copy:
            rmxt[i] = cur

    return rmxt


def gen_mlsag(pk, xx, index):
    """
    Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)

    These are aka MG signatutes in earlier drafts of the ring ct paper
    c.f. http://eprint.iacr.org/2015/1098 section 2.
    keyImageV just does I[i] = xx[i] * Hash(xx[i] * G) for each i

    Gen creates a signature which proves that for some column in the keymatrix "pk"
       the signer knows a secret key for each row in that column
    Ver verifies that the MG sig was created correctly

    :param pk:
    :param xx:
    :param index:
    :return:
    """
    rows = len(xx)
    cols = len(pk)
    logger.debug("Generating MG sig of size %s x %s" % (rows, cols))
    logger.debug("index is: %s, %s" % (index, pk[index]))
    c = [None] * cols
    alpha = scalar_gen_vector(rows)
    I = key_image_vector(xx)
    L = key_matrix(rows, cols)
    R = key_matrix(rows, cols)
    s = key_matrix(rows, cols)

    m = ''.join(pk[0])
    for i in range(1, cols):
        m = m + ''.join(pk[i])

    L[index] = [crypto.scalarmult_base(aa) for aa in alpha]  # L = aG
    Hi = hash_key_vector(pk[index])
    R[index] = [crypto.scalarmult(Hi[ii], alpha[ii]) for ii in range(0, rows)]  # R = aI
    
    oldi = index
    i = (index + 1) % cols
    c[i] = crypto.cn_fast_hash(m + ''.join(L[oldi]) + ''.join(R[oldi]))

    while i != index:
        s[i] = scalar_gen_vector(rows)
        L[i] = [crypto.add_keys2(s[i][j], c[i], pk[i][j]) for j in range(0, rows)]

        Hi = hash_key_vector(pk[i])
        R[i] = [crypto.add_keys3(s[i][j], Hi[j], c[i], I[j]) for j in range(0, rows)]
        oldi = i
        i = (i + 1) % cols
        c[i] = crypto.cn_fast_hash(m + ''.join(L[oldi]) + ''.join(R[oldi]))

    s[index] = [crypto.sc_mulsub(c[index], xx[j], alpha[j]) for j in range(0, rows)]  # alpha - c * x
    return I, c[0], s


def ver_mlsag(pk, I, c0, s):
    """
    Verify MLSAG
    :param pk:
    :param I:
    :param c0:
    :param s:
    :return:
    """
    rows = len(pk[0])
    cols = len(pk)
    logger.debug("verifying MG sig of dimensions %s x %s" % (rows, cols))
    c = [None] * (cols + 1)
    c[0] = c0
    L = key_matrix(rows, cols)
    R = key_matrix(rows, cols)
    
    m = ''.join(pk[0])
    for i in range(1, cols):
        m = m + ''.join(pk[i])

    i = 0
    while i < cols:
        L[i] = [crypto.add_keys2(s[i][j], c[i], pk[i][j]) for j in range(0, rows)]

        Hi = hash_key_vector(pk[i])
        R[i] = [crypto.add_keys3(s[i][j], Hi[j], c[i], I[j]) for j in range(0, rows)]

        oldi = i
        i = i + 1
        c[i] = crypto.cn_fast_hash(m + ''.join(L[oldi]) + ''.join(R[oldi]))

    return c0 == c[cols]


#
# Borromean signatures for range proofs
#


def gen_borromean(x, P1, P2, indices):
    """
    Generates Borromean signature for range proofs.
    :return:
    """
    n = len(P1)
    alpha = key_zero_vector(n)
    s1 = key_zero_vector(n)
    kck = crypto.get_keccak()  # ee computation

    for ii in range(n):
        alpha[ii] = crypto.random_scalar()
        L = crypto.scalarmult_base(alpha[ii])

        if indices[ii] == 0:
            s1[ii] = crypto.random_scalar()
            c = crypto.hash_to_scalar(crypto.encodepoint(L))
            L = crypto.add_keys2(s1[ii], c, P2[ii])
            kck.update(crypto.encodepoint(L))

        else:
            kck.update(crypto.encodepoint(L))

    ee = crypto.sc_reduce32(crypto.decodeint(kck.digest()))
    del kck

    s0 = key_zero_vector(n)

    for jj in range(n):
        if not indices[jj]:
            s0[jj] = crypto.sc_mulsub(x[jj], ee, alpha[jj])
        else:
            s0[jj] = crypto.random_scalar()
            LL = crypto.add_keys2(s0[jj], ee, P1[jj])
            cc = crypto.hash_to_scalar(crypto.encodepoint(LL))
            s1[jj] = crypto.sc_mulsub(x[jj], cc, alpha[jj])

    return s0, s1, ee


def ver_borromean(P1, P2, s0, s1, ee):
    """
    Verify range proof signature, Borromean
    (c.f. gmax/andytoshi's paper)
    :param P1:
    :param P2:
    :param s0:
    :param s1:
    :param ee:
    :return:
    """
    n = len(P1)
    Lv1 = key_vector(n)
    for ii in range(n):
        LL = crypto.add_keys2(s0[ii], ee, P1[ii])
        chash = crypto.hash_to_scalar(crypto.encodepoint(LL))
        Lv1[ii] = crypto.add_keys2(s1[ii], chash, P2[ii])

    kck = crypto.get_keccak()
    for ii in range(n):
        kck.update(crypto.encodepoint(Lv1[ii]))

    # ee_computed = crypto.hash_to_scalar(crypto.encodepoint(Lv1))
    ee_computed = crypto.sc_reduce32(crypto.decodeint(kck.digest()))

    return crypto.sc_eq(ee_computed, ee)


#
# Optimized versions with incremental hashing,
# Simple and full variants for Monero
#


def hasher_message(message):
    """
    Returns incremental hasher for MLSAG
    :param message:
    :return:
    """
    ctx = common.HashWrapper(crypto.get_keccak())
    ctx.update(message)
    return ctx


def gen_mlsag_assert(pk, xx, kLRki, mscout, index, dsRows):
    """
    Conditions check for gen_mlsag_ext.
    :param pk:
    :param xx:
    :param kLRki:
    :param mscout:
    :param index:
    :param dsRows:
    :return:
    """
    cols = len(pk)
    if cols <= 1:
        raise ValueError('Cols == 1')
    if index >= cols:
        raise ValueError('Index out of range')

    rows = len(pk[0])
    if rows == 0:
        raise ValueError('Empty pk')

    for i in range(cols):
        if len(pk[i]) != rows:
            raise ValueError('pk is not rectangular')
    if len(xx) != rows:
        raise ValueError('Bad xx size')
    if dsRows > rows:
        raise ValueError('Bad dsRows size')
    if (not kLRki or not mscout) and (kLRki or mscout):
        raise ValueError('Only one of kLRki/mscout is present')
    if kLRki and dsRows != 1:
        raise ValueError('Multisig requires exactly 1 dsRows')
    return rows, cols


def gen_mlsag_rows(message, rv, pk, xx, kLRki, index, dsRows, rows, cols):
    """
    MLSAG computation - the part with secret keys
    :param message:
    :param rv:
    :param pk:
    :param xx:
    :param kLRki:
    :param index:
    :param dsRows:
    :param rows:
    :param cols:
    :return:
    """
    Ip = key_vector(dsRows)
    rv.II = key_vector(dsRows)
    alpha = key_vector(rows)
    rv.ss = key_matrix(rows, cols)

    hasher = hasher_message(message)

    for i in range(dsRows):
        hasher.update(crypto.encodepoint(pk[index][i]))
        if kLRki:
            alpha[i] = kLRki.k
            rv.II[i] = kLRki.ki
            hasher.update(crypto.encodepoint(kLRki.L))
            hasher.update(crypto.encodepoint(kLRki.R))

        else:
            Hi = crypto.hash_to_ec(crypto.encodepoint(pk[index][i]))  # originally hashToPoint()
            alpha[i] = crypto.random_scalar()
            aGi = crypto.scalarmult_base(alpha[i])
            aHPi = crypto.scalarmult(Hi, alpha[i])
            rv.II[i] = crypto.scalarmult(Hi, xx[i])
            hasher.update(crypto.encodepoint(aGi))
            hasher.update(crypto.encodepoint(aHPi))

        Ip[i] = crypto.precomp(rv.II[i])

    for i in range(dsRows, rows):
        alpha[i] = crypto.random_scalar()
        aGi = crypto.scalarmult_base(alpha[i])
        hasher.update(crypto.encodepoint(pk[index][i]))
        hasher.update(crypto.encodepoint(aGi))

    c_old = hasher.digest()
    c_old = crypto.sc_reduce32(crypto.decodeint(c_old))
    return c_old, Ip, alpha


def gen_mlsag_ext(message, pk, xx, kLRki, mscout, index, dsRows):
    """
    Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)

    :param message:
    :param pk: matrix of points, point form (not encoded)
    :param xx:
    :param kLRki:
    :param mscout:
    :param index:
    :param dsRows:
    :return:
    """
    rows, cols = gen_mlsag_assert(pk, xx, kLRki, mscout, index, dsRows)

    rv = xmrtypes.MgSig()
    c, L, R, Hi = 0, None, None, None

    c_old, Ip, alpha = gen_mlsag_rows(message, rv, pk, xx, kLRki, index, dsRows, rows, cols)

    i = (index + 1) % cols
    if i == 0:
        rv.cc = c_old

    while i != index:
        rv.ss[i] = scalar_gen_vector(rows)
        hasher = hasher_message(message)

        for j in range(dsRows):
            L = crypto.add_keys2(rv.ss[i][j], c_old, pk[i][j])
            Hi = crypto.hash_to_ec(crypto.encodepoint(pk[i][j]))  # originally hashToPoint()
            R = crypto.add_keys3(rv.ss[i][j], Hi, c_old, Ip[j])
            hasher.update(crypto.encodepoint(pk[i][j]))
            hasher.update(crypto.encodepoint(L))
            hasher.update(crypto.encodepoint(R))

        for j in range(dsRows, rows):
            L = crypto.add_keys2(rv.ss[i][j], c_old, pk[i][j])
            hasher.update(crypto.encodepoint(pk[i][j]))
            hasher.update(crypto.encodepoint(L))

        c = crypto.sc_reduce32(crypto.decodeint(hasher.digest()))
        c_old = c
        i = (i + 1) % cols

        if i == 0:
            rv.cc = c_old

    for j in range(rows):
        rv.ss[index][j] = crypto.sc_mulsub(c, xx[j], alpha[j])  # alpha[j] - c * xx[j]; sc_mulsub in original does c-ab

    if mscout:
        mscout(c)

    return rv, c


def ver_mlsag_assert(pk, rv, dsRows):
    """
    Initial params verification for ver_mlsag
    :param pk:
    :param rv:
    :param dsRows:
    :return:
    """
    cols = len(pk)
    if cols < 2:
        raise ValueError('Error! What is c if cols = 1!')

    rows = len(pk[0])
    if rows == 0:
        raise ValueError('Empty pk')

    for i in range(cols):
        if len(pk[i]) != rows:
            raise ValueError('pk is not rectangular')

    if len(rv.II) != dsRows:
        raise ValueError('Bad II size')
    if len(rv.ss) != cols:
        raise ValueError('Bad rv.ss size')
    for i in range(cols):
        if len(rv.ss[i]) != rows:
            raise ValueError('rv.ss is not rectangular')
    if dsRows > rows:
        raise ValueError('Bad dsRows value')

    return rows, cols


def ver_mlsag_ext(message, pk, rv, dsRows):
    """
    Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)
    c.f. http://eprint.iacr.org/2015/1098 section 2.
    keyImageV just does I[i] = xx[i] * Hash(xx[i] * G) for each i

    :param message:
    :param pk: matrix of EC points, point form.
    :param rv:
    :param dsRows:
    :return:
    """
    rows, cols = ver_mlsag_assert(pk, rv, dsRows)
    c_old = rv.cc

    Ip = key_vector(dsRows)
    for i in range(dsRows):
        Ip[i] = crypto.precomp(rv.II[i])

    i = 0
    while i < cols:
        c = 0
        hasher = hasher_message(message)
        for j in range(dsRows):
            L = crypto.add_keys2(rv.ss[i][j], c_old, pk[i][j])
            Hi = crypto.hash_to_ec(crypto.encodepoint(pk[i][j]))  # originally hashToPoint()
            R = crypto.add_keys3(rv.ss[i][j], Hi, c_old, Ip[j])
            hasher.update(crypto.encodepoint(pk[i][j]))
            hasher.update(crypto.encodepoint(L))
            hasher.update(crypto.encodepoint(R))

        for j in range(dsRows, rows):
            L = crypto.add_keys2(rv.ss[i][j], c_old, pk[i][j])
            hasher.update(crypto.encodepoint(pk[i][j]))
            hasher.update(crypto.encodepoint(L))

        c = crypto.sc_reduce32(crypto.decodeint(hasher.digest()))
        c_old = c
        i += 1

    c = crypto.sc_sub(c_old, rv.cc)
    return not crypto.sc_isnonzero(c)


def prove_rct_mg(message, pubs, in_sk, out_sk, out_pk, kLRki, mscout, index, txn_fee_key):
    """
    c.f. http://eprint.iacr.org/2015/1098 section 4. definition 10.
    This does the MG sig on the "dest" part of the given key matrix, and
    the last row is the sum of input commitments from that column - sum output commitments
    this shows that sum inputs = sum outputs
    :param message:
    :param pubs: matrix of CtKeys. points are encoded.
    :param in_sk:
    :param out_sk:
    :param out_pk:
    :param kLRki:
    :param mscout:
    :param index:
    :param txn_fee_key:
    :return:
    """
    cols = len(pubs)
    if cols == 0:
        raise ValueError('Empty pubs')
    rows = len(pubs[0])
    if rows == 0:
        raise ValueError('Empty pub row')
    for i in range(cols):
        if len(pubs[i]) != rows:
            raise ValueError('pub is not rectangular')

    if len(in_sk) != rows:
        raise ValueError('Bad inSk size')
    if len(out_sk) != len(out_pk):
        raise ValueError('Bad outsk/putpk size')
    if (not kLRki or not mscout) and (kLRki and mscout):
        raise ValueError('Only one of kLRki/mscout is present')

    sk = key_vector(rows + 1)
    M = key_matrix(rows + 1, cols)
    for i in range(rows + 1):
        sk[i] = crypto.sc_0()

    for i in range(cols):
        M[i][rows] = crypto.identity()
        for j in range(rows):
            M[i][j] = crypto.decodepoint(pubs[i][j].dest)
            M[i][rows] = crypto.point_add(M[i][rows], crypto.decodepoint(pubs[i][j].mask))

    sk[rows] = crypto.sc_0()
    for j in range(rows):
        sk[j] = in_sk[j].dest
        sk[rows] = crypto.sc_add(sk[rows], in_sk[j].mask)  # add masks in last row

    for i in range(cols):
        for j in range(len(out_pk)):
            M[i][rows] = crypto.point_sub(M[i][rows], crypto.decodepoint(out_pk[j].mask))  # subtract output Ci's in last row

        # Subtract txn fee output in last row
        M[i][rows] = crypto.point_sub(M[i][rows], txn_fee_key)

    for j in range(len(out_pk)):
        sk[rows] = crypto.sc_sub(sk[rows], out_sk[j].mask)  # subtract output masks in last row

    return gen_mlsag_ext(message, M, sk, kLRki, mscout, index, rows)


def prove_rct_mg_simple(message, pubs, in_sk, a, cout, kLRki, mscout, index):
    """
    Simple version for when we assume only
        post rct inputs
        here pubs is a vector of (P, C) length mixin

    :param message:
    :param pubs: vector of CtKeys, public, point values, encoded form. (dest, mask) = (P, C)
    :param in_sk: CtKey, private. (spending private key, input commitment mask (original))
    :param a: mask from the pseudo_output commitment (alpha)
    :param cout: point, decoded. Pseudo output public key.
    :param kLRki:
    :param mscout: lambda accepting c
    :param index:
    :return:
    """
    rows = 1
    cols = len(pubs)
    if cols == 0:
        raise ValueError('Empty pubs')
    if (not kLRki or not mscout) and (kLRki and mscout):
        raise ValueError('Only one of kLRki/mscout is present')

    sk = key_vector(rows + 1)
    M = key_matrix(rows + 1, cols)

    sk[0] = in_sk.dest
    sk[1] = crypto.sc_sub(in_sk.mask, a)

    for i in range(cols):
        M[i][0] = crypto.decodepoint(pubs[i].dest)
        M[i][1] = crypto.point_sub(crypto.decodepoint(pubs[i].mask), cout)

    return gen_mlsag_ext(message, M, sk, kLRki, mscout, index, rows)


def ver_rct_mg(mg, pubs, out_pk, txn_fee_key, message):
    """
    Verifies the above sig is created corretly
    :param mg:
    :param pubs: matrix of EC points, encoded
    :param out_pk:
    :param txn_fee_key:
    :param message:
    :return:
    """
    cols = len(pubs)
    if cols == 0:
        raise ValueError('Empty pubs')
    rows = len(pubs[0])
    if rows == 0:
        raise ValueError('Empty pubs[0]')
    for i in range(cols):
        if len(pubs[i]) != rows:
            raise ValueError('pubs is not rectangular')

    M = key_matrix(rows + 1, cols)
    for i in range(cols):
        M[i][rows] = crypto.identity()

    for j in range(rows):
        for i in range(cols):
            M[i][j] = crypto.decodepoint(pubs[i][j].dest)
            M[i][rows] = crypto.point_add(M[i][rows], crypto.decodepoint(pubs[i][j].mask))  # add Ci in last row

    for i in range(cols):
        for j in range(len(out_pk)):
            M[i][rows] = crypto.point_sub(M[i][rows], crypto.decodepoint(out_pk[j].mask))  # subtract output Ci's in last row

        # subtract txn fee output in last row
        M[i][rows] = crypto.point_sub(M[i][rows], txn_fee_key)

    return ver_mlsag_ext(message, M, mg, rows)


def ver_rct_mg_simple(message, mg, pubs, C):
    """
    Verifies the above sig is created corretly
    :param message:
    :param mg:
    :param pubs: vector of points, encoded
    :param C:
    :return:
    """
    rows = 1
    cols = len(pubs)
    if cols == 0:
        raise ValueError('Empty pubs')

    M = key_matrix(rows + 1, cols)
    for i in range(cols):
        M[i][0] = crypto.decodepoint(pubs[i].dest)
        M[i][1] = crypto.point_sub(crypto.decodepoint(pubs[i].mask), C)

    return ver_mlsag_ext(message, M, mg, rows)

