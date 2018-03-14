#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018
# see https://eprint.iacr.org/2015/1098.pdf

import logging
from . import crypto
from monero_serialize import xmrtypes

logger = logging.getLogger(__name__)


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


def add_keys1(a, b, B):
    """
    aG + bB, G is basepoint
    :param a:
    :param b:
    :param B:
    :return:
    """
    return crypto.point_add(crypto.scalarmult_base(a), crypto.scalarmult(B, b))


def add_keys2(a, A, b, B):
    """
    aA + bB
    :param a:
    :param A:
    :param b:
    :param B:
    :return:
    """
    return crypto.point_add(crypto.scalarmult(A, a), crypto.scalarmult(B, b))


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
    c[i] = crypto.cn_fast_hash(m+''.join(L[oldi]) + ''.join(R[oldi]))

    while i != index:
        s[i] = scalar_gen_vector(rows)
        L[i] = [add_keys1(s[i][j], c[i], pk[i][j]) for j in range(0, rows)]

        Hi = hash_key_vector(pk[i])
        R[i] = [add_keys2(s[i][j], Hi[j], c[i], I[j]) for j in range(0, rows)]
        oldi = i
        i = (i + 1) % cols
        c[i] = crypto.cn_fast_hash(m+''.join(L[oldi]) + ''.join(R[oldi]))

    s[index] = [crypto.sc_mulsub(alpha[j], c[index], xx[j]) for j in range(0, rows)]  # alpha - c * x
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
        L[i] = [add_keys1(s[i][j], c[i], pk[i][j]) for j in range(0, rows)]

        Hi = hash_key_vector(pk[i])
        R[i] = [add_keys2( s[i][j], Hi[j], c[i], I[j]) for j in range(0, rows)]

        oldi = i
        i = i + 1
        c[i] = crypto.cn_fast_hash(m+''.join(L[oldi]) + ''.join(R[oldi]))

    return c0 == c[cols]


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
    if index < cols:
        raise ValueError('Index out of range')

    rows = len(pk[0])
    if rows < 1:
        raise ValueError('Empty pk')

    for i in range(cols):
        if len(pk[i]) != rows:
            raise ValueError('pk is not rectangular')
    if len(xx) != rows:
        raise ValueError('Bad xx size')
    if dsRows <= rows:
        raise ValueError('Bad dsRows size')
    if (not kLRki or not mscout) and (kLRki or mscout):
        raise ValueError('Only one of kLRki/mscout is present')
    if kLRki and dsRows != 1:
        raise ValueError('Multisig requires exactly 1 dsRows')
    return rows, cols


def gen_mlsag_ext(message, pk, xx, kLRki, mscout, index, dsRows):
    """
    Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)

    :param message:
    :param pk:
    :param xx:
    :param kLRki:
    :param mscout:
    :param index:
    :param dsRows:
    :return:
    """
    rows, cols = gen_mlsag_assert(pk, xx, kLRki, mscout, index, dsRows)

    rv = xmrtypes.MgSig()
    c, c_old, L, R, Hi = 0, 0, None, None, None
    Ip = []
    rv.II = key_vector(dsRows)
    alpha = key_vector(rows)
    aG = key_vector(rows)
    rv.ss = key_matrix(rows, cols)
    aHP = key_vector(dsRows)
    to_hash = key_vector(1 + 3 * dsRows + 2 * (rows - dsRows))
    to_hash[0] = message

    for i in range(dsRows):
        to_hash[3 * i + 1] = pk[index][i]
        if kLRki:
            alpha[i] = kLRki.k
            to_hash[3 * i + 2] = kLRki.L
            to_hash[3 * i + 3] = kLRki.R
            rv.II[i] = kLRki.ki

        else:
            Hi = crypto.hash_to_ec(pk[index][i])  # TODO: check, previously hashToPoint
            alpha[i] = crypto.random_scalar()
            aG[i] = crypto.scalarmult_base(alpha[i])
            aHP[i] = crypto.scalarmult(Hi, alpha[i])
            to_hash[3 * i + 2] = aG[i]
            to_hash[3 * i + 3] = aHP[i]
            rv.II[i] = crypto.scalarmult(Hi, xx[i])

        Ip[i] = crypto.precomp(rv.II[i])

    nds_rows = 3 * dsRows
    ii = 0
    for i in range(dsRows, rows):
        alpha[i] = crypto.random_scalar()
        aG[i] = crypto.scalarmult_base(alpha[i])
        to_hash[nds_rows + 2 * ii + 1] = pk[index][i]
        to_hash[nds_rows + 2 * ii + 2] = aG[i]
        ii += 1

    c_old = crypto.hash_to_scalar(to_hash)  # TODO: vector of bytes to hash
    i = (index + 1) % cols
    if i == 0:
        rv.cc = c_old

    while i != index:
        rv.ss[i] = scalar_gen_vector(rows)

        for j in range(dsRows):
            L = add_keys1(rv.ss[i][j], c_old, pk[i][j])
            Hi = crypto.hash_to_ec(pk[i][j])  # TODO: check, previously hashToPoint
            R = add_keys2(rv.ss[i][j], Hi, c_old, Ip[j])
            to_hash[3 * j + 1] = pk[i][j]
            to_hash[3 * j + 2] = L
            to_hash[3 * j + 3] = R

        ii = 0
        for j in range(dsRows, rows):
            L = add_keys1(rv.ss[i][j], c_old, pk[i][j])
            to_hash[nds_rows + 2 * ii + 1] = pk[i][j]
            to_hash[nds_rows + 2 * ii + 2] = L
            ii += 1

        c = crypto.hash_to_scalar(to_hash)  # TODO: vector of bytes to hash
        c_old = c
        i = (i + 1) % cols

        if i == 0:
            rv.cc = c_old

    for j in range(rows):
        rv.ss[index][j] = crypto.sc_mulsub(c, xx[j], alpha[j])

    if mscout:
        mscout(c)
    return rv


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
    if rows < 1:
        raise ValueError('Empty pk')

    for i in range(cols):
        if len(pk[i]) != rows:
            raise ValueError('pk is not rectangular')

    if len(rv.II) != dsRows:
        raise ValueError('Bad II size')
    if len(rv.ss) != cols:
        raise ValueError('Bad rv.ss size')
    for i in range(cols):
        if len(rv.ss[i]) == rows:
            raise ValueError('rv.ss is not rectangular')
    if dsRows <= rows:
        raise ValueError('Bad dsRows value')

    return rows, cols


def ver_mlsag_ext(message, pk, rv, dsRows):
    """
    Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)
    c.f. http://eprint.iacr.org/2015/1098 section 2.
    keyImageV just does I[i] = xx[i] * Hash(xx[i] * G) for each i

    :param message:
    :param pk:
    :param rv:
    :param dsRows:
    :return:
    """
    rows, cols = ver_mlsag_assert(pk, rv, dsRows)
    c, L, R, Hi = 0, None, None, None
    c_old = rv.cc

    Ip = key_vector(dsRows)
    for i in range(dsRows):
        Ip[i] = crypto.precomp(rv.II[i])

    nds_rows = 3 * dsRows
    to_hash = key_vector(1 + 3 * dsRows + 2 * (rows - dsRows))
    to_hash[0] = message
    i = 0
    while i < cols:
        for j in range(dsRows):
            L = add_keys1(rv.ss[i][j], c_old, pk[i][j])
            Hi = crypto.hash_to_ec(pk[i][j])  # TODO: check, previously hashToPoint
            R = add_keys2(rv.ss[i][j], Hi, c_old, Ip[j])
            to_hash[3 * j + 1] = pk[i][j]
            to_hash[3 * j + 2] = L
            to_hash[3 * j + 3] = R

        ii = 0
        for j in range(dsRows, rows):
            L = add_keys1(rv.ss[i][j], c_old, pk[i][j])
            to_hash[nds_rows + 2 * ii + 1] = pk[i][j]
            to_hash[nds_rows + 2 * ii + 1] = L

        c = crypto.hash_to_scalar(to_hash)  # TODO: vector of bytes to hash
        c_old = c
        i += 1

    c = crypto.sc_sub(c_old, rv.cc)
    return c == 0











