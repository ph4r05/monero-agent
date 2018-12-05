#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018
# see https://eprint.iacr.org/2015/1098.pdf

import logging

from monero_glue.xmr import common, crypto
from monero_serialize import xmrtypes

logger = logging.getLogger(__name__)


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

    m = "".join(pk[0])
    for i in range(1, cols):
        m = m + "".join(pk[i])

    L[index] = [crypto.scalarmult_base(aa) for aa in alpha]  # L = aG
    Hi = hash_key_vector(pk[index])
    R[index] = [crypto.scalarmult(Hi[ii], alpha[ii]) for ii in range(0, rows)]  # R = aI

    oldi = index
    i = (index + 1) % cols
    c[i] = crypto.cn_fast_hash(m + "".join(L[oldi]) + "".join(R[oldi]))

    while i != index:
        s[i] = scalar_gen_vector(rows)
        L[i] = [crypto.add_keys2(s[i][j], c[i], pk[i][j]) for j in range(0, rows)]

        Hi = hash_key_vector(pk[i])
        R[i] = [crypto.add_keys3(s[i][j], Hi[j], c[i], I[j]) for j in range(0, rows)]
        oldi = i
        i = (i + 1) % cols
        c[i] = crypto.cn_fast_hash(m + "".join(L[oldi]) + "".join(R[oldi]))

    s[index] = [
        crypto.sc_mulsub(c[index], xx[j], alpha[j]) for j in range(0, rows)
    ]  # alpha - c * x
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

    m = "".join(pk[0])
    for i in range(1, cols):
        m = m + "".join(pk[i])

    i = 0
    while i < cols:
        L[i] = [crypto.add_keys2(s[i][j], c[i], pk[i][j]) for j in range(0, rows)]

        Hi = hash_key_vector(pk[i])
        R[i] = [crypto.add_keys3(s[i][j], Hi[j], c[i], I[j]) for j in range(0, rows)]

        oldi = i
        i = i + 1
        c[i] = crypto.cn_fast_hash(m + "".join(L[oldi]) + "".join(R[oldi]))

    return c0 == c[cols]

