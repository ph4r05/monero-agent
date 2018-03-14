#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2018

import Crypto.Random.random as rand
import logging

from monero_serialize import xmrtypes, xmrserialize
from . import crypto
from . import asnl
from . import mlsag2


logger = logging.getLogger(__name__)
ATOMS = 64


def ctkeyV(rows):
    return [xmrtypes.CtKey() for i in range(0, rows)]


class ecdhTuple(object):
    __slots__ = ['mask', 'amount', 'senderPk']


class asnlSig(object):
    __slots__ = ['L1', 's2', 's']


class mgSig(object):
    __slots__ = ['ss', 'cc', 'II']


class rctSig(object):
    __slots__ = ['rangeSigs', 'MG', 'mixRing', 'ecdhInfo', 'outPk']

    
def d2b(n, digits):
    b = [0] * digits
    i = 0
    while n:
        b[i] = n & 1
        i = i + 1
        n >>= 1
    return b 


def b2d(binArray):
    s = 0
    i = 0
    for a in binArray:
        s = s + a * 2 ** i   
        i+= 1
    return s


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


def prove_range(amount):
    """
    Gives C, and mask such that \sumCi = C
    c.f. http:#eprint.iacr.org/2015/1098 section 5.1

    Ci is a commitment to either 0 or 2^i, i=0,...,63
    thus this proves that "amount" is in [0, 2^ATOMS]
    mask is a such that C = aG + bH, and b = amount
    :param amount:
    :return: sumCi, mask, RangeSig
    """
    bb = d2b(amount, ATOMS)  # gives binary form of bb in "digits" binary digits
    logger.info("amount, amount in binary %s %s" % (amount, bb))
    ai = [None] * len(bb)
    Ci = [None] * len(bb)
    CiH = [None] * len(bb)  # this is like Ci - 2^i H
    H2 = crypto.gen_Hpow(ATOMS)
    a = 0
    ii = [None] * len(bb)
    indi = [None] * len(bb)
    for i in range(0, ATOMS):
        ai[i] = crypto.random_scalar()
        a = crypto.sc_add(a, ai[i])  # creating the total mask since you have to pass this to receiver...
        if bb[i] == 0:
            Ci[i] = crypto.scalarmult_base(ai[i])
        if bb[i] == 1:
            Ci[i] = crypto.point_add(crypto.scalarmult_base(ai[i]), H2[i])
        CiH[i] = crypto.point_sub(Ci[i], H2[i])
        
    A = asnlSig()
    A.L1, A.s2, A.s = asnl.gen_asnl(ai, Ci, CiH, bb)
    
    R = xmrtypes.RangeSig()
    R.asig = A
    R.Ci = Ci
    
    mask = a
    C = sum_Ci(Ci)
    return C, mask, R


def ver_range(Ci, ags):
    """
    Verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    :param Ci:
    :param ags:
    :return:
    """
    n = ATOMS
    CiH = [None] * n
    C_tmp = crypto.identity()
    H2 = crypto.gen_Hpow(ATOMS)
    for i in range(0, n):
        CiH[i] = crypto.point_sub(ags.Ci[i], H2[i])
        C_tmp = crypto.point_add(C_tmp, ags.Ci[i])

    if not crypto.point_eq(C_tmp, Ci):
        return 0

    return asnl.ver_asnl(ags.Ci, CiH, ags.asig.L1, ags.asig.s2, ags.asig.s)


# Ring-ct MG sigs
# Prove:
#   c.f. http:#eprint.iacr.org/2015/1098 section 4. definition 10. 
#   This does the MG sig on the "dest" part of the given key matrix, and 
#   the last row is the sum of input commitments from that column - sum output commitments
#   this shows that sum inputs = sum outputs
# Ver:
#   verifies the above sig is created corretly


def prove_rct_mg(pubs, inSk, outSk, outPk, index):
    """
    c.f. http:#eprint.iacr.org/2015/1098 section 4. definition 10.

    :param pubs: matrix of ctkeys [P, C]
    :param inSk: keyvector of [x, mask] secret keys
    :param outSk: keyvector of masks for outputs
    :param outPk: list of output ctkeys [P, C]
    :param index: secret index of where you are signing (integer)
    :return: list (mgsig) [ss, cc, II] where ss is keymatrix, cc is key, II is keyVector of keyimages
    """

    # So we are calling MLSAG2.MLSAG_Gen from here, we need a keymatrix made from pubs
    # We also need a keyvector made from inSk

    rows = len(pubs[0])
    cols = len(pubs)
    M = mlsag2.key_matrix(rows + 1, cols) # just a simple way to initialize a keymatrix, doesn't need to be random.
    sk = mlsag2.key_vector(rows + 1)
    
    for j in range(0, cols):
        M[j][rows] = crypto.identity()
    sk[rows] = 0

    for i in range(0, rows): 
        sk[i] = inSk[i].dest  # get the destination part
        sk[rows] = crypto.sc_add(sk[rows], inSk[i].mask)  # add commitment part
        for j in range(0, cols):
            M[j][i] = pubs[j][i].dest  # get the destination part
            M[j][rows] = crypto.point_add(M[j][rows], pubs[j][i].mask)  # add commitment part

    # next need to subtract the commitment part of all outputs..
    for j in range(0, len(outSk)):
        sk[rows] = crypto.sc_sub(sk[rows], outSk[j].mask)
        for i in range(0, len(outPk)):
            M[j][rows] = crypto.point_sub(M[j][rows], outPk[i].mask)  # subtract commitment part

    MG = mgSig()
    MG.II, MG.cc, MG.ss = mlsag2.gen_mlsag(M, sk, index)
    
    return MG  # mgSig


def verify_rct_mg(MG, pubs, outPk):
    """
    Verifies MG
    :param MG: an mgsig (list [ss, cc, II] of keymatrix ss, keyvector II and key cc]
    :param pubs: matrix of ctkeys [P, C]
    :param outPk: list of output ctkeys [P, C] for the transaction
    :return: true or false
    """
    rows = len(pubs[0])
    cols = len(pubs)
    M = mlsag2.key_matrix(rows + 1, cols)  # just a simple way to initialize a keymatrix, doesn't need to be random..
    for j in range(0, cols):
        M[j][rows] = crypto.identity()

    for i in range(0, rows): 
        for j in range(0, cols):
            M[j][i] = pubs[j][i].dest  # get the destination part
            M[j][rows] = crypto.point_add(M[j][rows], pubs[j][i].mask)  # add commitment part

    # next need to subtract the commitment part of all outputs..
    for j in range(0, cols):
        for i in range(0, len(outPk)):
            M[j][rows] = crypto.point_sub(M[j][rows], outPk[i].mask)  # subtract commitment part
    return mlsag2.ver_mlsag(M, MG.II, MG.cc, MG.ss)


def getKeyFromBlockchain(reference_index):
    """
    Returns a ctkey a (randomly)
    :param reference_index:
    :return:
    """
    rv = xmrtypes.CtKey()
    rv.dest = crypto.public_key(crypto.random_scalar())
    rv.mask = crypto.public_key(crypto.random_scalar())
    return rv


def populateFromBlockchain(inPk, mixin):
    """
    Returns a ckKeyMatrix with your public input keys at "index" which is the second returned parameter.
    The returned ctkeyMatrix will have number of columns = mixin
    :param inPk:
    :param mixin:
    :return:
    """
    rv = [None] * mixin
    index = rand.getrandbits(mixin - 1)
    blockchainsize = 10000
    for j in range(0, mixin):
        if j != index:
            rv[j] = [getKeyFromBlockchain(rand.getrandbits(blockchainsize)) for i in range(0, len(inPk))]
        else: 
            rv[j] = inPk
    return rv, index
    

def ecdh_encode(unmasked, receiver_pk=None, derivation=None):
    """
    Elliptic Curve Diffie-Helman: encodes and decodes the amount b and mask a
    where C= aG + bH
    :param unmasked:
    :param receiver_pk:
    :param derivation:
    :return:
    """
    rv = xmrtypes.EcdhTuple()
    if derivation is None:
        esk = crypto.random_scalar()
        rv.senderPk = crypto.scalarmult_base(esk)
        derivation = crypto.encodepoint(crypto.scalarmult(receiver_pk, esk))

    sharedSec1 = crypto.hash_to_scalar(derivation)
    sharedSec2 = crypto.hash_to_scalar(crypto.encodeint(sharedSec1))

    rv.mask = crypto.sc_add(unmasked.mask, sharedSec1)
    rv.amount = crypto.sc_add(unmasked.amount, sharedSec2)
    return rv

    
def ecdh_decode(masked, receiver_sk=None, derivation=None):
    """
    Elliptic Curve Diffie-Helman: encodes and decodes the amount b and mask a
    where C= aG + bH
    :param masked:
    :param receiver_sk:
    :param derivation:
    :return:
    """
    rv = xmrtypes.EcdhTuple()

    if derivation is None:
        derivation = crypto.scalarmult(masked.senderPk, receiver_sk)

    sharedSec1 = crypto.hash_to_scalar(derivation)
    sharedSec2 = crypto.hash_to_scalar(crypto.encodeint(sharedSec1))

    rv.mask = crypto.sc_sub(masked.mask, sharedSec1)
    rv.amount = crypto.sc_sub(masked.amount, sharedSec2)
    return rv

#
# RingCT protocol
#


def gen_rct(inSk, inPk, destinations, amounts, mixin):
    """
    RingCT
    Creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
    columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
    Also contains masked "amount" and "mask" so the receiver can see how much they received

    Outputs:
        - rangesigs is a list of one rangeproof for each output
        - MG is the mgsig [ss, cc, II]
        - mixRing is a ctkeyMatrix
        - ecdhInfo is a list of masks / amounts for each output
        - outPk is a vector of ctkeys (since we have computed the commitment for each amount)
    :param inSk:  signers secret ctkeyvector
    :param inPk:  signers public ctkeyvector
    :param destinations: keyvector of output addresses
    :param amounts: list of amounts corresponding to above output addresses
    :param mixin: an integer which is the desired mixin
    :return: [rangesigs, MG, mixRing, ecdhInfo, outPk]
    """
    rv = rctSig()
    rv.outPk = ctkeyV(len(destinations))
    rv.rangeSigs = [None] * len(destinations)
    outSk = ctkeyV(len(destinations))
    rv.ecdhInfo = [None] * len(destinations)
    for i in range(0, len(destinations)):
        rv.ecdhInfo[i] = xmrtypes.EcdhTuple()
        rv.outPk[i] = xmrtypes.CtKey()
        rv.outPk[i].dest = destinations[i]
        rv.outPk[i].mask, outSk[i].mask, rv.rangeSigs[i] = prove_range(amounts[i])
        #do ecdhinfo encode / decode 
        rv.ecdhInfo[i].mask = outSk[i].mask
        rv.ecdhInfo[i].amount = crypto.encodeint(amounts[i])
        rv.ecdhInfo[i] = ecdh_encode(rv.ecdhInfo[i], destinations[i])
    rv.mixRing, index = populateFromBlockchain(inPk, mixin)
    rv.MG = prove_rct_mg(rv.mixRing, inSk, outSk, rv.outPk, index)
    return rv

            
def ver_rct(rv):
    """
    Verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct

    Inputs:
        - rangesigs is a list of one rangeproof for each output
        - MG is the mgsig [ss, cc, II]
        - mixRing is a ctkeyMatrix
        - ecdhInfo is a list of masks / amounts for each output
        - outPk is a vector of ctkeys (since we have computed the commitment for each amount)
    :param rv: [rangesigs, MG, mixRing, ecdhInfo, outPk]
    :return: true / false
    """
    rvb = True 
    tmp = True 
    for i in range(0, len(rv.outPk)): 
        tmp = ver_range(rv.outPk[i].mask, rv.rangeSigs[i])
        rvb = rvb and tmp
    mgVerd = verify_rct_mg(rv.MG, rv.mixRing, rv.outPk)
    return rvb and mgVerd


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
    H = crypto.gen_H()
    Ctmp = crypto.point_add(crypto.scalarmult_base(mask), crypto.scalarmult(H, amount))
    if not crypto.point_eq(crypto.point_sub(C, Ctmp), crypto.identity()):
        logger.warning("warning, amount decoded incorrectly, will be unable to spend")
    return amount

