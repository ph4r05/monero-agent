#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
#
# Limbs computation from: https://www.imperialviolet.org/2010/12/04/ecc.html
# Used to implement sub256_modm() - computation of 2xM, 4xM for modular reduction and underflow protection.
#

import math
from monero_glue.xmr import crypto


LIMBS = 9
LIMB_SIZE = 30

MASK = 2**LIMB_SIZE - 1


def sumlimb(limbs):
    res = 0
    for i in range(LIMBS):
        res += (2 ** (LIMB_SIZE * i)) * limbs[i]
    return res


def to_limbs(num):
    limbs = []
    for i in range(LIMBS):
        limbs.append(num & (2**LIMB_SIZE - 1))
        num >>= LIMB_SIZE
    return limbs


def print_limbs(limbs):
    res = 0
    for i in range(LIMBS):
        res += (2 ** (LIMB_SIZE * i)) * limbs[i]
        print('  %x %s' % (limbs[i], math.log(limbs[i], 2) if limbs[i] > 0 else '-'))
    print('Total: %s, below moduli: %s' % (res, res < crypto.l))


def limbs_consts(var=0, limbs_val=0, limbs=None, value=None):
    print('** Limbs var: %s val: %x' % (var, limbs_val))

    # Compute maximal reduced limb value for < top limb.
    # Top limb has specific (moduli).
    pbase = 2**LIMB_SIZE
    if var == 1:
        pbase = 2**(LIMB_SIZE + 1)
    if var == 2:
        pbase = 2**LIMB_SIZE + 2**(LIMB_SIZE + 1)

    if value is not None:
        limbs = to_limbs(value)
    else:
        limbs = [limbs_val] * LIMBS if not limbs else limbs
        value = sumlimb(limbs)

    sums = sumlimb(limbs)
    sumsmod = sums % crypto.l
    print('sum:    0x%x' % sums)
    print('summod: 0x%x' % sumsmod)

    # Top limb
    first = crypto.l >> (LIMB_SIZE * (LIMBS - 1))
    print('Top limb: 0x%x, bit-size: %s\n' % (first, math.log(first, 2)))

    over_idx = LIMBS * LIMB_SIZE
    leftover = pbase >> LIMB_SIZE
    final_leftover = leftover << over_idx

    # First limb is without leftover
    limbs[0] += pbase
    print('Pbase:            0x%x, log: %s' % (pbase, math.log(pbase, 2)))
    print('Leftover:         0x%x' % leftover)

    for i in range(1, LIMBS):
        if i < LIMBS - 1:
            limbs[i] += pbase - leftover
        else:
            # Trick to reduce number of modular reductions
            limbs[i] += first//2 - leftover
            final_leftover = (first//2) << (LIMB_SIZE*(LIMBS-1))
            # limbs[i] += first - leftover
            # final_leftover = (first) << (LIMB_SIZE*(LIMBS-1))

    print('Final_leftover:   0x%x' % final_leftover)

    left_moduled = final_leftover - crypto.l
    left_moduled = -left_moduled % crypto.l
    print('Test:             %s' % bool(final_leftover > crypto.l))
    print('Moduli:           0x%x' % crypto.l)
    print('Moduled leftover: 0x%x' % left_moduled)

    for i in range(LIMBS):
        limbs[i] += (left_moduled >> (i*LIMB_SIZE)) & ((2**LIMB_SIZE) - 1)

    # limbs print
    print('\nLimbs: ')
    print('[' + (', '.join(['0x%x' % x for x in limbs])) + ']\n')

    print('Limbs sizes: ')
    res = 0
    for i in range(LIMBS):
        res += (2**(LIMB_SIZE*i)) * limbs[i]
        print('  %x %s' % (limbs[i], math.log(limbs[i], 2)))

    print('Final value:     0x%x' % res)
    print('Final value mod: 0x%x' % (res % crypto.l))
    print('Final correct:   %s' % (res % crypto.l - sumsmod == 0))

    # collapse with carry
    print('\nLimbs with carry sum: ')
    c = 0
    res = 0
    for i in range(LIMBS):
        c += limbs[i]
        res += (2 ** (LIMB_SIZE * i)) * (c & MASK)
        c >>= LIMB_SIZE

        print('  %x %s c: %x' % (limbs[i], math.log(limbs[i], 2), c))

    print('')
    print('Final value:     0x%x' % res)
    print('Final value mod: 0x%x' % (res % crypto.l))
    print('Final value mul: 0x%x' % (res // crypto.l))  # number of modular reductions needed
    print('CORRECT: %s' % ((res % crypto.l) == value))
    print('-'*80)


limbs_consts(0, value=0)
limbs_consts(1, value=0)

print('='*80)
# limbs_consts(0, value=crypto.l-1)
# limbs_consts(1, value=crypto.l-1)

lmbs = [0x5cf5d3ed, 0x60498c68, 0x6f79cd64, 0x77be77a7, 0x40000013, 0x3fffffff, 0x3fffffff, 0x3fffffff, 0xfff]
limbs = [0x0fffffff, 0x0fffffff, 0x0fffffff, 0x0fffffff, 4, 0, 0, 0, 0x1000]

print_limbs(limbs)
limbs_consts(0, limbs=limbs)

print_limbs(to_limbs(crypto.l-1))


