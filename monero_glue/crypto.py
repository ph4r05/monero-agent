#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hashlib  # for signatures
import math
from Crypto.Random import random as rand
from mnero import Keccak  # cn_fast_hash
from mnero import mnemonic  # making 25 word mnemonic to remember your keys
import binascii  # conversion between hex, int, and binary. Also for the crc32 thing
from mnero import ed25519  # Bernsteins python ed25519 code from cr.yp.to
from mnero import ed25519ietf  # https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-02
import zlib
import struct

from mnero.mininero import b, q, l, public_key, scalarmult_simple

from mnero import mininero, keccak2
from monero_serialize import xmrtypes, xmrserialize
from . import common as common


def cn_fast_hash(buff):
    kc2 = keccak2.Keccak256()
    kc2.update(buff)
    return kc2.digest()


def b2d(arr):
    s = 0
    i = 0
    for a in arr:
        s = s + a * 2 ** i
        i += 1
    return s


def random_scalar():
    tmp = rand.getrandbits(64 * 8)  # 8 bits to a byte ...
    tmp = sc_reduce(tmp)  # -> turns 64 to 32 (note sure why don't just gt 32 in first place ... )
    return tmp


def hash_to_scalar(data, length=None):
    #this one is H_s(P)
    #relies on cn_fast_hash and sc_reduce32 (which makes an int smaller)
    #the input here is not necessarily a 64 byte thing, and that's why sc_reduce32
    # res = mininero.hexToInt(mininero.cn_fast_hash(binascii.hexlify(data[:length] if length else data)))
    res = b2d(cn_fast_hash(data[:length] if length else data))
    return sc_reduce32(res)


def sc_check(key):
    #in other words, keys which are too small are rejected
    return 0


def check_ed25519point(P):
    """
    Simple check if the point has exactly 2 coordinates
    :param P:
    :return:
    """
    if not isinstance(P, (list, tuple)) or len(P) != 2:
        raise ValueError('P is not a ed25519 point')
    if not ed25519.isoncurve(P):
        raise ValueError('P is not on ed25519 curve')


def ge_scalarmult(a, A):
    #so I guess given any point A, and an integer a, this computes aA
    #so the seecond arguement is definitely an EC point
    # from http://cr.yp.to/highspeed/naclcrypto-20090310.pdf
    # "Alice's secret key a is a uniform random 32-byte string then
    #clampC(a) is a uniform random Curve25519 secret key
    #i.e. n, where n/8 is a uniform random integer between
    #2^251 and 2^252-1
    #Alice's public key is n/Q compressed to the x-coordinate
    #so that means, ge_scalarmult is not actually doing scalar mult
    #clamping makes the secret be between 2^251 and 2^252
    #and should really be done
    #print(toPoint(A))
    check_ed25519point(A)
    return ed25519.scalarmult(A, a)


def ge_mul8(P):
    #ok, the point of this is to double three times
    #and the point is that the ge_p2_dbl returns a point in the p1p1 form
    #so that's why have to convert it first and then double
    return ge_scalarmult(8, P)


def sc_reduce(s):
    #inputs a 64 byte int and outputs the lowest 32 bytes
    #used by hash_to_scalar, which turns cn_fast_hash to number..
    r = mininero.intToHex(s)
    r = r[64::]
    return mininero.hexToInt(r) % l


def sc_reduce32(data):
    #ok, the code here is exactly the same as sc_reduce
    #(which is default lib sodium)
    #except it is assumed that your input
    #s is alread in the form:
    # s[0]+256*s[1]+...+256^31*s[31] = s
    #and the rest is just reducing mod l
    #so basically take a 32 byte input, and reduce modulo the prime
    return data % l


def ge_scalarmult_base(a):
    #in this function in the original code, they've assumed it's already clamped ...
    #c.f. also https://godoc.org/github.com/agl/ed25519/edwards25519
    #it will return h = a*B, where B is ed25519 bp (x,4/5)
    #and a = a[0] + 256a[1] + ... + 256^31 a[31]
    #it assumes that a[31 <= 127 already
    return ed25519.scalarmultbase(8*a)
    #return ge_scalarmult(8*a, BASEPOINT)


def ge_frombytes_vartime(key):
    #https://www.imperialviolet.org/2013/12/25/elligator.html
    #basically it takes some bytes of data
    #converts to a point on the edwards curve
    #if the bytes aren't on the curve
    #also does some checking on the numbers
    #ex. your secret key has to be at least >=4294967277
    #also it rejects certain curve points, i.e. "if x = 0, sign must be positive
    return 0


def generate_key_derivation(key1, key2):
    # key1 is public key of receiver Bob (see page 7)
    # key2 is Alice's private
    # this is a helper function for the key-derivation
    # which is the generating one-time key's thingy
    if sc_check(key2) != 0:
        # checks that the secret key is uniform enough...
        raise ValueError("error in sc_check in keyder")
    if ge_frombytes_vartime(key1) != 0:
        raise ValueError("didn't pass curve checks in keyder")

    point = key1  ## this ones the public
    point2 = ge_scalarmult(key2, point)
    # print("p2", encodepoint(point2).encode("hex"))
    point3 = ge_mul8(point2)  # This has to do with n==0 mod 8 by dedfinition, c.f. the top paragraph of page 5 of http://cr.yp.to/ecdh/curve25519-20060209.pdf
    # and also c.f. middle of page 8 in same document (Bernstein)
    return point3


def derivation_to_scalar(derivation, output_index):
    # this function specifically hashes your
    # output index (for the one time keys )
    # in order to get an int, so we can do ge_mult_scalar
    # buf = s_comm(d = derivation, o = output_index)
    check_ed25519point(derivation)
    buf2 = struct.pack('64sl', ed25519.encodepoint(derivation), output_index)
    return hash_to_scalar(buf2, len(buf2))


def derive_public_key(derivation, output_index, base):
    if ge_frombytes_vartime(base) != 0: #check some conditions on the point
        raise ValueError("derive pub key bad point")
    check_ed25519point(base)

    point1 = base
    scalar = derivation_to_scalar(derivation, output_index)
    point2 = ge_scalarmult_base(scalar)
    point3 = point2 #I think the cached is just for the sake of adding
    #because the CN code adds using the monty curve
    point4 = ed25519.edwards(point1, point3)
    return point4


def sc_add(aa, bb):
    return (aa + bb ) % l


def sc_sub(aa, bb):
    return (aa - bb ) % l


def sc_isnonzero(c):
    return (c % l != 0)


def sc_mulsub(aa, bb, cc):
    return (cc - aa * bb ) % l


def derive_secret_key(derivation, output_index, base):
    # outputs a derived key...
    if sc_check(base) !=0:
        raise ValueError("cs_check in derive_secret_key")
    scalar = derivation_to_scalar(derivation, output_index)
    return base + scalar


def hash_to_ec(key):
    #takes a hash and turns into a point on the curve
    #In MININERO, I'm not using the byte representation
    #So this function is superfluous
    h = hash_to_scalar(key, len(key))
    point = ge_scalarmult_base(h)
    return ge_mul8(point)


def generate_key_image(public_key, secret_key):
    # should return a key image as defined in whitepaper
    if sc_check(secret_key) != 0:
        raise ValueError("sc check error in key image")
    point = hash_to_ec(public_key)
    point2 = ge_scalarmult(secret_key, point)
    return point2


def derive_subaddress_public_key(out_key, derivation, output_index):
    check_ed25519point(out_key)
    scalar = derivation_to_scalar(derivation, output_index)
    point2 = ge_scalarmult_base(scalar)
    point4 = ed25519.edwards_Minus(out_key, point2)
    return point4




