#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018
#
# Adapted from Monero C++ code
# Faster exponentiation uses Pippenger algorithm: https://cr.yp.to/papers/pippenger.pdf
#
#

from monero_glue.compat import gc, log
from monero_glue.compat.utils import memcpy as _memcpy
from monero_glue.xmr import crypto
from monero_serialize.core.int_serialize import dump_uvarint_b_into, uvarint_size
from monero_serialize.xmrtypes import Bulletproof
import binascii

# Constants

_BP_LOG_N = 6
_BP_N = 1 << _BP_LOG_N  # 64
_BP_M = 16  # maximal number of bulletproofs

_ZERO = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
_ONE = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
_TWO = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
_EIGHT = b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
_INV_EIGHT = b"\x79\x2f\xdc\xe2\x29\xe5\x06\x61\xd0\xda\x1c\x7d\xb3\x9d\xd3\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06"
_MINUS_ONE = b"\xec\xd3\xf5\x5c\x1a\x63\x12\x58\xd6\x9c\xf7\xa2\xde\xf9\xde\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10"
_MINUS_INV_EIGHT = b"\x74\xa4\x19\x7a\xf0\x7d\x0b\xf7\x05\xc2\xda\x25\x2b\x5c\x0b\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0a"

# Monero H point
_XMR_H = b"\x8b\x65\x59\x70\x15\x37\x99\xaf\x2a\xea\xdc\x9f\xf1\xad\xd0\xea\x6c\x72\x51\xd5\x41\x54\xcf\xa9\x2c\x17\x3a\x0d\xd3\x9c\x1f\x94"
_XMR_HP = crypto.xmr_H()

# get_exponent(Gi[i], XMR_H, i * 2 + 1)
_BP_GI_PRE = b"\x0b\x48\xbe\x50\xe4\x9c\xad\x13\xfb\x3e\x01\x4f\x3f\xa7\xd6\x8b\xac\xa7\xc8\xa9\x10\x83\xdc\x9c\x59\xb3\x79\xaa\xab\x21\x8f\x15\xdf\x01\xa5\xd6\x3b\x3e\x3a\x38\x38\x2a\xfb\xd7\xbc\x68\x5f\x34\x3d\x61\x92\xda\x16\xed\x4b\x45\x1f\x15\xfd\xda\xb1\x70\xe2\x2d\x73\x69\xc8\xd5\xa7\x45\x42\x3d\x26\x06\x23\xa1\xf7\x5f\xae\x1f\xb1\xf8\x1b\x16\x9d\x42\x2a\xcd\x85\x58\xe9\xd5\x74\x25\x48\xbd\x81\xc0\x7d\x2b\xd8\x77\x1e\xb4\xbd\x84\x15\x5d\x38\xd7\x05\x31\xfe\x66\x2b\x78\xf0\xc4\x4a\x9a\xea\xea\x2e\xd2\xd6\xf0\xeb\xe1\x08\x96\xc5\xc2\x2f\x00\x70\xeb\xf0\x55\xdf\xe8\xdc\x1c\xb2\x05\x42\xef\x29\x15\x1a\xa0\x77\x1e\x58\x1e\x68\xfe\x78\x18\xef\x42\x35\xc8\xdf\x1a\x32\xae\xce\xed\xef\xcb\xdf\x6d\x91\xd5\x24\x92\x9b\x84\x02\xa0\x26\xcb\x85\x74\xe0\xe3\xa3\x34\x2c\xe2\x11\xbc\xd9\x67\xbc\x14\xe7\xab\xda\x6c\x17\xc2\xf2\x2a\x38\x1b\x84\xc2\x49\x75\x78\x52\xe9\x9d\x62\xc4\x5f\x16\x0e\x89\x15\xec\x21\xd4\xc8\xa3\x83\x1d\x7c\x2f\x24\x58\x1e\xc9\xd1\x50\x13\xdf\xcc\xb5\xeb\xa6\x9d\xf6\x91\xa0\x80\x02\xb3\x3d\x4f\x2f\xb0\x6c\xa9\xf2\x9c\xfb\xc7\x0d\xb0\x23\xa4\x8e\x45\x35\xf5\x83\x8f\x5e\xa2\x7f\x70\x98\x0d\x11\xec\xd9\x35\xb4\x78\x25\x8e\x2a\x4f\x10\x06\xb3\x2d\xa6\x38\x72\x92\x25\x9e\x69\xac\x0a\x82\x9e\xf3\x47\x69\x98\x96\x72\x8c\x0c\xc0\xca\xdc\x74\x6d\xae\x46\xfb\x31\x86\x4a\x59\xa5\xb9\xa1\x54\x9c\x77\xe4\xcf\x8a\xb8\xb2\x55\xa3\xa0\xae\xfa\xa4\xca\xd1\x25\xd2\x19\x94\x9c\x0a\xef\xf0\xc3\x56\x0a\xb1\x58\xed\x67\x17\x48\xa1\x75\x56\x41\x9e\xc9\x42\xe1\x6b\x90\x1d\xbb\x2f\xc6\xdf\x96\x60\x32\x4f\xcb\xcd\x6e\x40\xf2\x35\xd7\x5b\x76\x4f\xaf\xf6\x1c\x19\x05\x22\x2b\xaf\x87\xd5\x1d\x45\xf3\x55\x81\x38\xc8\x7c\xe5\x4c\x46\x4c\xc6\x40\xb9\x55\xe7\xfa\x33\x10\xf8\x3b\x13\xdd\x7b\x24\x73\x19\xe1\x3c\xe6\x19\x95\xbc\x77\x1e\xe1\xed\xe7\x36\x35\x99\xf0\x8f\xc5\xcf\xda\x89\x0e\xa8\x03\xe0\xec\xa7\x0a\x97\x70\x7e\x90\x56\x29\xa5\xe0\x6d\x18\x6a\x96\x4f\x32\x2f\xff\xba\xa7\xed\x2e\x78\x1d\x4d\x3f\xed\xe0\x74\x61\xf4\x4b\x2d\x98\xdb\xcc\x0c\xaa\x20\x55\x14\x6e\x13\xf5\x0e\xcf\x75\x49\x1d\xad\xd3\x6a\xd2\xba\xac\x56\xbc\x08\x56\x2e\xc6\x6c\xe1\x10\xb5\x44\x83\x1d\xbd\x34\xc6\xc2\x52\x95\x81\x51\xc4\x9a\x73\x4c\x6e\x62\x5e\x42\x60\x8c\x00\x5e\x79\x7e\xdb\x6d\x0a\x89\x34\xb3\x24\xa0\xe4\xd3\x1c\xba\x01\x57\x83\x50\x1e\xcd\xfa\x7a\x8e\xba\xe3\xa6\xbf\xd3\x2e\x6d\x1a\x36\x14\xb1\x11\x83\xc8\x09\x80\xd4\x54\x6c\xc3\xee\x5d\xb4\x7b\xfe\x97\x05\xaa\x95\xe2\xda\x29\xf2\x28\x23\x03\x53\x91\x7e\x5d\x2b\x19\x32\xfe\x48\x2f\xbc\xfe\xd7\x13\x4d\x55\x6d\x0c\x27\xf6\xcc\x6b\xf3\x01\x5c\x06\x61\x16\x25\x73\x9d\x88\x9c\x57\x89\xfa\x75\xb3\xc8\x39\x69\xcb\x88\xb1\xdf\x01\xc0\xac\xa4\x70\xf6\x65\xeb\x71\x82\xe0\x72\xbc\xa8\x9b\xc6\x69\xff\xe5\xb0\x29\x6f\xe2\x13\x43\xa8\xc3\x27\xc8\xa8\x41\x75\x02\x85\x5a\x25\xcc\xb7\x5b\x2f\x8e\xea\xc5\xd1\xdb\x25\x04\x4b\x0a\xea\xd2\xcf\x77\x02\x1e\xd9\x4f\x79\xf3\x00\x1e\x7b\x8e\x9d\xb7\x31\x1d\xb2\x8c\x45\xc9\x0d\x80\xa1\xe3\xd5\xb2\x7b\x43\xf8\xe3\x80\x21\x4d\x6a\x2c\x40\x46\xc8\xd4\x0f\x52\x4d\x47\x83\x53\x20\x4d\x01\xa1\x7c\x4f\xb7\xb1\x8c\x2f\x48\x27\x01\x50\xdb\x67\xd4\xb0\xb9\xce\x87\x86\xe0\x3c\x95\x50\xc5\x47\xfb\x18\x02\x9e\xf1\x6e\x56\x29\xe9\xa1\xc6\x68\xe1\xaa\x79\xc7\x88\x73\x55\xf5\xf5\x1b\x0c\xbb\x1f\x08\x35\xe0\x4e\x7a\xcc\x53\xac\x55\xa3\x57\x41\x97\xb5\x4c\x5a\xaa\xad\x47\xbe\x24\xdb\xbc\x11\xc1\xbd\x3e\xeb\x62\x46\x54\x2d\x2f\x5a\xe5\xf4\x39\x8d\xd4\xa7\x60\x17\x03\xcb\xbf\xd5\x9b\xad\xdd\x3a\x7c\xe6\xe3\x75\xe7\xd9\x00\x50\xe2\x71\xb1\x3f\x13\x2d\xf8\x5e\x1c\x12\xbe\x54\xfe\x66\xde\x81\xf6\x8a\x1c\x8f\x69\x6f\x3e\x77\x3c\x7e\xef\x57\xac\x13\x89\xbd\x02\x80\xd5\x58\xea\x78\x62\xf0\x1b\x64\x1e\xc6\xda\x0e\xfe\xfb\xee\xd0\x50\x9c\x53\x8a\x8c\x36\x16\x68\x1d\x76\x1a\xe5\xc6\xf9\xd2\xaa\xde\xd7\x18\x90\xda\x24\x96\x15\x60\x43\x08\x21\x82\xec\x85\x9c\x3a\xe4\x86\x93\xf9\x13\x43\xd0\xa5\xf0\xec\xbb\x7d\xec\x9b\x97\x3b\xf2\x13\x67\x8a\x65\x3b\x0d\x9d\xf5\x10\x65\x2a\x23\xc0\xb8\x06\x53\x67\x92\x4a\x4c\xfc\x78\x60\x36\xc0\x66\xca\xa7\x38\x34\x9c\xf1\xcd\xa7\x0d\xbf\xa8\x5c\xce\xb4\xa0\x9f\x85\x03\x9b\x6f\x77\x27\x4f\xa6\xe2\x79\x35\xbf\x89\xae\x37\x3a\x3b\x5a\xda\x58\x24\xbd\x4b\x2a\xec\x22\x2a\xeb\xd7\xfe\xe7\xa4\x82\xe9\xc1\x33\x58\xea\xb2\x5f\x94\x22\x36\xf3\xf4\xb6\xeb\xaf\xe1\xc3\xee\xee\xf7\x93\x83\x66\x80\x66\x7c\x66\x94\x64\xc3\xd4\xa0\x84\x7d\xf3\x02\x4b\xd5\xdf\x2a\xa4\xaa\x4d\x19\xe5\x51\xed\xe9\x3d\xd0\x75\xf7\x95\x3a\xca\xe5\x3f\x0f\x9e\x8a\x38\x4e\x49\x6c\x52\x50\xb0\x7e\x76\x17\xe8\x9e\x28\xf9\x53\xd0\x96\xec\x29\x87\xeb\xd8\xf3\xe7\x4d\x93\x39\x63\xb8\x27\x73\xd3\x7a\xb1\xb7\xa3\x60\x1d\xc8\x97\x13\x34\x82\x5d\xd1\xd6\x7e\x4c\x48\x29\x72\x92\xa0\x7a\x40\x62\x96\x75\xb3\xe8\x78\x8e\xfc\x68\x73\x85\x30\x04\x81\xae\x69\x74\x06\xd2\x4e\xf8\x8e\xbf\x9c\xa1\x97\x2c\x1d\x52\x84\x78\x85\x8e\xad\x85\x78\x2e\xd4\x10\xeb\xbc\x1f\x3d\xa4\x8b\xa8\x07\x83\x62\x36\xaa\xc0\xa8\xf0\x8a\x50\x29\x11\x5d\x57\xe7\xef\x18\xcb\x27\xcc\xe8\xd2\xc1\x57\xa9\xf4\xf5\x61\x5d\xcc\x34\x8a\xea\xc8\x0d\x0f\x28\xdf\x33\xba\xbe\x39\xf6\xec\xbd\x19\xa4\xa6\xaf\xa8\x53\xaa\x4d\xa0\x3b\x6b\xd7\xa8\x06\x22\x9d\xed\x76\xd2\xc5\xb9\xde\x11\x76\xd5\x19\xa7\x93\x94\x67\x92\xb5\x41\x7e\xaf\x7d\x2d\x51\x26\x97\x7c\x57\x04\xfc\x0f\xcd\x8e\x1b\x2f\x58\x9b\x1d\x41\x8d\x19\xdd\x28\xf7\xe9\x4c\x51\xa1\x78\x2d\x32\x2e\x03\xcb\xa4\x78\x85\x74\x24\x49\x7b\x4a\x37\x3f\xde\x0f\xba\xe4\xcc\xd9\x38\xcb\xbf\xa0\xf4\xad\x23\x97\xee\xd7\xf7\x6d\xc3\xcd\xb6\xb0\x6a\x36\x66\x0c\x07\x75\xd3\x91\xca\x47\x21\x33\x41\xf6\x59\xe9\x01\x4f\x70\x28\x4e\xfa\xa5\xfa\xab\xa4\xbb\x83\x79\xce\x02\x04\xf5\xae\xdc\x28\x26\x8d\x82\x43\x8b\x5b\x88\x1f\xdf\x2d\xee\x4a\xd7\xd4\x0e\xd1\x3d\xad\x57\xca\x92\x96\x14\xa6\x3a\x00\xfe\x3a\x78\xf3\x3b\x30\xb6\xfd\x5f\x39\xe4\x43\x70\x36\xdc\xed\x8d\x87\xaf\x43\x28\x2f\x43\xfa\x14\xab\xaf\x6c\x84\x15\xfc\x05\xee\x1a\xd1\x71\xd8\x1f\xaa\x46\x7d\xdf\xe5\xe0\x2e\xb6\x89\x5e\x56\x88\xde\xc0\x48\xf6\x66\x0e\x3a\x2f\xd8\xbd\xec\x60\x2a\xf5\x95\x90\xec\x4c\x6e\xab\x83\x4c\xc0\xde\xc8\x62\x1e\xb5\x10\xfb\xa6\xf7\xad\xf4\x76\x93\xc2\xfd\x57\x4d\x82\x20\xa2\xe7\x0e\x73\xad\x68\xe4\xc3\x32\x48\x8e\xb8\xe7\x31\xfe\x60\x0d\x1e\x9f\x6b\x8f\x5c\xbf\x69\x9c\x18\xd0\x6b\xcd\x73\xb7\xcf\xce\xf4\x2e\x68\xaf\x7a\xe6\x7f\xea\x46\xe9\x46\xde\x6a\x61\xfa\xa4\x2c\x53\x5c\xfc\xae\xaa\xd5\x33\x4f\xc1\xa9\xba\xd4\xa5\x3e\x57\xd1\x1c\x6a\xcc\xfc\xef\xd2\xe8\xab\x44\xcb\x12\xfb\x2e\x66\x4f\xcb\xdf\x5c\x82\xb2\x12\x89\x62\x6a\xc2\xa1\x40\x2b\xde\x7a\x86\x9e\xb9\xed\x78\x07\x33\x8d\xd3\xb2\xba\x82\x37\x84\x5d\xb9\x67\x71\xcc\x98\x80\x08\x1a\xcf\x05\x3d\x9b\xd5\x1c\x01\x01\x94\x1c\x4c\x26\xf6\x6a\xa5\xdb\xad\x3f\x53\x54\x60\x85\x77\xf9\xe5\x1a\xfe\x74\x3a\xdd\x50\xf1\xb5\x90\x1b\xea\x7b\xeb\x5a\xe7\x80\xb6\xec\xe9\x77\xf6\x5b\x9c\x62\x8e\x1d\xce\x0a\xd1\xe0\x78\xc7\x46\xc2\xf3\x8d\x0e\x7f\x06\xb0\x88\x70\x8a\xe9\xac\x11\x17\xe3\xa3\x79\x99\xc1\xd7\x5a\x62\xe9\xc9\xe0\x17\x01\x8e\x08\x8a\xeb\xfb\x37\x8d\xe2\x9c\x78\x93\xac\xf1\x09\x42\x58\x4b\xf5\x58\xa2\xd0\x2d\x75\x1e\x34\xf3\xf4\x84\xb0\x01\xe3\x19\x24\xcc\x21\x84\x8b\xf0\xdd\xaf\x1f\x3d\x8a\x31\x00\x49\x73\x6f\xf7\xf0\x49\x29\x4d\x8a\x59\x5f\x2c\xa7\x26\x3a\x36\x13\x84\x0c\x14\xb3\x3e\xf4\x83\xcd\xca\x5b\xbb\x8a\x4c\x70\x04\xcc\xb8\xf6\x71\x56\x26\x7e\xe3\x5f\x28\x0d\xb1\x26\x45\xde\x8e\x55\x2a\x93\x12\xdf\x57\x69\xa0\x30\xa6\xb4\x6d\x80\xdb\x2e\x6c\x06\xb3\xc7\x6c\x1a\xda\x42\x37\x3b\x29\xa0\x59\x1f\x39\x85\x67\x49\xdf\xdf\xb2\x66\x81\x16\x6a\x28\x6f\xb4\xf2\x09\x7a\x3b\x6f\x8f\xeb\xdb\xe4\x41\x3b\x67\xb5\x58\x68\x9c\x2e\x7c\x1d\x6d\x64\x08\xf4\x6a\x60\x94\xc7\x4b\x22\x81\xe7\x96\xe1\xd9\x00\xcc\x83\x53\x37\xa3\x1b\x53\x50\xca\xa9\xc4\x44\xc6\x70\xf7\x8f\x86\x6e\x03\xef\x6e\xc2\xcb\xcb\xc1\x79\x97\x41\x45\xb2\x39\xb9\x09\x12\xbb\xee\xf8\xf5\x76\x96\x1b\x5e\xfc\x69\x64\x1f\x7a\x71\x51\x70\x87\x75\xb6\x7c\x9e\x65\xed\x9b\xb9\xf5\xa8\x7b\xb7\x90\xda\x20\x35\x57\xbe\xd2\x67\x40\x55\xe8\xa6\xab\x36\x46\xc4\xe1\xa8\x45\xea\x53\xd8\x61\x4a\xe4\x90\x06\x5d\xef\x75\x76\x15\xa2\x65\xf2\xab\x98\x38\x80\x29\xae\xc3\xaf\xb5\xcc\xa3\xa6\x66\xab\x29\xb6\xd2\xc0\x02\x97\x9c\x63\x6a\x3b\x41\xb8\x83\x7a\x43\x2a\x81\xd6\xdb\x55\xcf\x40\x6b\x1f\x58\x42\xb0\xa8\x87\xfe\x6b\x2b\xd8\x8e\x46\x29\x8e\xd3\xec\xc3\x87\x4c\x98\x37\x73\x46\x33\x1f\xde\x7a\x2f\xf7\xf1\x04\x26\x5b\xbd\x2d\x02\x74\xc0\x33\xc7\x58\x38\x51\x00\x1d\xcd\xb3\xde\xd9\x0a\x9c\x09\x77\xc1\xf8\x6d\x58\x46\x47\x55\x73\x30\xce\xe5\x0a\x53\xbb\x15\xab\x2b\x5a\x8d\x8a\x2b\x5f\xb2\x9f\xfd\xa0\xe1\x54\xb2\x63\x67\xe5\xba\x1c\x67\xa8\x79\xdd\xdb\x61\xd4\x08\x67\xb6\xcd\xf5\xe3\x8e\x0f\xcb\xdb\x9a\x92\x5f\x62\x2c\x7d\xe9\x34\xa3\x08\x23\x90\x67\xda\x11\x65\xdc\x9b\xa8\x91\xfd\x29\xbb\x9d\x9d\xff\x2c\x46\xc6\x0f\x95\x39\x0d\x3d\xda\x52\xaf\x9e\xf6\x4f\xf6\x3d\x2d\xf7\x22\x25\x38\x3b\x92\xbe\x1b\xa4\x8b\x17\x40\x56\x78\xd2\x24\x35\x65\xbb\x58\x86\x9b\xc4\xb2\xb8\x79\xcc\xc8\x99\xd2\xf9\x36\xc2\xb8\x19\x5f\xd4\x74\x05\xd8\x6f\xfb\x46\x97\x55\xb7\x72\xe4\xb5\xfb\xe7\xe4\xa2\x93\xb5\xdb\x71\x00\x08\xc9\x00\x6d\xab\xd6\xa9\xab\xec\xdf\x60\x9a\x3c\x78\x9a\xcf\xe2\xf2\x33\xae\x14\x21\x93\x1e\xf6\x63\x34\xfe\x74\x3f\x48\x77\xbf\xcd\x3a\x63\x71\xfb\xe3\x78\x46\x5b\xd6\x3b\xf5\xda\xee\x92\x0b\x1a\x64\x13\xa4\x6c\x69\x69\x3f\x72\xfc\x87\x9f\xff\xe1\xa9\x17\x38\x08\x4d\xf8\x46\xbe\x95\x43\x89\x28\x93\x95\x83\x44\xa0\x01\x58\x1e\xe3\x2c\x21\xa7\x28\xe8\x05\x04\x69\x95\x3b\xda\xb7\x83\xee\xae\xc5\x56\xa2\xa5\xab\x1c\xf3\xd0\x8c\x2b\x92\x33\xf5\xf3\x64\x1b\xcd\x76\x08\x7c\xf2\x95\x5b\x60\xae\x14\x1e\xd4\xca\xde\x54\x5d\xf6\x0a\x61\x9a\x55\x60\x71\xd2\xef\x3d\xea\x09\xe7\xbf\x54\x60\x50\xe5\xdf\x3a\x8f\xdf\x04\xf6\x63\x16\xf6\xda\xa4\xdb\xb8\xcb\xd2\x42\xd0\x6a\xae\xcb\x1f\x1d\xbb\x4d\xae\x42\xc1\x58\x9c\x32\x83\x02\x77\xd2\x09\xbe\x16\x0d\xaf\x62\x8b\x5b\x19\x92\xf2\xb1\xc5\xf0\xea\xcd\xa1\xe3\x8e\x00\x87\xb7\xca\x8d\xab\x93\x50\x15\x40\x48\x5a\xd1\x8f\xf8\x69\xab\x4f\x4b\x8b\x01\x6f\x45\x43\xc6\xa7\xa9\x36\xfd\x35\x1f\xa5\xcc\x62\x7d\x24\xeb\xbb\x30\xd8\x18\x9c\x42\x58\x86\x45\xcb\xf1\xff\x87\xee\xc9\xb7\xd7\x09\xc0\x5e\x64\x9d\x9b\x64\x01\xa9\x9b\x3a\xca\xb8\xaf\xc1\xc6\x9b\x85\xea\xaf\x3f\xf3\x68\x67\xde\x12\x50\xd9\x8a\xcf\x2d\xc6\xb2\xe1\xd7\x1c\xd3\x2e\xf0\xc7\x14\x02\xcd\x66\x5f\x03\x05\x3d\x22\xa9\xc5\x8d\xe0\x81\xc4\xec\x3a\x5e\xae\x8a\x20\xeb\xe8\x08\x56\x19\x78\xae\x45\x59\x43\xc6\x54\x2d\x03\x19\x86\x4c\xf7\x75\x4f\x64\x9a\xe4\x64\x69\x69\xbe\x65\x18\x5f\xb7\x59\xe6\x98\x27\x4b\x45\x6b\x74\x8b\x9a\x51\xf7\xfd\xef\xd4\xcd\x48\x60\x9c\xbe\x64\x60\xa3\x19\x76\x52\x9f\xe4\xb6\xfc\x64\x37\x45\xfd\x2d\xd3\x63\x1c\x8f\x75\x76\xbc\x80\x52\xbd\x32\x90\x5f\xbd\x42\x65\x94\x79\xbf\x79\xde\x2d\x3b\xe3\xcb\x19\xe3\xd4\xd0\x28\x83\x44\x9b\xe1\x37\x4b\x6e\x24\x3a\xaa\x87\x14\x94\x77\xc2\x5f\xf6\x82\xe5\xc8\x4a\x03\x03\xf1\x12\x31\x08\x6e\x4a\x57\x8f\xf5\x2b\x63\x06\x00\xfc\xbb\xe7\x1f\xb7\x19\xc3\x03\xb9\x16\x31\x05\x81\xb3\x2e\xf2\xdc\x89\xf4\x09\x4e\x0b\x37\x0b\x08\x3b\xd3\x21\x4a\x0f\x3f\x45\x04\xfc\xb3\x72\xd3\xad\x4a\xe2\x06\xbd\x8e\x34\xd1\xe2\x0f\xce\x72\xa8\xab\x40\xc1\xca\x4e\x45\x46\x35\xee\xbf\xe7\x2d\xea\x80\xfd\x95\xf9\xc6\x53\xe3\x2e\xde\x81\x6b\x43\x2b\xa4\x8e\x38\xbe\x49\x57\x0c\xf5\x55\x0b\x7e\x82\x67\xfc\x2f\x15\x64\xbc\x4b\x64\xef\xee\x9b\xe2\xb5\x81\xf9\x0e\xb9\x6e\xd0\x1d\x5f\x34\xe3\x42\x62\x31\x4c\x87\xf6\x02\xc9\xb1\xd3\x1c\xce\x77\x2c\x1a\x02\x3c\x2c\x02\x95\x28\xcf\x8d\x6f\x9e\xa1\xb3\x3b\x61\x26\xc4\xa8\xc2\x87\x72\x38\x8f\x38\x2a\x7a\x87\x56\xe1\xe2\xfc\xca\x54\x9b\x00\x85\x8d\xe2\x82\x9f\x87\xaa\x20\xeb\x08\x30\xa0\x04\xbd\x8a\xe7\xd5\xb3\xe3\x36\x31\xaa\x57\xcf\x07\x18\x26\x2c\x0e\x76\x80\x62\xeb\x36\xa0\x37\xf8\xf0\xab\x7c\xca\x79\x29\xf7\x8f\x03\xc9\x17\x27\x17\x4e\x53\xe6\x02\x47\x39\xbe\x73\x24\xfe\xc9\xb4\x50\xf4\xab\x82\xd1\x05\xbb\x3a\xcb\x69\x33\x27\x55\x8f\x80\x96\x89\xd4\x52\xe9\xa4\x6e\x3d\xe7\xda\xfa\xdf\x87\x92\x1f\x17\xfa\x24\xce\x87\x4d\x3e\xf2\xa5\x56\x10\x0a\x0c\x88\x4f\x84\x40\x48\x1f\x97\x4d\xeb\x9e\x17\x86\xe5\xfa\x8e\x14\x19\x1b\x6f\x79\x7d\xbc\x0c\x86\x42\xa1\xf7\x34\xbe\xd7\xcd\x72\xb2\x15\xd0\xb2\xb5\xb9\x87\xd2\x30\xdf\x63\x74\x2b\xbc\x4b\x10\x17\x6a\x99\x15\xcf\xc7\x49\x8d\x48\xb3\xfd\x30\x47\x57\xb2\xa1\xf5\x9e\x08\x97\x88\x18\xcf\x04\x3a\x6e\x9c\xdc\xe9\xbe\xaf\x09\xd6\x15\x30\xde\x06\x1f\xd7\xad\xc9\xd4\x7d\x23\xe7\x52\x88\xd0\x92\x91\xc6\x01\xba\xd4\xa7\x6d\xa8\xdf\xf2\x62\xa7\x23\x46\xc0\x77\xee\x25\x15\x62\x1d\xf9\x07\xaa\xbc\xfd\xbc\x14\x59\x04\xff\xfd\x9f\x8b\x04\xe2\x47\x65\xa0\xfb\xb0\xb4\x34\xab\xd3\xb7\x86\xd5\x60\xec\xea\xb5\xf9\xfc\xe4\x2a\x85\xec\x05\xe8\x85\xe1\xc6\x6b\xaf\xdd\x0f\x6e\xb7\xde\x3a\xb1\x45\x11\xda\x69\xc7\x72\x3d\xec\x82\x92\xbb\x3f\xf2\x01\xff\xe6\x0d\xf6\xe2\xc5\x24\x0d\x1a\xd7\xcc\x0c\x51\xa3\xdc\xb2\xf6\xaf\x1f\x30\xe3\xa9\x7a\xf1\xf3\x2f\x30\xda\x0c\x7d\x6c\xeb\x89\x71\x99\xc9\x36\x7d\x4d\xad\xd7\xa8\x43\xcd\x2f\xbd\xa1\x36\x14\x69\x2b\xa4\x92\xbb\xb3\x7c\xea\xe1\x51\xd5\x6f\x81\x53\x2f\xeb\x37\x8a\x18\x6c\xca\x0f\xc8\xf1\x36\x63\xce\x01\x7e\x2c\x7c\x21\x99\x76\xc7\x6b\x93\xfe\xc4\x0b\x52\x72\xb2\x59\x72\xba\x14\x67\x2e\x7b\x72\x00\x05\xdf\xfd\x08\xf7\x82\x18\x8c\xc1\x6e\x37\x1a\x3b\x9e\x98\x5f\x9f\x51\x90\x7c\x49\xb0\x17\xa4\xa8\x8a\x14\xe3\x2b\x67\x36\x4e\xf0\xde\x7a\x12\xed\x65\x88\x33\x4b\xdf\xbf\xe2\xe4\xea\xd9\x9e\x7b\xe5\xbe\x31\x93\x34\xe0\x75\x52\x9a\x84\x37\xc7\x24\xf6\x1e\x6c\xc5\x16\xd3\xb2\xaa\xb6\xb4\xf9\x35\x35\x1f\x01\xa8\x37\xb0\xb3\xe6\x4e\xac\x92\xee\xb8\xa1\x46\xaf\x9b\xe9\x76\x61\x02\x2c\xf9\xc6\x6b\x98\x3b\xb1\x55\x7c\x42\xd9\xbe\xd4\x12\x34\xe9\x93\x6b\x31\x86\x64\xd8\xcb\x24\x06\xe8\xa4\xdb\x92\x67\x8a\xe1\x2f\x94\x0f\x3c\xa3\x3b\xe2\x7b\x37\x5d\x29\x65\x05\xd3\x7d\xb1\xf3\x7b\x45\x7f\xe4\x45\x6a\x92\xda\x58\x4a\x66\xd0\xbd\x4d\x57\x6e\x07\xcd\x4b\x1b\x50\x97\xf4\x01\xe1\x88\xab\x16\xbc\x92\xc8\x23\xac\x02\xf2\xae\x41\xe2\x2f\xb5\xd4\xce\x56\x25\x7c\x55\x27\xd0\x88\x92\x49\x3e\x33\xe8\xa1\xc2\x9a\x91\x55\x83\x1f\x5c\x86\x98\x96\x81\xb6\x9d\x83\xd7\x38\xb1\x5b\x75\xc6\x9e\x38\x62\xce\xdd\xb9\x0b\x96\x97\xf7\x27\xe0\xca\x28\xc8\x67\x38\xc4\x2f\x4d\x2e\xb8\x4d\xe2\x3a\x3c\x5c\x32\xc8\x6d\xdc\x8c\xe2\x6f\x0b\xa1\xca\xd9\x9d\xb4\x2e\x34\x6a\xc1\xae\x59\x23\x21\x43\xb9\x39\x24\xbf\xd2\xf1\x59\x05\x42\x03\xb8\x40\xb8\x60\x47\x24\xf9\x81\x94\xe1\x3a\x7a\x42\x07\xb4\x1b\x37\xe0\xb3\xfa\xd4\x1c\x24\x4b\x19\xe7\xc2\x5f\x22\x76\x4d\x88\x8c\x5c\x8c\x61\xe1\x15\x57\x6d\xea\x39\x9e\xf2\xa2\x73\x2f\xd8\xc2\x4c\xc6\xaa\x0f\x72\x5f\xe4\x91\x6c\x4e\x23\x4e\x92\x4c\xb4\xf7\x08\x4d\x2d\xf1\x9c\x06\xbd\xc3\x24\x86\x6d\xbd\x5b\x4a\x16\x54\x29\x61\x9f\x2e\x99\xf0\x30\xef\xb2\x23\x30\x1c\x47\x56\x5a\x48\xa9\xa2\x8f\xc5\x39\xc1\x82\xcf\xc9\x0c\x44\x06\xba\xfc\xa7\x4f\xe4\x58\x22\x85\xa3\x79\x1e\x3c\xbe\xbf\x2a\x1a\xca\xdb\xe8\x7d\xa6\x55\xc9\xce\xe9\x4d\xe6\x8f\xd1\x34\x61\xf0\x1f\x5d\x22\x5e\x06\x1f\xcf\x05\x17\x12\x26\xde\x40\xa3\x9b\xd2\xb0\x17\x7e\xa0\xde\xae\xd2\x36\x10\xad\xe4\x1e\xee\x1e\xa3\x25\xdf\xe4\x3c\xca\x28\x00\x0d\xaf\xcd\x79\x6c\xb2\x8c\x23\xcf\xd9\xbd\x9e\x8b\x6a\xfb\xb2\x1d\x33\x34\xc3\x96\xca\xfd\x23\xf6\x7d\xd8\xcd\xcd\x58\x66\xf9\x36\xf1\x29\x70\xb3\xa1\xfb\x4b\xd7\x38\x6e\xec\x4f\xaf\xff\x64\xff\x65\x8d\x14\xfc\xe9\x2d\x81\x1f\x93\xe9\xde\x6d\x01\x24\x1c\x85\x1c\xf3\xef\xbe\x72\xbb\x17\x7e\x81\x8f\x62\x45\xfc\x7e\x8f\xb8\x57\x1f\x0f\x48\x04\x01\x49\x2f\x11\x0e\xed\xe8\x4d\x5e\xe2\xf4\x25\x2c\x56\x23\x6a\x0f\x5a\x8f\x93\xdd\xfc\xf2\x22\x40\xdf\x56\xe5\x8c\xf9\xe5\xa6\x64\x7b\x69\x7e\xd1\xf5\x87\x19\x55\xa2\xfb\xce\x9e\x11\xca\x26\xc1\x3a\xde\x04\xea\xbb\x67\x5d\x69\xf4\xce\x3e\x60\x9c\xe5\x06\xf3\x7a\x03\x97\x8c\xe5\x26\x01\xba\x4a\xe9\xbb\x28\xb0\x5a\xb7\xb2\x4e\x93\xb9\xfe\x6a\x21\x59\xab\x58\x9a\xb5\xf5\xe3\x4b\x9e\xea\xc4\x6f\xd6\x7c\x97\xa5\x9d\x08\xd0\xc9\xdc\x89\x7f\x89\x45\x95\x24\x00\x7b\x62\x21\x70\x0f\xfa\x78\xf6\xfe\xdf\xb1\x73\xc0\xc3\xf5\xe4\x10\x5b\x7e\x25\xfa\x5f\xa4\x3d\x66\xe6\x6e\xd8\x0a\x0d\x0a\xbf\xab\xd9\x41\x12\xe1\x58\x31\x89\x92\x49\xef\x96\xb9\xdf\x1f\xa1\x76\xad\x3b\x44\x23\x70\x8c\x3f\xcd\x4e\xd8\x8e\x92\xe5\xcc\x9b\x69\xb7\xd4\x69\xaf\x43\x12\x07\xe0\x0a\x0f\x0f\x99\xa0\xb8\xca\x94\xbc\x12\xb6\x78\x08\xe3\xf2\xc7\xdc\xc2\x4b\xa5\x82\xcd\xb8\xcb\x33\xa8\xf4\x15\x23\x47\xf0\x49\xca\xe5\x99\x45\xd7\x02\x7a\x2c\x27\xbd\x88\x4a\xbf\x2e\x02\x13\x0b\xaf\xe9\x33\xf3\xc7\xff\xc1\x6d\x61\xf6\x8a\xd0\x6d\x01\x7b\xc6\xb1\x01\x5a\x12\xab\xf3\xb1\x4d\xf5\xb7\xe2\x1f\x34\x03\x74\x62\x05\x6c\xe8\xc3\x98\x65\x7d\xc9\x8f\x20\xbc\x62\xa5\x4f\x83\xfd\x4a\x67\x73\xc6\x54\x95\xe8\x1e\x97\x9a\x6e\x04\x40\xd1\x72\x25\x79\x4e\x05\x7f\x76\x65\x7d\x58\x19\xbf\x6c\x9a\x42\x87\x32\x13\x02\xe4\x2f\xb0\xbb\x92\xd4\x0b\xfd\xc2\x3d\x5e\x96\x04\xaa\xd6\x74\xf1\x8c\xab\xd4\xdf\x79\xf8\x57\xca\x8b\xf6\xcd\xe8\x65\x9b\xed\x37\xc9\x58\x3a\x5f\x1b\x3d\x01\xbb\xb8\x70\x9b\x5f\x5b\x90\x6f\x04\xb2\x04\x04\x98\xb0\xfc\xdb\x41\xc3\x31\xd7\xfa\x76\x46\x90\x55\x39\x0b\x09\x94\x30\x31\xc2\x14\x4c\x0b\x56\x0c\xa4\xb2\x80\xec\x38\x83\xab\x53\xb3\xa7\xf6\x79\x4c\x15\x23\x72\xef\x90\xfd\xf1\x1f\xbb\xd9\xa9\xb6\x45\xed\x91\x96\x7f\x13\xfd\x40\xc3\x7f\xfb\xbc\x4d\x91\x1f\xb9\x67\x0c\xe2\x52\x4d\xd3\xa8\x05\x54\x5b\x85\xd8\x21\x97\x86\x99\x82\x77\xf9\x0b\xea\x24\xb8\x86\x2e\x70\x6f\x57\x72\xe5\x55\x29\x3e\x5c\x7b\xaf\xfe\x5a\xaa\xc0\x15\x36\x91\x47\x06\x40\xbe\x77\x77\x8d\x00\xad\x98\xf5\x45\xc6\xc7\x52\x97\x38\x64\x58\xc2\x88\x7a\xb7\x78\x7d\xb0\x01\x92\x19\x05\x94\x29\x10\x31\x06\x8b\x98\xc1\x93\x48\x62\x1b\x2f\xc6\x55\x39\xc5\xe2\xf6\xe5\xf3\x0e\x2b\x7c\xc0\xe9\xc3\x53\xc4\x74\x4e\x42\x81\xe0\x2e\x61\xa7\x4b\x41\xc2\x80\x54\xba\x0c\xa3\x82\x67\x08\x34\xc5\x19\x7e\x89\xfa\x1d\xee\x66\xb5\xd4\x58\xf5\x40\xe9\x43\xa6\xf0\x7b\xbc\x5e\xfa\x4d\x5f\xdc\xdc\x93\x8b\x06\xdd\x8f\x24\x9d\x93\x9e\x82\x92\x13\x6e\x32\x7e\x0d\x7f\x97\xfc\x1c\xca\x48\xdc\xd0\x1d\xe5\x74\x5b\x9a\x68\x53\xe0\xf1\x81\x85\x16\x3f\xfb\xe1\x96\x7c\x00\xc6\xfb\x5e\xa6\xd5\x9f\xff\x5b\xd5\xb4\xf7\xc9\xda\x29\xa7\x8f\x93\xe3\x77\xae\x08\x24\x75\xaa\x1f\xd0\xb5\x5b\x13\xf8\xed\x58\xb9\x91\xdf\xe8\x61\xb0\xf6\xd7\x9f\x79\xcc\x8f\xdc\x3a\xd0\x06\x7b\xc3\xfc\x37\x75\xe9\x03\xde\x54\x8e\xd4\x8e\xde\xf2\x6e\x50\xd9\x30\xa6\x12\x53\x0e\x5f\x38\x5c\xe5\x83\xe3\x34\xa2\x7b\xaf\x05\xde\xf1\xd4\x91\x13\xf2\x08\x80\x95\xb9\x7c\x40\xbd\xf6\x08\xdc\xad\x81\xe0\xe9\x30\x00\x63\xc6\x5d\x74\x2b\x14\x21\xea\xc8\xc6\xdb\x74\xc5\xde\xd9\x47\x6c\x16\x94\xd5\xbc\x75\xde\xb7\x97\x6f\xb6\x93\x78\x80\x88\x3a\x04\xe6\x04\x24\xff\x67\x7c\xb2\x95\xae\x3b\x58\x93\x80\x67\x1c\xcf\x61\x86\x34\x1f\x52\x85\x30\xbd\xd2\x8f\x6a\x66\x2f\xbc\xeb\x26\xd2\x08\x91\x25\xaa\xcc\x0d\xbb\xd7\xa4\x08\xc9\x82\xe9\x38\x08\x4b\xaf\x7f\x6c\xf2\x23\x04\x33\xa7\x6b\x4b\x79\xa7\x00\x6c\xcd\xa2\x98\xfd\xff\x1b\x5f\xd1\x00\xec\x1f\xaa\x2d\xc5\x09\x52\xe4\x35\x2a\xb1\xb1\x2c\xeb\xa0\x5c\x29\x17\x78\xfe\xf2\x80\x0a\x17\xa4\x38\x31\x37\xea\x5a\x74\x1d\x54\xfa\xc4\x1e\xc2\x46\xe8\x8f\x63\x16\x61\x2e\xb1\x67\xd6\x04\x39\xe8\xb9\xde\x19\x05\xee\xb1\xb6\x08\x89\xab\xc0\x0b\x5e\xe6\x42\x72\x23\x87\x63\xc4\x91\x29\xf9\x15\xdd\xf6\xf9\xe2\x4c\xec\xff\xcf\x33\x1b\xcb\xce\xa9\x68\x49\x7f\xc0\x8f\x55\xdb\xa0\x13\xab\xa5\xe3\xaa\xbf\x96\xfb\x7d\x83\x6d\xb6\xaa\x13\xec\x80\xb0\xd5\x05\x06\x8f\x5b\x0d\x92\x65\x8e\x01\x98\x13\x78\xe4\x71\x65\xa7\xaf\x5c\x08\x65\x81\xe8\x13\xc2\x68\xd8\x51\x3a\x5e\xa6\x62\x95\xfd\x0f\x27\x00\x4a\x6e\x86\x56\x43\x23\xbc\xd8\x67\x17\x08\x8d\x7a\xaf\x6d\x7e\x03\x55\x28\xca\xbb\xfa\xb6\x5a\xb5\xd3\xeb\x9d\x6a\x92\x8b\x29\x49\xe3\xe8\xd5\x39\xd5\xcf\x85\x5d\x5a\x63\xfb\x5d\x53\xcf\xee\xcb\x21\x3a\x0a\x7c\x16\xd8\x1b\x43\xdc\xac\x3e\x70\xb3\x4f\x5a\x00\x0d\x45\x35\xc8\xd5\xa5\xe0\xd2\xbf\xb1\x03\xbf\x10\x16\x6c\xa9\xab\xb9\x3e\xe2\x0b\x50\x77\x3e\xa4\x82\xd9\xbd\xaa\xec\xe1\x8f\x7f\x57\xb8\x3e\x63\x19\xa3\x09\xe8\x2c\xf6\xc7\xab\x52\x27\xc0\x51\x98\xf4\x5a\x8c\xb7\xd7\x9f\x84\x14\x80\x69\x5a\x01\xa9\xc4\xa9\x13\x25\x97\xc6\x40\x8d\xc9\x9f\x52\x68\xe0\x8a\x6f\x44\x95\xce\x32\xd9\xba\x89\xc4\x3f\x21\x4d\x15\x89\xc7\x53\x50\x56\xaa\xa3\x8c\x47\x94\x24\xc8\xc5\x91\x9a\xe3\xd2\xc3\xd3\xee\xd1\xaf\xc1\x6c\x97\x96\xba\x48\xca\x2a\x74\x12\xce\x7c\x02\x7a\x3f\x66\x75\x17\x14\x57\x9e\x6c\x0a\x37\x08\xe6\xa9\x15\x1b\xc8\x64\x1f\x2c\x31\x86\x2d\xd1\x64\x43\xdf\xa7\x48\xc4\x34\xbc\xbc\x12\x8a\x47\x4f\xb2\xfc\x33\xd7\xe4\xe0\xf9\x6c\xaa\x74\xa9\x4a\x4b\xf2\xc7\x79\xce\xe9\xa9\x9e\x27\x66\x14\xd1\xe2\xc6\xe0\xfb\xd9\x6f\x28\xe1\x90\x81\xc0\x5b\x80\xeb\x9d\x66\xec\x39\xc5\xfc\x0d\x7a\x1e\x00\xfd\xcb\xa0\x76\x74\x74\x62\xd6\xc2\x2f\x85\x29\x28\xcc\x1c\x17\x50\x34\xf9\xf2\xd8\x8d\xbc\xbc\x32\xc6\x65\x82\x4e\x61\xa6\x15\xf4\x79\x72\x06\x39\x66\x95\xec\x94\xce\x6d\x1b\x62\x99\x18\x19\x1a\xb8\x25\xe8\xfa\x3e\x5e\xb9\x06\x28\xc1\x46\xd1\x32\x90\xff\xbe\xc1\x98\x93\x69\x1a\x26\xa0\x84\xa2\x48\xf0\x37\x06\x97\xa8\x16\x98\x46\x31\xb7\x1c\x0e\xc0\x52\x08\x80\x15\x17\x3d\xc6\x29\x29\x5a\x63\x63\xc2\x81\x3a\x59\x16\xd3\xe3\xeb\x51\xbb\xba\x08\xaa\xa0\xa5\x97\x86\x18\x39\x69\x43\x9d\x15\x38\xb7\x17\xf8\x3d\xbb\x57\x1c\x8f\x80\x9d\xbf\xf5\xd6\xbc\x5f\x20\x72\x45\x17\x70\xd6\xd9\x7d\x5e\x6b\xa3\x5a\xe4\x72\x2b\xbd\x89\x55\xd4\x1b\xae\xa6\xd4\x66\xdc\x14\xf0\xe1\x67\xdb\x9f\x7c\xec\xa7\x95\xee\x38\x46\x0c\x14\xf0\x4d\x35\x34\x18\xcf\xd4\x41\x0f\xa4\xd7\x9e\x3a\x72\x1b\xac\xf8\x23\x8a\xb6\x2b\x7f\xed\xee\xbb\x5d\xeb\xc6\xe3\xef\xd5\x80\x86\xde\x28\x6a\xdd\xeb\xf2\x7d\x4c\x80\x78\x9b\x96\x94\xf5\xce\x8b\x3b\xa8\x0f\xee\x00\x99\xe6\x81\xed\x74\xc3\xc6\xca\xc6\x10\x3f\x1c\x5d\x86\x41\x1b\xfc\x70\x5e\xa6\xd9\x79\x6d\xbe\x00\x62\xd6\xa7\x93\xaa\x20\x86\xa2\x3d\x26\x81\xe3\x99\x6b\x85\xf0\xf2\xb8\x62\x16\x70\xd6\x14\xbd\x3e\xab\xdc\x53\xbe\x0b\x0e\xbe\x6c\x4f\x3b\xfa\x56\x2d\x6a\x7a\x40\x24\x1d\xdd\x6d\x9f\xfb\x28\xa0\xb2\xbb\x6f\xa4\xe1\xf4\xd7\xc2\x12\x99\xe7\x37\xf9\x72\xd8\xe5\x35\x9d\x39\x48\x62\xfe\xbb\xf4\xaa\xe1\x5d\x68\x89\x22\x35\xc1\xf3\x4f\x31\xd7\xc6\xb0\xaa\xfe\x76\xda\xf0\x43\x79\xc6\x9d\xb5\x2a\x55\x5e\xe0\x2e\x99\x37\x62\xcd\x0b\x72\xaa\x86\x59\x6d\xc3\x11\xcf\xa4\x6b\x64\x30\x07\xee\x46\xac\x8b\x68\x67\x32\xfc\x10\xc0\x7b\x38\x9f\x23\x7d\x0b\x63\x0f\x76\x72\xb0\xf6\x3d\x63\x19\x9b\xe5\x46\x4f\x71\x8a\x71\x42\x76\xd7\xf5\x47\x1c\xa0\x69\x34\x5a\xaf\x3b\x38\xd9\x41\xc6\xb6\x4e\xde\xc9\xc0\x66\xd2\x79\x9c\x4b\x51\xbd\x04\x05\x35\x8f\x83\x4b\xd5\x98\x8c\x78\x61\x72\xb8\xf2\x17\x68\x06\x78\x77\xa5\x5e\xfe\x94\x11\x25\x9d\x24\x03\x6c\xf0\xd4\xe4\x42\xa9\x22\xc1\xe9\xfd\x70\x15\xc0\x04\xbe\xdd\x94\x06\xe9\x41\x0c\x9e\x1b\x55\xa3\xde\xa6\x7b\x11\x96\x1d\x0c\x0d\x6c\x7f\xb9\xfa\x61\xb7\xb7\x40\xe0\x5a\x58\x57\x35\x9d\xa1\x79\xff\x9e\x49\x35\xd7\xad\xe8\x2e\xb2\x0f\x30\x8b\xfc\xe2\x9d\x13\xe9\x8c\x81\x85\x3c\x22\x96\x46\x95\xdc\x18\x8b\xe9\xce\xeb\xff\x8d\xae\x55\x8f\x5f\x7b\x03\xdb\x0a\x22\x3e\x31\xb9\xad\xce\xa0\x00\x26\x32\x5f\xb8\x85\x8e\xc2\x10\x6e\x10\x20\x7d\xaf\xd4\x1e\x7a\xdd\x2a\x42\xc3\x13\xe2\xfd\xeb\x38\x09\x5f\x66\x54\x23\x46\x64\xf9\xf2\x04\x05\x3e\x7f\xe1\xa0\xdb\x12\x53\x1d\x3f\xcd\x7f\x0c\x7c\xe6\xc5\x58\x0b\xd6\x37\xd7\x35\x80\x1d\x65\x10\xcf\xfe\x72\xe0\x1a\x88\x4c\xbe\x76\xaf\xe9\x3a\x58\xc2\x23\x79\xc1\xe6\x4d\x7c\x7a\x02\xdf\xd1\x6d\xa2\x3d\x26\xc5\x84\xdb\xec\x9a\xba\xae\x15\x13\xc0\xa3\x81\xc9\x6e\x49\xf6\x3c\x04\x04\x6e\x42\x26\xd3\xcf\xa3\x2d\xdb\x98\x75\x4e\x2c\x99\x93\xf8\xa9\x7f\xb8\xa5\x93\xab\x6f\xb1\x9f\xc0\xa8\xd1\x4b\x8a\xdf\x71\xd9\x25\xef\x06\x7a\x3b\x96\x65\xa6\xba\x66\xfc\x5c\xb6\x88\xfa\x14\x86\xc2\x81\x1f\xd8\x1b\xd8\x28\xea\x49\x4d\x0d\xf1\x59\x91\x8e\xff\x1d\x38\x0b\x5c\xfd\x57\x7b\x01\x7f\x3c\xff\xc9\x0b\x0d\xc0\x74\x03\x3c\x8c\xf5\xe8\x1f\xff\xcf\xba\x0d\x0c\xc3\xfe\x1e\x36\x0f\x2b\x0c\x3d\xcc\xf0\xc2\xc4\x04\x3d\xfa\xde\xc2\xf5\xbe\xf1\x68\x5e\x77\xb6\xf0\x1b\xd8\x8f\xb5\xfc\x8b\xfe\x46\x2a\x64\x1d\xc6\x6c\xe7\xc1\x82\x4c\x2b\x4d\xdc\x73\xf3\xca\xe3\x3b\xd0\xb6\x69\xb8\xf6\x42\xf7\x77\x5e\xc3\x18\x0a\xaf\x67\x4c\xa8\x04\x2a\x2d\x76\x40\xd4\x02\x14\x9e\x1b\x64\x21\xfa\xb0\xa3\xad\x0c\x30\xe2\x48\x9b\x6c\xcd\x3a\x98\x95\x3f\x62\xb5\x5a\xfc\x3a\xfe\xb6\x05\x51\x7e\xdb\x95\xcd\x7d\xab\xb1\x32\x67\x10\x6c\xf0\x0b\xda\x79\x7c\x3a\x57\x45\x80\x0b\xc1\x7a\x7f\x31\xf1\x2d\xf4\x4f\x95\xb1\x69\x5a\xde\xbc\x35\xa7\xa9\xcc\x20\x58\x42\xe6\x03\x30\x3d\xe6\x02\x87\xfd\x1c\xe9\x24\x0d\x9d\x78\x75\xaa\x2d\x9f\x59\x1c\xdc\x45\x65\xe1\x7c\x18\x4d\x43\x8a\xf2\x9f\xfe\x02\xc2\x49\x34\x0c\xa1\x09\x19\x31\xbb\x97\x84\x96\x22\x99\x71\x8d\xab\x96\x9d\xde\xe6\xd7\x1d\x2e\x4d\x57\x12\xd9\xa1\x31\xb0\xf6\xfb\x7a\x90\x81\xcc\x3f\x69\x23\xb5\x36\x72\xd6\xe5\xda\xdc\x54\x5e\x79\xb0\x92\x62\x82\xb2\xae\x53\x48\x22\x6b\x2a\x14\x6e\x2d\x46\xc3\x56\x7b\xd3\x16\x1d\x23\x13\x30\x26\xe9\x6c\xd9\x53\xca\x96\xf5\x8b\x09\x1b\x2c\xdc\xe9\x48\xb2\xc1\x84\xfc\xc2\x4f\xfd\xbd\xb8\x14\x7d\x62\xe6\xb3\xdd\x03\x17\x5b\xb6\x8a\xea\x5b\xe5\x0e\x23\xf9\xc8\x9d\xff\xf0\xe9\x27\x89\x35\xfd\xdb\x23\x89\xb0\xfd\x8b\xd8\xea\x2f\xde\x7c\x3f\xa9\x0f\x8d\xcd\xa6\x6c\x29\x71\xa4\x31\xed\x85\xb2\x87\x1c\x54\xc8\x0c\x99\x5b\xab\x33\x97\x07\x6b\x2a\x17\xfa\x8f\x59\x57\x5b\x87\xf2\xfa\xfc\xb6\x17\x19\xcf\x77\xc3\xe6\x52\xd2\x52\xac\x14\xae\x0b\xac\x6e\xa5\xf3\x2d\xbb\x42\x65\xee\x86\xd6\x18\x02\xf5\x52\x0a\x78\x95\xf0\xcb\x69\xa1\xf2\xf6\xfa\xf4\xd8\x8b\xc2\x9a\xab\x48\x38\x06\x4a\x11\x50\x65\x59\x9b\xe8\x3f\x67\x99\xf3\x7a\x5c\x5b\x6f\xe5\x2c\x2e\xb9\x10\xf9\xe7\x15\x0e\x33\x96\xcc\x41\xa0\x40\xf4\x13\xdd\xac\xfc\xce\x34\x4d\xe2\xbb\xd1\xe6\x6f\x5a\xb6\x62\x75\x32\xca\x7d\xc2\xd1\x9d\x22\x75\x7a\x7d\x14\xa1\xca\x01\x1e\x6e\xde\x6c\x41\xcc\x3b\xb8\x30\xe9\x54\x0a\x6e\x75\x22\xa4\xa9\x72\x3d\xbb\x8c\x05\xdf\xbc\x40\xfe\x3a\xb1\x07\x05\x4f\x9f\x5e\xc8\x68\x22\xd7\x7f\x6d\xac\x7e\x4e\x17\x0a\xf8\xea\x42\x26\xea\xe3\xc2\x1c\xbd\x1d\xfb\x94\xcc\x22\x3b\x2c\x67\x09\x72\x4f\x71\xd3\xf9\x96\xd8\x10\x17\xa1\x20\x9c\x8d\xcc\xb8\x54\xf9\xf0\x6d\x0a\xac\x59\xda\x98\x9e\x31\x54\xcd\x20\x91\xd0\x1c\x89\xe2\xb4\x9f\x2e\xd3\xfa\xd6\xf4\x34\x19\xb3\x37\x74\x50\x23\x84\xc3\x7a\x02\x31\x0e\x8e\x5d\x44\x1f\x89\xcc\x9b\xd5\x9d\x09\x67\x1f\x41\xf1\x95\x9a\xad\xd2\x8b\x69\x44\xd5\x1c\x91\x08\x67\x30\x68\x25\x3d\xda\x0d\xca\x16\xa3\x37\x8f\xab\xa3\xf2\x98\x0b\x60\xe0\x8b\x11\xe7\x9e\x7a\x05\x29\x2b\x82\x44\xd1\xce\x8b\x51\x8a\x92\xcf\xff\xdd\x72\x02\x51\x75\x01\x07\x76\x38\xa9\x66\x7c\x88\x4c\xd4\xdb\x63\xdf\xc4\x79\x81\x43\xb7\xb7\xb8\x7b\x7a\x0b\x74\x30\xd0\xe6\xf3\x19\x50\xa5\x1e\xb8\x8a\x72\x2b\x6d\xf7\xcf\xb9\xab\xe9\x51\x81\x48\xd9\xe3\xf8\x7c\xe0\xc3\x2d\x96\x3a\xbb\x82\xe1\x33\x44\x8c\xf9\xc4\xcc\x42\xf0\xb6\x3c\x7c\x04\x31\xc2\xea\xe5\xdf\x57\x29\x39\x03\x62\x5d\x04\x55\xc3\xf1\x0d\x1c\x76\xb2\x52\x20\x84\x5b\x91\xd1\x5f\x9c\x9a\xd1\x2c\xf7\xb7\xe3\x74\xe7\x93\xf9\xca\x2f\xcc\xf4\xcd\xec\x2e\x67\x4f\x2f\x36\x77\xf7\xfa\x16\x5b\xb6\x66\xd1\xca\x00\x74\xa8\x50\x84\xaa\x62\x64\xb1\x19\x2c\x92\xc1\xaa\xc4\x90\xea\xdd\x00\x76\xcf\x39\xb7\xb1\xcc\xb7\x8a\xcf\xa5\x0b\x2d\x0d\x3f\x4d\x42\xda\x7f\x43\x4e\xff\x4b\x53\xb3\x4d\x3c\xcb\x2a\xe8\x29\x0e\x58\x11\x19\xf4\x7f\xc3\x3a\x52\x79\x15\x85\x07\x08\xbf\x23\x5f\xb8\x49\xf2\x17\xcd\x77\x70\xf7\x95\xa7\x1c\x6c\xcb\x7b\x0c\x98\x7d\x3d\x4f\x35\xf1\x51\x74\xa2\xdf\x6a\xb2\xd5\x0c\x3d\xd3\x7f\x0a\x7f\xa2\x3a\xf9\x51\x53\xfe\x14\xe4\x16\xd3\x17\x40\x35\x11\x27\xa6\x55\xfa\xac\xeb\x30\x70\x73\x0e\x58\xa9\x40\xbd\xc7\xb8\xfd\x7b\x16\xcf\x45\x28\x54\x44\x26\x16\xd6\x24\x69\x7c\x84\xd9\xca\xe9\x68\x99\x1a\xa0\x38\x64\xdb\xb1\xd6\x3d\x11\x83\xdf\x0d\xd7\xdc\x60\x49\xc2\x0f\x09\x02\x22\x76\x49\x83\x46\xed\xeb\xf3\x06\x3a\xe9\xc9\x90\x36\x7f\x1d\xa3\xd8\x6d\x98\xa0\x97\x56\x8d\xa7\x4e\x49\x9f\x29\x7b\x85\xe0\x55\xe9\x67\x08\x63\x9f\x7f\x5b\x98\x29\x95\xd2\x77\x00\x4b\x2d\x21\x38\xd4\x7a\xcb\xab\x8e\x89\x08\x9b\x91\x7a\x72\x28\xf6\x45\x67\xc9\x72\x76\x7f\xc9\x63\xa2\x9c\xc9\x95\xba\x9b\xf6\xd4\x99\xd4\xba\x16\x22\xa2\xc5\x8b\x08\xa2\xa7\x78\x71\x4d\x95\xed\x56\x3a\x36\xcc\x48\xa4\x6f\x7f\x76\xb6\x57\x80\x2f\x5c\xd9\x42\xfa\x0a\xa5\x17\x05\x34\x57\x22\xc3\x24\xa5\x4a\x0e\x51\xa0\xd1\x3a\x09\xf2\xb7\xe4\xa2\x14\xcf\x89\x7b\x51\xeb\x1d\x8c\x84\x70\x37\x26\x60\xa3\x19\x50\x4e\x39\xae\x4a\x2b\xc1\x92\x93\xb6\x03\x87\x6c\x4d\x4b\xfc\x04\x9d\x66\x1a\x5e\x63\xa7\xeb\xe6\xc2\x77\xa0\xe2\xb9\x25\xd0\xe0\xb1\xc5\x0f\x74\xae\xaa\x15\x1d\x42\x22\x27\xf2\x86\x19\x5d\xc0\xd8\x8d\x09\x45\xe8\x51\xbf\x8e\xdd\x52\xbf\x6f\x3b\x1e\xf3\x56\x4c\x97\x0d\x04\x9e\x90\x20\x7e\x79\x9f\x75\x5f\xbd\xfc\xd5\x23\xe3\x2b\x29\xcb\xc0\x35\xe1\x3f\x04\x05\x19\x81\x8f\x16\xdf\xc5\x5c\x59\xc1\x8d\x72\x8c\x89\xd1\xdb\x6e\x60\x3b\xae\x87\xf8\x44\x14\x95\x03\xc3\xae\xf4\xdf\x2a\x98\x89\x44\xa6\x7b\x0d\xb6\xef\x82\x71\x1c\xcf\x0f\x66\x43\x91\x0c\x4e\x5c\x50\x28\x5a\x17\x14\x28\xfa\x89\x16\x44\xdc\x35\x0e\xe5\x7e\x10\xf6\x26\x6c\xd0\x9d\x86\xd0\x0a\xba\xe7\xff\x10\x7d\x9e\xfe\x91\x19\xf4\xb4\x1a\xe4\x8c\x25\x90\xa0\x2c\x79\x22\x9c\x6a\x40\x1d\x97\x5a\xe5\x63\xd1\x68\x51\xda\x23\x06\xe5\x66\xea\x40\x57\xba\x5b\x05\x21\x1f\xc6\x75\xf7\xf1\x95\x7f\x62\x62\x7d\xc8\xf4\x5b\xeb\xc7\x88\x97\x4f\x5b\x13\x06\x79\x44\xf5\xa9\x01\x23\x99\xd1\xfb\x7d\xd6\x7d\xa3\x0f\xa8\x78\x1f\x3e\xe7\x28\xb2\x7c\x86\x05\x36\xc7\xe9\xef\x90\xe9\x6c\xdb\xec\xa6\x44\x33\xc6\x0a\x9a\x9c\x98\xfd\x0e\xb4\x4e\xd9\xa9\x34\x11\x7d\x54\xe3\xbb\x05\x3a\xee\xc2\x90\x3a\xde\x8e\x51\x08\x53\x8d\x37\x6f\xe1\x62\xfb\xb7\x1a\x37\x0c\xc0\xb4\x23\x99\xd4\x0b\x1b\x9d\x7c\xd7\x2e\xac\x1a\x5c\x07\xd6\x69\x31\xd0\x6b\xaa\x89\x00\xea\x8a\xed\x80\x04\x59\x17\x88\x13\x6d\x35\xce\xff\x6b\x09\xae\x69\x35\xd2\x83\x58\xc4\xf9\xb6\xef\x3c\x81\xc2\xf2\xf6\x16\xce\x54\xcc\x1d\x54\x24\x04\x12\x74\x3b\xb1\xfd\xe7\x0d\xbe\x1c\xf6\x2a\xda\xf2\xb2\xa3\xaa\x16\x7a\x8a\x0d\xb0\x09\xec\x42\xf2\x40\x00\xea\x2a\xb3\xde\xd5\xf0\x9a\xf3\x5c\xc8\x3a\xba\x1a\xb8\x28\xe2\xf7\x09\x70\x0d\x1e\x93\x1e\x94\x9f\x69\x2d\x38\xc5\xe3\x73\x50\x8e\xb5\xa3\x85\xd0\x84\x18\xdb\x9b\x6a\x14\xf4\x9c\xae\x9e\x6c\xeb\xf9\x88\x12\xbd\xb5\x8f\x94\x77\x2b\x8b\xc3\x52\x7c\x90\x75\x96\x5b\x62\x66\x15\x8b\xb5\x7d\x67\xac\x31\xb5\xc0\x8e\x8a\x22\x4a\xd0\x86\x01\xda\x5b\xfd\x5f\x18\xda\x9f\x54\x23\xa6\x3c\x05\x23\xe6\x03\xfc\xe0\xcd\x53\x43\xcb\x81\xbe\xb3\x73\x7d\xa5\x4b\xd3\xf6\x48\x71\xee\x89\x65\x79\x05\xfd\x66\x86\xa6\xa5\xf3\x32\x5b\x1c\xf7\xab\x3a\x22\xf8\xea\x7d\x7b\x66\xb2\x98\xc1\xc2\xda\x1f\x06\x07\x83\xe6\x4d\x66\xf0\xc9\xcc\xc7\xbf\x96\x46\x14\x2c\x5a\x09\x35\xc7\x17\xbb\x1d\xc2\x00\x15\x9b\xb9\xeb\x8a\x01\x8c\xed\x15\xc2\x56\x48\xf2\xdc\xa9\x95\x4c\xc3\xa8\x36\x7f\x9d\x85\x04\xd9\xb5\xec\x3e\x94\x9d\xdf\x8f\x98\xd8\xf2\xea\xc3\xe3\xe8\xfb\x2d\xbd\x96\x79\x06\x21\x2c\xed\x9b\x97\x56\x63\x10\x82\xb6\xb9\xd5\xe4\x68\xb2\x46\x11\x6a\xf4\xc4\xeb\xd3\xf2\xce\x84\x0b\x57\x0e\x48\xd3\xc7\x30\x84\xcb\x85\x08\xe0\x17\xf1\x01\x2f\xe5\x05\xbd\x07\xb8\x8e\x09\xe5\x8b\x18\xe1\x93\x66\xce\xb6\x4b\xd2\xac\xa3\x9b\xb8\x9f\x2a\x9c\xae\x59\x49\x56\x8f\xdd\x20\x2c\x5c\x30\x16\xd1\x62\xec\x89\xec\xdc\xf5\xb1\x3a\x84\x90\x02\xce\x69\xfb\x75\xd9\x04\xe7\x49\x8f\x74\xe9\x1d\xad\xaa\x69\x92\xdb\x89\x01\x88\x1c\xf1\x47\x8a\x65\xf8\x4b\x3e\x88\x8a\xde\x70\xc3\xb6\x9f\xef\xaf\x12\x42\x8c\x27\x64\xc7\x4b\xe0\x7c\xb5\x77\x2e\xbc\x0d\x9e\x41\xf9\x3a\xf9\x12\xda\x24\x2a\x78\xcd\x76\xb1\x3f\xf4\x67\x41\x13\xd9\x79\x60\xf6\xde\xc0\xdc\xdf\x2a\x29\x7d\xb1\xf0\x8a\x64\x43\xb5\xbb\x2f\xa8\xb0\xd4\x92\xd3\xb2\x2f\xc9\x6f\x17\x31\x40\x7d\x0a\x2e\x2e\x12\x4b\x91\xf2\x07\x6f\xd0\xf4\xc6\x61\x5c\xcb\xea\xe7\xce\x4d\xd7\x5e\xa5\xf1\x37\xa7\x06\x47\x89\xa2\x9b\x08\x2f\xd1\x42\x49\x06\x1c\xe2\x09\xda\x43\xd5\x96\x7b\xb7\x3d\x81\x96\x32\x61\xa4\x9d\x6c\x6d\x23\x32\x87\xe3\x91\x8b\x92\xb0\x05\xf4\x60\x91\xb2\xe0\x94\xe0\xf4\xf5\x52\xb1\x6a\xbd\x4c\x27\x61\xc9\x72\x55\x7e\xa7\x6a\xd2\x6f\xda\xf2\xb3\x04\x52\xab\x4a\x59\x07\x1c\xf3\xa3\x01\xfc\x37\xbc\xa4\x41\x1f\x9e\x00\x9c\x6e\xcc\x5c\x83\xe1\xe0\xb8\xb6\x9d\x58\xf6\x19\x8c\x03\xdd\x05\xf7\x98\xb5\x15\xd9\xae\xce\x42\x7e\x89\x56\x2a\x86\x78\x45\x6b\xe8\x40\xef\x8e\x5c\x07\x55\x73\x62\x6b\x3b\x26\x5b\x05\xe9\x91\x8d\x3c\x30\x8a\x5f\xa5\xd6\xad\xc3\x36\xd8\x7b\x29\xf3\xc7\xc3\xda\x97\xa2\xef\x36\x3e\x14\x76\x6f\xa1\x76\x0b\xae\x9b\xe6\xab\x73\x03\x45\xf7\x2d\xc7\x75\xd1\x8b\x72\x2b\x20\x41\xaf\x17\x4c\xeb\x82\xc9\xf9\x48\xff\x0d\x2d\x73\x5e\x4e\x04\xeb\xdc\xd0\xc1\x96\x6e\x4e\xc0\x6f\x2f\xe4\x18\xa8\x92\x66\xe1\x10\xdb\x9c\x6d\x97\x76\x39\x76\x4c\x07\x7a\x3c\x0d\x7b\x1c\xdb\xff\xe4\x2d\xf6\x8b\xc3\x24\x8e\x1e\xa2\xfb\x40\x54\x3b\x9d\xea\x96\x93\xe0\x8e\x84\xe6\x39\x77\x61\x19\x8c\xd4\x3a\xd5\x74\x37\x3e\x96\x7e\xa6\x41\xdb\xde\xcd\xcc\xa2\x46\x8f\x19\x51\x9b\xee\x24\xfd\x94\x5a\x46\xb8\xb6\x69\x77\xc0\xb6\x4b\xab\xa0\x76\xfd\x0f\x3d\xa3\x31\x8e\x29\x57\x3b\x85\x5f\xe6\xf3\x3f\x33\x86\x95\x28\xd7\xd9\xa3\x93\x70\x26\x1b\x1b\x45\x9c\xd7\x94\xdb\xf0\x8d\x2b\xf3\x27\xd2\xe3\x2e\xc2\x6f\x78\x63\x91\xcf\x29\x85\xd3\x9f\x6e\x23\x3e\xf7\xcf\x7b\x3d\xf4\x89\x1c\xc6\x14\xf7\xa3\xc9\x1e\x07\xb4\xd1\x44\xb7\x78\xcc\xa9\xef\xc4\x05\x3e\x78\xf8\x25\xa5\x4b\x28\xcd\xb9\x0e\x4e\x4b\x36\x4e\x38\x00\xc8\xb5\x65\x14\x54\xff\xe6\x7c\x32\x01\xc8\x39\x1b\x3d\xc0\xb8\x32\x1e\x41\xcf\x08\xe8\x2a\xae\xd3\xae\x81\x98\xfa\xbb\x5e\x95\x86\xda\xfb\xa0\xd0\x16\x96\x5d\x7a\x3d\xfc\x17\xc8\x21\x63\x82\xd7\xf1\xf3\x2a\x07\x86\xb6\x77\x5a\x9e\x09\x2a\x82\x07\x05\x2d\xef\x8c\xc8\x8f\x6e\x07\x68\x2d\x9d\x58\x49\xb1\x97\x63\x3a\x70\xbe\x88\x16\x95\x14\x10\xd5\x64\x42\x53\x59\x78\xfb\x5e\xe1\x7a\xfd\x0f\xf1\x01\x37\x24\x4c\x77\xd4\xf3\x53\x6f\xee\xa8\x10\x2a\x6a\x41\x0d\x0e\x2d\xe0\x92\x1b\x16\xcb\x19\xb0\x73\x3e\x63\x54\x0e\xfe\x90\xfe\x65\x54\xe2\x3f\x7e\x8f\x1e\x61\x54\x4d\x51\x89\xc9\xdc\x1e\xc1\x3c\x25\x65"

# get_exponent(Hi[i], XMR_H, i * 2)
_BP_HI_PRE = b"\x42\xba\x66\x8a\x00\x7d\x0f\xcd\x6f\xea\x40\x09\xde\x8a\x64\x37\x24\x8f\x2d\x44\x52\x30\xaf\x00\x4a\x89\xfd\x04\x27\x9b\xc2\x97\xe5\x22\x4e\xf8\x71\xee\xb8\x72\x11\x51\x1d\x2a\x5c\xb8\x1e\xea\xa1\x60\xa8\xa5\x40\x8e\xab\x5d\xea\xeb\x9d\x45\x58\x78\x09\x47\x8f\xc5\x47\xc0\xc5\x2e\x90\xe0\x1e\xcd\x2c\xe4\x1b\xfc\x62\x40\x86\xf0\xec\xdc\x26\x0c\xf3\x0e\x1b\x9c\xae\x3b\x18\xed\x6b\x2c\x9f\x11\x04\x41\x45\xda\x98\xe3\x11\x1b\x40\xa1\x07\x8e\xa9\x04\x57\xb2\x8b\x01\x46\x2c\x90\xe3\xd8\x47\x94\x9e\xd8\xc1\xd3\x1d\x17\x96\x37\xec\x75\x65\xf7\x6f\xa2\x0a\xcc\x47\x1b\x16\x94\xb7\x95\xca\x44\x61\x8e\x4c\xc6\x8e\x0a\x46\xb2\x0f\x91\xe8\x67\x77\x25\x1d\xad\x91\xf0\xd5\xd4\x51\xd7\xe9\x4b\xfc\xd4\x13\x93\x4c\x1d\xa1\x73\xa9\x2d\xdc\x0d\x5e\x0e\x4c\x2c\xfb\xe5\x92\x5b\x0b\x88\x9c\x80\x22\xf3\xa7\xe4\x2f\xcf\xd4\xea\xcd\x06\x31\x63\x15\xc8\xc0\x6c\xb6\x67\x17\x6e\x8f\xd6\x75\xe1\x8a\x22\x96\x10\x0a\xd3\x42\x06\xfc\xf4\x44\x35\x7b\xe1\xe9\x87\x2f\x59\xd7\x1c\x4e\x66\xaf\xdf\x7c\x19\x6b\x6a\x59\x6b\xe2\x89\x0c\x0a\xea\x92\x8a\x9c\x69\xd2\xc4\xdf\x3b\x9c\x52\x8b\xce\x2c\x0c\x30\x6b\x62\x91\xde\xa2\x8d\xe1\xc0\x23\x32\x87\x19\xe9\xa1\xba\x1d\x84\x9c\x1b\xb4\x46\xbc\x0b\x0d\x37\x76\x25\x0d\xd6\x6d\x97\x27\xc2\x5d\x0e\xfe\xb0\xf9\x31\xfc\x53\x7a\xb2\xbd\x9f\x89\x78\x21\x6f\x6e\xb6\xe4\x23\xfa\xe0\xd3\x74\xd3\x4a\x20\x69\x4e\x39\x7a\x70\xb8\x4b\x75\xe3\xbe\x14\xb2\xcf\x53\x01\xc7\xcb\xc6\x62\x50\x96\x71\xa5\xe5\x93\x73\x6f\x61\x13\xc3\xf2\x88\xec\x00\xa1\xcc\x2f\xc7\x15\x6f\x4f\xff\xa1\x74\x8e\x9b\x2c\x2d\xdf\x2f\x43\x03\xbb\xfe\x7f\xfc\xee\x5e\x57\xb3\xb8\x42\x06\xa9\x1b\xcf\x32\xf7\x12\xc7\x5e\x5f\xa5\x10\x87\x85\xb8\xcc\x24\x47\x99\x83\x12\xca\x31\xab\x85\x00\xc8\x2c\x62\x68\x45\x39\xa2\x70\x01\xfb\x17\xf2\xa5\x64\x9d\xb2\xe2\xd6\x4b\x6b\x88\xf0\xd6\x81\x00\x9a\xe7\x8e\xae\xce\x9c\x73\x57\x80\x2c\x6c\x1c\xd8\x1e\xf6\x24\x86\x89\x85\x40\x89\xaa\xd6\x94\x47\x33\x91\xba\xd6\x18\xef\x01\xdf\xd6\x80\x98\x1a\x78\x97\x18\xe9\xd7\xca\xef\x06\x3d\xeb\x2d\x67\x5f\xe8\x43\xea\x63\x4d\xcf\x96\x77\xc1\xd3\xee\x92\x51\x39\x71\xb7\x24\xc7\x88\xe4\x10\x7a\x42\x40\xfe\x26\xe5\xfb\x36\xcc\x00\x7e\x76\x58\x96\x48\x82\xf7\x69\xf1\x8c\x78\x6a\xb1\x52\xf2\x5c\x5d\x2a\xe4\x72\xf7\x1e\x40\x13\xc4\xb0\xc5\x78\x7d\xc1\xd7\x8b\xdc\x8d\x52\x33\x10\x39\xaf\x41\x24\x11\x2e\xe9\x34\x6f\x11\x0a\x4e\x81\x18\xe8\x64\x11\x5d\x49\xb0\x82\xc8\x38\x51\xd4\xd5\xe1\x10\xa4\xab\xda\xdd\xbd\xa9\xb0\x22\x7f\x5b\x26\xbf\x52\xd5\xa2\x25\x25\x23\x59\x72\x84\x3d\xe9\x1d\x99\xd0\x09\x1f\x17\xf4\x78\x2d\x4f\xeb\x2b\x76\x0c\xd5\x8b\x6f\x24\x76\xe8\xb0\x2d\x90\x8a\x15\x15\x07\x8a\xa8\x08\xaa\x3a\x56\x5e\xfc\xb7\x16\x9f\xe0\xcb\xf7\x2c\x12\xce\x17\x50\xf2\x86\x1f\xb6\xc6\x85\x16\x13\xcb\xe9\x74\xef\xc1\x68\x4a\xeb\xbe\x8b\x8a\x52\x2a\xbb\xe7\x82\x77\xd0\xda\xa7\x89\x2d\x9d\xa8\x7c\x27\xbe\xcd\x3e\xc0\x38\x95\x23\x3a\xd4\x66\x31\x8c\x44\x3c\x4d\x6d\x5c\xf1\x2e\xba\x7d\xbd\x3e\x84\x32\x9d\xf6\x1a\xfc\x9b\x7e\x08\xfc\x13\x32\xa6\x82\x34\x42\x73\x39\x6e\xc7\xdc\xdc\xbe\xae\x48\xff\x70\xa1\x9a\x31\xd6\x62\x44\x3c\xce\x57\xf7\x7a\xfe\x05\x0b\x81\x22\x48\x60\x25\x5b\xcb\xc8\xf4\x80\xc4\x3c\xfd\xeb\xb1\xb2\xa6\x89\x72\xb7\xd3\x32\x3b\x03\x61\xf3\xa1\x14\x2f\x8b\x45\x2e\x92\x98\x77\x3d\xef\x56\x35\xc2\xe2\xef\xa3\x70\x0e\x4c\xc9\xe5\xd8\xde\x78\x96\x7e\x57\x35\x82\xcf\x7c\x74\x97\x7c\x30\xb5\x46\x9b\x2c\x0b\xac\xe8\xec\x25\x9f\x71\xba\x25\xc8\xdd\x1c\x51\xe5\xb0\x24\x1c\xca\x7c\x86\xf7\x18\xb7\xd2\xc3\xd4\x57\xa6\xe5\xe0\xb3\x9f\x1f\x39\xeb\xaf\xbb\x08\x83\xd4\x27\xd9\x36\x47\x60\x15\xad\x88\xb7\x92\xa0\x31\xe4\xdd\x98\x37\x57\xc9\x9a\xea\x39\x12\xe8\xf8\xc2\xf6\x59\xde\x4b\xc1\xa2\x20\x4c\xea\x13\x2e\x4f\x9e\xf7\x17\x77\x11\x91\x53\x63\x9a\x71\xff\x24\x17\xf5\x22\xfe\x41\xb8\x7e\x9c\x1c\xb7\x66\x9f\x40\xf9\xd6\x85\x88\x7d\xff\x81\x92\x7a\xa4\x2e\xda\x7f\x2a\x69\x67\x89\x09\x10\x33\xcf\x5b\xe2\xfc\x1f\x5f\x3a\x2d\xe2\x27\x15\xeb\x33\xd6\x28\x28\x92\x2d\xac\x86\x2e\xfc\x7f\xc6\xd5\x4c\x99\xe6\xec\x6e\x58\xc0\xb6\x4d\xa9\x57\xe7\x36\xd3\x00\x93\xc8\x67\xa1\x20\xd5\xdb\xfc\x55\x03\xca\x27\x64\x05\xdf\x4b\x2d\xbe\x6c\xfe\x7c\x2c\x56\xbc\xd2\x66\x9f\x1b\x7d\x82\xc9\xf9\x29\x91\xbf\x41\x02\xaf\x61\x10\xbf\x1b\xf5\xbd\xae\x89\x7f\x9a\x06\x42\x09\xcf\x31\x29\x96\x53\x13\x7e\x86\x5f\x90\x5c\x89\x29\x44\x91\x39\x54\x5a\xc8\x25\x3c\x32\xbe\x19\xcc\x8b\xd8\x54\xca\x7c\xdb\x07\xc2\xae\xba\x12\xa1\x4c\xcf\xa3\x08\x5f\x9f\xfd\x9f\x75\x39\x80\xc9\xd4\x5b\x7b\x4e\x0f\x5b\xe4\x6d\xf3\xae\x5c\x10\xc1\x89\xf1\xdc\x9e\xd2\x59\x2e\x24\x6b\xd2\x44\x9a\xa0\xda\xae\x45\x8a\xe8\xbf\xbd\x52\xf9\x83\xc3\xde\x44\x12\x37\x26\x71\x9c\x08\xd4\xc3\x7c\x8c\x9b\x0b\xe1\x7b\x6b\x49\x82\x61\x36\xaa\x7b\x90\x85\x31\xbc\x91\x73\x2b\x08\x7a\x41\x36\x03\x0b\xad\x7b\x5b\x1c\xfa\x7d\x9c\x98\xa9\xdc\x34\x7a\x92\x65\x1f\x29\xc2\xe1\x10\xaf\xf8\x89\x7f\x26\x7c\x04\x22\x10\xa6\xb7\x0a\x31\x3c\xc0\x6a\xfa\x2b\xd9\xc2\x91\x15\x37\xd6\x09\xd6\x8b\xec\x94\x32\xe8\x4b\x96\x79\x52\x7d\x6a\xbb\x58\x8b\xa7\x2b\xb2\x14\x98\x70\x69\xd8\x0b\x0a\xbc\x2b\xbd\x68\xeb\xa0\x33\x1e\x3a\xe5\xf4\x10\x6f\x7f\xc1\xe2\xe7\xb8\xd6\xe5\x37\x0e\x32\x01\xcc\xe2\xa0\x36\xb6\x8e\xd3\x54\x31\x63\x39\xf0\x92\xde\xc7\x66\x2b\xce\xbd\xd2\x06\x61\x11\xd1\x6c\xe5\x5a\x93\x7e\x2c\x61\x90\x7b\xc3\x66\xc8\x85\xda\xa3\x74\x95\xbe\x67\x1e\xf6\xc2\xf2\xe5\x54\xed\xe3\xb5\x3c\xe2\x80\xcb\xe8\x8a\x48\xb9\xd9\x74\x0e\x98\x0c\xea\xf8\x04\xed\xcd\x8c\x96\x85\x81\x93\xe6\xd5\x17\x8b\xf6\x04\xcc\x73\xbd\x8f\xaa\xd5\x0d\x53\x15\x49\x99\x31\x97\xcc\x27\x28\x27\x21\x6d\x1a\xf9\xdc\xc6\xe9\x86\x2a\x6e\x53\xa0\xa2\xc7\x32\x98\xe1\xfa\xdc\x0f\x91\x48\xcb\xc8\x5e\xc0\x56\x7c\x38\x76\x9c\x27\x65\xd6\x54\xc4\x26\x9f\x6e\xf1\x39\x47\xf1\x3c\x23\x9c\xbb\x08\xb7\xcf\x67\xa2\x5b\xac\x03\x0a\xd1\xb8\x92\xc4\x34\x79\x24\x64\x49\xf5\x32\x8d\xac\x31\x41\xd3\xd7\xc8\xa9\xa2\x54\x0d\xca\xc2\xcb\xc9\x8e\x27\x84\x31\x43\xe7\xd4\xb9\x6d\xde\x75\x21\xfc\x70\xb3\x28\x0a\x2a\x4c\x5f\x39\x28\x7f\x5d\x24\xd7\xa7\x59\xea\x03\x7b\x11\x44\x87\x39\xee\x2a\x28\xfc\x4b\x16\x0e\xac\x40\x61\x08\xae\xe6\xb5\x80\x62\x13\x11\xfe\x03\x0b\xf0\x8b\x4f\x6e\xed\x3d\x7d\x3d\x86\x93\xd3\xac\x52\x4d\xa2\xb4\xeb\xf1\x9e\x25\x59\xdc\x50\xff\x35\xe6\x2d\xa6\x20\xdc\x0a\x02\xed\xcb\xe4\xf3\x98\xb1\xbd\x86\xea\x15\x4b\x6a\x94\x00\x57\x9e\x3f\x1c\xd5\x7f\xdc\x2f\x10\xbd\x8c\xdb\x16\x7c\x0b\x28\x3f\x90\x07\xe6\x20\xd9\xca\x28\x06\x7f\xe2\xb0\x15\xed\x65\x7c\x91\x53\xb8\x44\x3d\x77\xe8\xe2\x5f\xf3\x48\xf4\xdf\x78\xbb\xc1\xce\x20\xa7\xba\xbd\xe4\x0e\xd2\xbd\xbe\xaf\x2b\x5c\xd9\x8e\x52\x02\xba\xf7\xe3\xdc\xf1\x8b\xa1\x15\x62\x0c\x51\xae\x8b\x58\xb4\x92\x3b\x9a\x86\x94\xc9\x3d\xf6\x4b\x17\x8c\x4c\xd2\xf9\xf6\xef\xc5\x1f\x45\x8b\x0c\x5e\xe8\x60\xa4\x0a\xc8\xce\xc3\x50\x6e\xc8\x5b\x99\xdc\x71\x6b\x95\xcb\xb3\x42\xdb\x91\xad\xe4\xb6\x1e\x17\x7f\x60\xf9\xfa\xbb\xff\x2c\x9b\xad\xee\x04\xcf\xd7\x41\xd6\x6d\x2f\x26\x32\x1e\x2c\xf5\x0a\x3c\xd0\x21\xf6\x28\x88\x63\xde\x2d\xad\xf8\xd5\x2d\x1f\x8b\x9f\x51\x42\x43\x05\xa3\xd4\x07\x96\x29\x63\xc1\xd0\xbe\xeb\x81\x13\xf8\x03\x07\xec\xc2\x19\x23\x94\x7f\xe8\xcb\xaf\x5c\x2c\x05\xae\x63\x69\x85\x21\x99\xc5\x2a\x17\x97\xb9\xaf\xf2\xa9\x24\x5d\x7a\x8b\x91\x72\xd5\x72\xb4\x43\x2f\x63\x44\x1f\xf5\x1c\x4a\x4e\x27\x0e\x3b\x61\xea\xe6\xe1\x3e\xef\xe3\x5e\x85\x42\x7b\xc7\x58\xef\x4a\xf4\xc0\x0f\x9c\x77\x52\x1c\x03\x61\xd2\x99\x43\x1f\x9d\x8e\x29\x8c\x13\x41\x4c\x46\x17\x0a\x1d\x82\xa1\x38\x0f\xba\xfe\x53\x1c\xa7\x01\x84\xab\x89\x65\xc4\xc8\x07\x06\x0e\x80\x39\xfe\xc4\x61\x5e\x59\x09\xd2\x7a\xc5\xca\x80\x41\xe3\xf9\x5b\x27\xf1\xc3\xd4\xd4\x06\xa2\x04\x8b\x1e\x6c\xe1\xe6\x37\xcb\x87\xc0\xf9\x7d\x36\x17\xd4\x6a\xef\xfd\xd1\xe8\x13\xc2\x55\xfb\x8b\x3e\xf9\x39\xa2\xc5\xfa\xd4\xd1\x09\x73\xc0\x8c\x05\x5f\x79\x13\xc5\x16\x64\x58\x9d\xa5\x14\x5a\x9c\x59\x72\xf4\xb2\x12\xeb\xf5\x11\x71\xd9\x23\x43\x83\x3a\x08\x95\x3c\xd8\x0c\xd0\xd9\x08\x90\x4c\x56\x3e\xdc\x34\x29\x42\x21\x86\x56\x33\xd8\xcf\x6f\xf5\x04\x44\xb9\xd2\x9b\xeb\x05\xa4\x7b\x8b\xb1\x21\xcb\x11\x8d\x6c\xb1\x6b\x24\xc4\x45\x09\x8a\xa9\x0e\x6d\x5a\x10\xea\xe0\xa0\xf3\x97\x7a\x28\x08\xf7\x9c\xaf\xe8\xf8\x70\x52\x97\xbd\x91\xeb\xbf\x27\x92\xa1\x89\x2c\xb0\x09\xdb\x0b\x7a\xc3\x51\xd0\x35\x3f\x43\xfe\x3a\xa9\x71\x92\xe8\xb9\xd7\xfe\xf5\xba\xec\x41\x5b\x0c\xa4\x8c\x92\x0e\x7c\xdd\x78\xf9\x24\x6a\xd2\x54\xe8\x7e\xe1\xb0\x65\x84\xb8\x60\xb0\xb8\x80\x0a\xae\xe1\x78\x96\xf0\x29\x0c\xb7\x89\xb0\xd7\x9e\xcd\x7d\x04\xcd\xed\xa7\x10\xef\xa5\x5e\x76\xe4\x73\x14\x85\xba\x1f\xf8\x6a\x31\xfa\xad\xfa\xf5\x62\x8f\xbf\x17\x11\x34\x6d\x57\x32\x54\xba\x0f\x56\xb5\x38\xf7\x5b\x6f\xc4\x32\x17\x45\xed\x42\xa3\x19\xa8\xef\xb8\x68\xa6\xf3\x5a\x64\xa6\xc7\x44\xa6\x96\xc9\x1a\x61\x12\x5f\xad\x25\x92\x02\x02\x56\xfa\x8a\x61\x41\xa7\x4b\x9d\x49\x62\xde\xec\x53\xab\x75\x14\xca\x3a\xce\xde\xd5\x24\x99\x7a\x9a\xeb\x7c\x43\x0f\xbf\x01\xd9\x36\xfd\xc7\x6f\x55\xee\xcb\x74\x96\x32\x48\xdf\xb4\xa1\x5f\x71\xf7\xa9\x30\x35\x14\x3c\x8f\x42\xe3\x1a\xed\x71\xbd\xec\xd9\x53\x54\x24\xe7\x7d\x31\x48\x49\x1f\xf7\xe4\x63\xf6\x38\xa6\x2d\xad\x56\x95\xef\x93\x4e\x96\xfd\x5e\x21\x30\x4a\xce\x05\xc4\x2a\xf9\x86\x60\x77\x81\xab\x57\x66\xc1\x83\x83\x07\x1f\xe3\x5f\x16\xa5\x89\xd4\xe4\x81\xa9\x32\x21\x7c\x3b\xc5\x62\x8d\x67\x29\x3f\x50\xbf\xfe\x46\x98\x8e\xe1\x0c\x3e\x30\x58\x6c\x77\x45\x1b\xa7\x58\x08\x46\x4d\xc1\xac\x64\x50\x2e\x8f\xde\x87\xb5\xd3\xc8\x97\x7e\xe9\x0d\x63\x7d\x4b\x2d\xb9\x2a\xce\xd2\x0c\xdc\xaf\x5d\xa0\xad\x15\x4a\xdc\x68\x2d\xd7\x2f\x0f\x33\xbc\xf6\xbd\xcc\xe6\xfe\x17\x8c\x82\xca\x18\x3d\xce\x8c\x82\x37\xf9\xf5\x8f\x84\xb4\xb1\x08\xf7\x97\x85\x71\x08\x31\x17\x66\x84\x02\x97\xca\xcb\x0d\x7d\x2a\x28\xb4\x47\x55\x5f\x39\xa1\xda\x0d\xda\x87\x5e\x9d\x06\xe0\xa4\x8e\x2b\x63\x7a\x8f\xd3\x6f\x34\xe5\x6e\x30\x28\xde\xeb\x36\x36\xc1\x4f\x53\x87\xcc\x83\x2b\xee\xe7\xad\xd4\x1d\x8a\xbd\x1f\x6a\x50\x3d\xbf\x2e\xf9\xca\x55\xe5\xdb\x15\x9a\x02\x4f\xb4\x6f\xa8\x9c\x00\x32\x23\x30\xa0\xee\xc9\xd8\x67\x3a\x8c\xf5\x60\x0d\xb4\x77\xac\xae\xd4\xaf\xa2\x41\x13\x42\x9e\x21\x24\xda\x81\x07\xda\xe9\x46\x7c\x5f\x97\x6e\xb0\x1d\x36\xad\x57\x5e\xe4\x48\x6e\xbd\x2c\xa6\xb0\xd9\x34\xe1\xf4\xcd\x6e\xcc\x0f\x0f\x10\xa5\x44\x43\x88\x03\x15\xce\xb9\x7f\xcd\x3f\xa2\x09\x3d\xbe\xab\xef\xe5\xd4\x9b\xe6\x7e\xca\x9f\x4a\xf0\x2f\x64\xa8\x13\xc3\xa3\x75\xbe\x11\x50\xa2\x8c\x45\x27\xff\x67\x5d\xc0\x76\xf4\x4c\xe1\x9c\x6f\xa2\x81\x06\xb7\x97\xc9\xc0\xcb\x32\xc5\x90\xf7\x6c\xaa\xa9\x51\xa6\x70\x9d\xc3\x75\x26\xcc\xc3\x06\x16\x53\x94\x3d\x4b\x4f\xc6\x1a\xc6\x02\x2a\x63\xde\x69\x5a\xd2\x3d\x95\x26\x62\x9a\x6b\xf6\xff\x33\x82\xd4\xbe\x95\x49\x11\x27\x53\x1b\xb6\x9e\xa3\x69\x9c\xac\x5f\x21\xfe\x65\x2e\x10\x8e\xcc\xd0\x5d\x9a\x10\xc0\x42\x3f\x72\x2f\x97\x1c\x84\x1d\x0f\xe0\x2a\x82\xce\x3f\x65\xca\x23\xd0\xde\xde\x39\x26\x4b\xf2\x7f\x9c\x70\x52\x66\x36\xfa\x49\x3e\xbc\xe0\x6e\xd2\x90\x5b\xeb\x2d\x66\x32\xe8\x09\x7c\xc1\xc4\x6a\x48\x79\x33\xf4\x63\x30\xa0\x48\x58\x20\x21\xb0\xab\x0c\x6d\xf2\x4c\x54\x7b\x99\xe9\x8a\x19\xfe\xcd\x8d\x18\x67\xd9\x99\xf4\xf5\x9d\x7b\xca\x19\x13\xb2\xcf\x74\x6d\xd3\xbe\xa6\xec\x65\xb1\xed\xc2\x0c\xde\x46\xad\x02\xcf\x55\x59\x97\xf0\xb1\x88\xc0\xeb\x02\xab\x4c\x8a\xff\x11\xc2\x02\xc1\x9f\x16\x07\xcf\x2e\x8d\x64\xa7\xbf\x6f\x21\xc2\x4f\x1e\xb1\x25\xbc\xc6\x26\x4a\x35\xb7\x81\x72\xe4\xf9\xd3\x4b\x12\x0a\x36\xf2\x54\x9f\x6b\xac\xa4\x56\x85\x20\xb5\x7a\xe0\xd0\xb1\xce\x5d\x3b\x2b\x79\x32\xb8\x11\x0f\xae\xcd\xab\xb3\x64\x55\xeb\x5a\xd3\xec\x87\x5d\x16\x34\xf6\xc5\xb6\xb9\xa5\xb0\xd3\xa0\x32\x6a\x79\xc0\x34\x08\xb8\x18\xe7\x30\xe1\x9c\x22\xe9\xfb\xda\x0a\xd0\xee\xb7\x85\x19\x8e\x18\xad\x6e\x98\xe4\x44\xbd\xd5\xde\xda\x8c\xe9\x0b\xa9\xe8\xfd\x27\x6f\x4e\x13\x5a\xe5\xb2\x75\x1e\xc4\x0b\xf3\x5d\xb6\xc3\xd2\x75\x33\x8b\xb9\x59\xa0\x75\x0d\xe7\x00\xb0\x74\xab\xc4\x1b\x12\x6c\x69\x0c\xae\xed\x54\xa2\x96\xd9\x01\x22\xdc\xf4\x8a\x7a\x81\xe1\x3f\x40\x1b\x7a\x58\x52\x68\x58\x68\x39\xf7\xca\x16\x6a\x46\xf2\x98\x9b\x72\x25\x8d\xc8\x28\xc2\x3d\x40\xaf\x74\x9b\x4d\xb9\x45\xd3\xfa\xe8\x83\x3c\xcf\x22\xe5\xf4\xc3\xa2\xe9\xab\xf2\x27\xdc\x00\x4c\x1f\xc5\xe4\x96\x97\x65\x57\xed\xd7\x09\xd4\x1a\x7e\xd6\xaf\x6b\xe4\x8d\x7e\xde\x5e\x8e\x6d\xe3\x1d\x2f\xe8\x12\xd7\x77\xeb\x0d\x59\xa6\xe9\x15\x52\x20\xb2\x0d\xd8\xd4\x3a\xa3\xaf\x50\x99\x49\x3b\x25\xfb\xa1\x33\x7d\x4e\x79\xec\x2c\x10\xb4\x8f\xad\xbb\x4c\x93\xb9\x32\xe8\x06\xcb\x49\xd9\xfa\x17\xb1\xd8\x63\x17\xc0\x98\x03\x2e\x16\x46\x63\xc4\x66\x9a\xcb\xee\xb4\x38\x45\xdd\x2d\xed\x34\x1a\x5f\x05\x6b\x8a\x2b\x71\x02\xfe\xc1\x8c\xaf\x25\x04\xbc\x37\xc0\xd4\xc9\xb3\x8f\x1b\xf3\x62\x38\x1e\x13\xa5\xa3\x93\x9a\xe3\x06\xe8\x21\x62\x0d\x07\xa9\x00\x88\x01\xe9\x69\xad\x40\x86\xc1\x11\xa6\xa1\xfb\xd2\x29\xb8\xfd\x06\x09\xcf\xd0\x8a\x01\x9c\x0f\x46\x38\x2a\x7a\x91\x89\xe2\x96\x8f\x00\x12\xb7\x0f\xc7\x73\x45\x1c\xed\x06\x5c\x0f\x80\x48\x17\x1c\x0f\x5d\xfc\x96\x5b\x22\x60\x53\x0f\xb0\x50\x47\x5b\x00\xea\x42\xcf\x37\xf0\xd4\x28\xe0\x1e\x76\x1f\x17\x29\x29\x4f\x07\x0e\xaa\x8e\x15\x5e\x2e\xa0\xd9\x6c\x96\x54\x81\x8a\x6e\x5f\x15\x23\xac\x3b\xd8\x7b\xf2\x56\x34\x86\x1d\x6a\x9e\x28\x6a\x3f\xa3\xfb\x26\xaf\xb4\xe5\x54\x45\x85\x31\x9c\xf0\x23\x08\x73\x07\x16\x91\x5e\x70\xb3\x67\xb2\xba\xa9\x50\x2c\xb7\x1d\xe0\xcb\xc4\xc4\xde\xab\x33\xc4\xb9\x81\xd8\xf8\x0c\x95\x5d\x9e\x0d\xaf\x9b\xb6\x1b\x05\xb4\xc7\xe5\xe1\xf9\xa8\x09\x36\xd3\x4b\xb8\x64\x57\x59\x26\xe7\x46\xd7\xd3\x4e\x76\x71\xe0\xb8\x24\xb1\x8e\x7a\x31\x61\x67\xee\xc9\x87\xf1\x4b\x95\x5e\x35\x7f\x99\x1c\x89\xd2\xfa\xfa\x2a\xc6\xdb\x87\x6c\x7f\x35\x7f\x06\xe4\x82\x36\x5e\xe9\x1c\x15\xa9\x23\x95\xa1\xa7\x63\xa1\x3b\xff\x1a\x36\xde\xd2\x10\xc6\x1f\xc7\xac\x8c\xf4\x44\x8d\xbb\xb4\x93\x5e\x84\x0b\xc6\xbf\x11\x3f\xd2\x43\xbd\xf8\x74\xac\x91\x64\xa3\x14\x31\xcc\x4d\xaa\xf5\xc0\x3d\xb9\xbc\x80\xd9\x1e\x4f\x2c\xaa\x8c\xec\xe5\x8d\x41\x5f\x26\xb0\x03\xbf\x5b\x74\xa1\x7d\x8b\x8e\x52\x9a\x64\xe4\x14\xd0\xbd\x88\x49\xa6\x2a\x88\x45\xe7\x51\xcc\x3c\xba\xa4\x21\xc4\x67\x90\x0e\x52\x99\x0c\x35\x86\xda\x11\xab\x33\x77\x2d\x9e\x13\x44\x6c\x71\x4c\x66\x78\x00\x4d\x72\x5e\x02\x87\xda\xad\x19\x6d\xa1\x23\xab\x11\x38\x60\xce\x49\xf5\x0b\x12\xe6\xdf\xaf\xa0\xc0\xa8\xce\x79\x9c\x8c\x40\xd1\xe6\x8d\xef\x09\xec\x1d\x62\x63\xe5\xe8\x52\x08\x77\x28\xd5\x50\x8e\xdb\xbe\x17\xa3\x76\x87\x13\xa4\xb7\x5e\x49\xd6\x99\xd8\x30\xc7\x59\xcc\x83\xd5\xa8\x95\xe9\x6e\x42\xdd\x26\x8f\x0b\x7c\x14\x73\x3d\xba\x87\xb1\xa9\x47\xe3\xc0\x0e\x7e\x22\x8b\x63\x07\x06\xd4\x62\x93\x88\x9e\x9f\x53\x9b\x58\x93\x3b\xbd\xea\x70\x8c\x30\x10\xc1\x8a\x01\xb4\x5e\xb0\x3e\xa5\x06\x37\xb7\xb3\x3a\x07\x9f\x3c\x73\x06\x09\xab\xa4\x20\x12\xcd\xab\x7f\x79\x11\x17\xf6\xdb\xe4\x3d\x1a\x6f\x06\x1e\xee\x27\x0f\x3e\x4e\xc2\xfb\xfd\x7c\xab\x58\x45\xff\xdc\xa3\xd4\x5c\x5d\x3d\x99\xda\x7d\x74\xe9\xb5\x55\xa6\x59\x7c\x43\x72\xe1\x79\x61\x6c\x36\xdf\xe9\xcc\x48\x7a\x97\xa7\x9b\x6f\xf0\x2a\xa8\x12\xa6\xad\x55\x37\xba\x99\x15\x35\x03\x25\x4d\x00\xe2\x33\x53\xc6\x0a\xf1\xe1\xc4\x8a\xac\x02\x38\x17\x6d\xff\x63\x73\x04\x73\x35\xaa\xd4\x16\xae\x20\x50\x59\xef\xf6\x67\x14\x8d\xe2\x9d\x2a\x6d\x24\x42\xd7\x76\x1c\x91\x9b\x3d\x11\x07\x30\x4a\xa6\x54\x0a\xf0\x55\x20\x70\xd8\x3e\xa5\xe3\x49\xc3\x6e\x80\x2c\xbc\x05\x35\xdb\x5c\x55\xa0\x3c\x10\xe3\xd5\xc5\x61\xa4\xb7\x1f\xcb\x25\x03\x0f\x04\xfd\x00\x5d\x31\xfb\xe2\xc4\x89\x96\xc6\x28\x5b\x74\x3d\x8d\x62\xb1\x3b\x7f\x58\xb9\x2f\xf3\x9e\x58\xe7\x04\x4a\x8d\x39\xa0\x69\xb4\x3a\xbe\xe2\x59\x2e\x28\x71\x81\xb0\x17\xeb\x2b\x91\xa8\xb1\x48\xbd\x71\x3b\xd6\xe1\xc5\x2b\x2f\x08\x8e\x38\xec\xe1\xdc\x9c\x0f\x92\xe9\xa5\x39\x65\xa0\x8f\x19\x5e\xb5\x1a\x74\x36\xc1\x2a\x68\xd6\xc6\xee\xec\xe2\x6f\xc8\x32\xc8\x51\x81\x51\x39\x78\xfc\x4d\xa4\x63\x61\x8b\xda\x41\x27\x37\x03\xb2\xee\x10\x7c\x3c\xf0\x24\x55\xcc\x32\xc4\x4b\xc1\x8a\x7a\x1b\xb4\xf6\xf3\xff\x6f\x7d\x03\x89\x6f\x6c\xea\x1a\x8f\x5b\x1b\xf7\x49\x68\x69\x44\x7b\xaf\x5f\x8f\x34\xb8\x75\x30\x0a\x6f\xc7\xde\xb9\xf4\x67\x29\xc8\x36\xaa\xb0\xfc\x82\xb3\x24\x1b\xde\x63\x4b\x3b\x95\x78\xf8\x0f\x08\x4b\x8f\x17\xcb\x85\xee\x39\x2a\x79\xec\x92\x8a\x6a\x57\xd1\xba\x9a\x64\x8a\x00\x9f\x21\xbb\x21\xc1\xf3\x59\x68\xe9\x70\x46\x13\xa0\x9c\x53\x5a\x27\xb6\x7b\xb6\xd8\xdd\x3b\xff\xe2\xdb\x01\x10\xce\x90\x8f\x24\x70\x0b\x31\xc0\xdb\x03\x1c\x50\x98\x43\x41\xc3\xe2\x51\xf3\xea\x2d\x5b\x81\x35\xd1\x81\xd2\xb6\xd2\x62\x60\x93\x5d\x70\xe3\xcc\xf6\xa2\x2b\x54\x0f\x5c\xac\x73\x05\x91\xe0\x8c\x72\xa2\x05\x69\x8c\x9b\x2d\x3c\xf9\xa0\x4d\xf9\x94\x1c\xb4\x85\x45\x4e\xac\x12\x14\x24\xd7\xfe\x86\x56\x82\xd3\x82\xaa\x31\x1b\x38\x56\xdc\x28\x9f\x91\xf4\x5e\xef\xe0\xb8\x19\xd5\xdb\x86\xe8\xac\x5e\x8b\x54\x7e\xa2\xbe\xbf\xb8\xac\xf1\xbc\xa2\x92\xac\x1c\x84\xb6\xa3\xa3\x28\x30\xc8\x4d\xd5\x45\x14\x75\x74\xf6\x97\x8c\x04\x62\xc2\xcf\x43\x90\xe8\xe5\x94\xf1\xcf\x0e\x3c\x58\x28\xfa\xfd\xdb\x4b\x8a\x36\x82\x3d\x1c\x38\x9c\x30\x4f\x9c\x20\x5f\xda\x6a\x7e\x88\x44\x7e\xd4\xe0\xdb\xfc\xc6\x81\xb5\x86\x0b\xe0\xed\x2e\x90\x99\xc3\x0b\xfc\x57\x9f\x1a\xfb\x04\x94\xa0\x1e\xc1\x98\x88\x3f\xc2\x1c\xea\xcd\x14\x8d\x5b\x21\x1a\x87\x2f\xb3\x63\xb9\x9a\x4b\xf0\x86\x43\x02\x9d\x4c\x2f\x2c\xa1\x53\xe5\x6e\x91\xe8\xb3\x72\x75\x54\xcf\xb9\x1b\xba\xcb\xb1\xc8\x5b\x18\x18\x38\x36\x13\x58\x47\x32\x6b\xe6\x96\x29\x56\xd3\x5e\x4b\x47\xcf\x15\xd6\x26\x26\xf7\x4e\x89\x78\xea\x80\xe0\x40\x3e\xf5\x3a\xd1\xac\x48\x64\x2e\x3f\x25\x6d\x82\x66\x8c\x47\xd5\x05\x17\x5d\xdb\x7f\xdd\x83\x9a\x91\x41\xa3\xf0\xd9\x1a\x71\x51\x7a\x36\x39\x6e\x9e\x3c\x20\x55\x99\x58\x44\xdf\xed\x40\x96\xc6\xec\xd9\xfc\xef\xe1\x40\x57\x83\xe8\xa6\xd8\xc1\x86\xc9\xd4\xa6\xc9\x2d\xf7\xd2\xc6\x08\x16\xf7\xba\xbc\x34\x5c\x2e\x79\x1a\x88\x11\x39\xf4\xd7\x4c\x5d\x43\x0f\xa2\x4b\x1f\xbe\x95\xb8\x23\x7b\xce\x02\x61\x5a\x19\x27\x98\x83\x75\x3d\x41\x6d\xa9\xdc\xd5\x1a\xc6\x1b\xef\x11\x29\xf5\xc8\xd0\x6f\xba\x4a\xfa\x2a\x4b\xc7\x5a\x72\xfa\x34\xfc\x7c\xcb\x1e\x91\x09\xb0\x2b\x1d\x00\xd6\x18\x78\xc7\x14\xb0\xde\x7e\x1a\x1c\xba\xac\x36\xe6\x6c\xb5\x9f\xb3\x0e\x38\x5c\xee\x9c\xb9\xd4\x88\x2b\x40\xad\xaf\xee\xc9\xb4\x61\x87\x51\xbd\x2f\xd2\xdb\x07\xb6\x4d\x42\xcf\xd8\xf6\x73\xdc\x25\x75\x12\xfd\xd8\xf8\x62\x7b\x6a\x67\xa6\x81\x5c\xf9\x41\x31\xa2\xf0\x44\x96\xd6\xae\xd9\xed\xfd\xc9\xc3\xde\x43\x59\x46\x91\xaf\x23\x42\xd8\xb0\xc3\x7e\xb5\x26\x76\x42\x1a\xe9\xfc\xf6\x84\x57\x8b\x3f\xd7\xfb\x1b\x3e\xe0\x1a\xd5\xb2\x71\xdd\x6b\x72\xe0\x92\xf7\xfb\x99\xe7\x5c\xb8\x2d\x59\x94\x7a\x65\x70\x5a\x1a\x5e\x64\x0c\xe1\xd7\x82\x45\x0d\x2e\xa4\x9d\x4d\x80\xf1\xbb\x9e\xb0\x1c\x8c\xcc\xf2\x66\x50\x8b\xfe\x01\x24\x67\x59\x69\x1b\x03\x22\x34\x2e\xbb\x5d\x28\x66\xd5\x2d\x09\x89\xb5\x4f\xcf\xef\xc1\x07\xda\x24\x48\x5f\x83\x75\x1d\x2b\x72\x5d\x82\xde\x16\xa6\x2a\x04\x08\x30\xee\x01\x2f\x6c\x20\x88\xd9\x88\x24\xf7\xaa\xa7\x1e\xda\xd0\xa9\xe6\x8a\x33\x3b\x86\xd0\x10\x54\xba\x9c\x79\xda\xa7\x8c\x73\x33\xab\xb5\xc5\x6c\xf7\x7a\x13\x9b\x5e\x85\x6a\xa2\xe9\xfd\xf7\x8e\x5d\x35\x5e\x6e\x82\xab\xb1\x08\xbd\x4c\x2a\xd7\x32\xca\xaf\x6e\xfa\xe2\x39\x85\xb2\x4d\x6a\x4a\x02\x16\x63\x3f\x5e\x97\x0f\x16\x57\x3c\x15\xfa\x2f\xad\x51\x1e\x09\x1e\x4d\x5f\x8e\xf7\x14\xec\x22\xbb\xe6\x82\x9e\xf9\xf6\x04\xb1\x2d\x03\x2c\xcc\x1f\x5a\x3a\x83\x25\x5e\x77\x8a\x8d\x90\x02\x68\x66\x66\xf6\xde\x05\x1c\xd1\x20\x7e\x7a\xf6\xe8\x1c\xa9\x96\x39\xcd\x64\x82\xa1\x3a\xc4\x89\xd1\xa2\x5a\xca\xd6\x18\xc5\x70\x87\xab\x02\xf4\x81\xca\x50\x12\x6c\x92\x25\xdd\x0c\x37\xc2\x93\xae\x3b\x50\x15\x5c\x72\xfb\xaf\xe5\xa5\xc2\xd0\x45\xc8\x80\x0a\xaf\x0e\xa9\x4b\x89\x85\xf3\x1c\x25\x53\x8f\x73\x0d\x33\x91\xa2\x36\xa7\xd9\x08\xbf\x00\xd7\xdd\x97\x3a\x8b\x64\xc4\x34\x09\x4e\x04\x5d\xf9\xf9\x63\x50\xef\x5f\x86\x84\x3a\xfd\x10\x98\xbb\x6c\x8d\x7b\x59\x37\x53\x79\x0c\x30\x19\xd2\x7d\x3b\x9f\xe8\xe8\x6d\x1f\x95\x8d\x4b\xdf\x15\x14\x87\xa5\xbe\x3d\xfd\x74\xf5\xa3\x98\x0c\x76\x48\x94\x26\x90\x2a\x2d\xdf\xb4\x21\x66\x9c\xe2\x7b\xa3\xdb\xfd\xe4\xa4\x91\x5c\xd0\xd1\x43\x01\x55\x16\x4d\x37\xea\x70\xb1\xf4\x30\x27\x59\xda\x61\x1d\x6d\x62\x32\x83\x5d\x20\xd5\x0e\x7e\xa4\x42\x43\x5e\xea\x8c\x76\xd6\xa2\xee\x93\x4b\x7b\x86\xb4\x61\x1b\x72\x52\x71\xde\xb8\x88\x05\x00\x2c\xad\xde\xf5\xe6\x8c\xaa\x08\xa3\x02\xab\xe3\x6a\xf1\xa2\x64\x5a\x24\x08\xe2\xf3\x89\x9e\xcd\x19\x79\x1f\x54\xa0\x91\xef\x99\xe4\xf8\xfd\x1e\x7b\x37\x26\xfe\x56\xb6\xc4\xf4\x9f\x5a\x0d\x42\x6d\x8e\x81\xc0\xc8\xb8\x44\x85\x37\xbc\xe5\xa1\x9c\xff\xe5\x41\x4c\xc1\x9e\xcf\x15\x7d\x66\xbb\x39\xaf\x6c\x3a\xe1\xec\x25\x4a\x5d\x72\x65\x5c\xba\xa4\x26\x81\xab\x44\x7f\x06\x7e\x2e\x6d\x68\xf9\xb7\xaf\x80\x21\x18\xf5\x38\xd8\x50\x08\xaa\x6b\x96\x8c\x3d\x27\x87\x32\x2f\xf0\x71\x09\x89\xc6\xdb\x4d\xbc\x13\x72\x06\x91\x8c\xb5\x3b\xe1\x6d\xea\x6c\x86\x35\x41\x2e\xb0\xd7\x84\x20\xdd\x43\x2f\x83\xc2\xf2\x4d\x67\x2d\x85\x98\xf0\xab\x88\x87\x65\xee\x41\x33\xcd\xaa\x5c\x9f\x58\x4a\xb1\xd2\x43\xf4\x54\x5f\x37\x58\xbc\x49\x94\x41\x28\x61\xac\x9d\xde\x12\x46\x1c\xd4\x4c\xae\x83\xd2\x19\xfb\xb4\x70\xaf\x4a\x76\xa6\x74\xfe\x37\x9c\xfc\x98\x64\xb1\x8e\xd1\x28\x4d\xb2\x4b\xf5\x44\x61\xfe\xc7\x43\xbf\x4f\x3e\xb5\x2a\xaa\xc0\xbc\xb8\xee\xa5\x61\x8a\x2b\xb4\x41\xcf\x65\xcb\xd5\xf5\xce\x47\x02\x4a\x3a\xd6\xc7\xd3\x07\x33\xee\x0d\xfb\x2b\x4e\x91\xce\x96\xda\xcc\x4e\xc8\x9f\xc9\x6b\xa3\x77\x01\x25\x48\xf9\x21\x5b\x0a\xaf\xc3\x0a\xc3\xc1\xb1\x70\xaf\xf9\x37\x26\x57\x13\x26\xeb\x96\x41\x58\xb1\x56\x59\x01\x55\xda\x48\x25\x4e\xc2\x6c\xe9\xb3\x3e\x65\x88\x4b\x42\x01\x98\x40\xd0\xdd\x0e\x99\xc6\x13\xb3\x4b\xa4\x9c\xb6\xec\x37\x8b\x22\x71\x81\x1b\x48\x28\x9b\xf7\xe5\x66\x28\x8e\x2a\xa9\xff\x75\xfd\x22\xfa\xca\x62\x2a\x84\x32\xd7\x65\x96\x94\x90\xca\x77\x81\xaf\xc7\x83\x77\xd0\x51\x26\x7d\x61\xb1\xfb\x50\xff\xea\xcc\xc8\xb1\xfa\xcb\xb4\x7a\x9e\xa9\x78\xd7\x3c\x16\xb7\x0c\x96\x06\x06\x50\xf7\x63\xef\xc8\xdd\xb9\xac\xfd\x5a\xcb\x9c\x57\x4c\xaa\x11\x1d\x6b\x67\xb0\x9e\x64\xf5\xe5\xaa\xa5\xda\xb2\x2d\x25\x69\x2a\x34\x27\xa7\x8c\x40\x7c\xd0\x50\xee\x8d\x16\xf3\xdf\x31\x8f\x23\xfb\x62\x90\x42\xfb\x99\x8a\x88\xa9\x9f\xe6\x1b\x13\x36\x54\x40\x76\x25\x01\xb3\x08\x76\x9b\x83\x45\x1b\xf3\x5c\x56\x4b\x23\x50\xdf\x06\xc6\x92\xf6\x1d\x52\x03\x05\xc1\x64\xbd\x5a\x03\x02\xce\x9f\x7c\x4e\x3f\x8f\xb1\x2f\x76\x9d\x9a\xfb\x57\xeb\x23\xf4\x98\xff\x74\x4e\x41\xe9\x11\x14\x42\xb4\x2d\x6a\x86\x86\xee\x2b\x73\x36\x67\x0d\x33\xfc\xa0\xee\xb1\xd1\xe8\xa7\x45\x8b\xe5\x84\xab\xd5\x2b\x59\xd7\xdc\xc6\x9a\xaa\x49\x79\x47\xcc\x48\x64\x8f\xae\xd2\x41\xcf\x57\x3e\xe4\x7f\xc5\x2f\xef\x4a\x3c\x06\xf9\x4d\xe1\xaa\xd1\x45\xb4\x58\xbc\xd8\x74\x48\xc3\x74\x16\xeb\x1c\x3c\xa8\x98\xeb\xa5\xb8\x7f\x6b\x4c\xd7\x83\xd6\x07\xd0\x23\xb7\x50\x12\x38\xbd\x4f\x40\xf5\xba\x8d\x21\xd3\xe7\x1a\xa7\x5d\x49\xf9\xfa\xa9\xfc\xec\xe7\x5d\x1e\xb5\xa7\x64\x13\x95\xc1\x3c\xda\x18\x98\x07\xb0\x73\xf3\xb3\x8f\xb0\x6e\x54\xb3\xbf\x5b\x3d\x72\x60\xff\xcb\xca\xdc\xcf\x4f\xf9\x93\x6a\xbc\x79\xc3\x2f\x01\xb5\x77\xc3\x76\x6e\x12\x1b\x68\x0b\x3b\xde\x82\xbd\x70\x3a\x6a\x95\xf9\x7b\xba\x36\x9b\xbb\xb6\xfd\x82\x56\xbb\x01\x75\x83\x18\x0a\x81\xf8\x87\x80\x74\x12\x64\x1c\x7a\x3a\x5e\xfb\x1a\x92\xf8\x77\xcf\xab\x21\xba\x2d\x34\xf1\xe4\x7e\xa4\x72\xc6\xc9\x05\x89\x4a\xd0\xbc\x58\xd4\xfe\xfd\xb1\xdc\x71\xe5\x05\x00\x43\xb3\x5a\x36\x69\xe8\xdd\x13\xdc\x70\x32\x29\x10\x80\x20\x14\x0b\x01\xed\x2a\x72\x0e\x27\x1b\xd3\x0a\xe7\xf5\x33\xda\xad\x1a\x02\x25\x9b\xae\x7e\x71\x08\x95\x2d\xad\x85\x4b\xcc\x90\x6a\xb5\x60\x04\x8d\xae\xc7\x58\x4c\x0e\x4f\x69\xe4\x97\x9c\x1d\x65\xd5\x80\x5e\x4d\xc7\x60\x66\xdb\x0c\xe0\xbd\xfb\x19\x50\x21\x82\xcf\xed\x5b\x0f\x05\x60\xa6\x0f\x10\xd0\xf1\x43\x92\xe5\x5f\x63\x77\x46\x75\x27\x23\xe2\x4a\x7e\x40\x35\x0c\x25\x38\xdc\xd9\xe4\x92\xbe\x99\x71\x2c\x63\x0b\xb5\xf4\x98\xeb\x71\x95\x7e\x01\xb6\x2b\x5c\x37\xf1\x1d\x2d\x07\x00\x37\x38\xf4\x5b\x7f\x45\xd5\xb6\x18\xfa\x51\x73\xf1\x44\x1e\xaf\x3f\x00\x20\x8d\xe6\x0c\xae\xf7\x33\xaf\x14\x61\x1a\x89\x55\xf0\x4c\x44\xf9\x38\x74\xca\x17\x7e\x28\x86\xd3\x95\x13\xbd\x94\xd8\xff\x6f\x02\x35\xe5\x52\xa1\x89\x16\x30\xd6\xee\x22\x79\xf1\xe4\x6a\xe5\x46\x61\x7a\x29\xb8\x2e\x9f\xa7\xf0\x93\xf8\x45\x36\x02\x69\x1d\xb6\xd2\x3f\x70\xcc\x61\xd3\x4d\x73\x25\xb0\x15\xc1\x54\x30\xe1\x4e\xa8\x0f\x7f\x52\xf2\x37\x66\x1d\xa7\x59\x8f\x0c\x71\x18\xa5\xb9\xb4\xda\x4f\xd8\xf5\x1e\xc7\xf3\x54\xa8\x0a\x5f\x98\xe9\x82\x73\xa3\x53\x72\xbc\x63\x04\x47\xfc\xfe\x9f\x43\x63\xad\x05\x82\x4f\x64\x28\xff\x9b\xa6\x0b\x4f\xec\x62\x42\x67\xd4\xf6\x8b\xf9\x62\x37\xcd\x25\xed\x94\x0d\x10\x00\x8a\xa5\xdc\xb9\x4d\x91\x63\x68\x82\x6d\x4d\x9d\xc8\x1c\x60\xa1\xf4\x1d\xd9\xda\x7a\xde\x58\xaf\xdf\x1b\x49\x35\x7b\xe1\xcf\x67\x34\x02\xab\x99\x15\x99\xfc\xa1\xc0\x71\x4f\xe4\x43\xae\xbb\x5e\xf3\x29\xb5\xff\x5d\x19\xe4\x2c\x8e\x51\x24\x27\x92\x1b\xb4\x40\x32\x50\xcd\x5b\x1b\x09\x1d\xf1\x0a\xe0\xbc\x7c\x34\x44\x23\x6a\xb5\x4f\x49\x29\x89\xb4\x07\x13\x95\x4d\x59\x3a\xa2\x7a\xa0\xb1\xfb\x14\xe8\x9b\xc7\x96\xd1\x04\x5c\xf4\xf0\xfb\x83\x49\x88\x06\x86\x0e\x7f\x54\x10\x65\x95\xcb\x7a\xef\x4b\x81\x97\xc6\x36\x73\xbc\x01\xe9\xa7\xd2\xbd\xff\xcb\x07\x86\x00\xab\x5c\xd0\x00\x9e\xa1\xdc\x68\xa2\xa8\x24\x3f\x57\xaf\xdc\xf6\x65\xf6\x7d\x7a\x05\x68\xc8\xa8\x43\x53\x56\xee\x90\x46\xb6\x5b\xac\x0c\xd1\x0c\x78\xc9\xb2\x6a\x77\xba\x53\xcf\xdc\x7d\xdd\x99\xdf\xa4\x45\xdf\xca\xf3\x45\x2c\xb7\x22\xb4\xbb\x6c\x05\x03\xad\x5e\x86\x31\x93\x53\x72\xab\x96\x48\x42\x7a\x32\xea\x8f\x7a\xea\x9c\x94\xf2\xd7\x1b\xb9\x59\xcd\x63\xda\x6f\x9b\xe0\xe2\xd8\xc8\x1b\xb2\x12\x3e\xa8\x8a\x51\x08\x9e\xb4\xde\x60\xd4\xa4\xf6\xe9\xb8\x55\x48\xc0\x47\x4a\x86\xf1\x1f\xa7\xb5\xa7\x77\x18\xf2\x2b\x3b\x9e\xf7\xbb\x4d\x74\x82\x6c\x77\xaf\x84\xb2\xa5\x49\x1b\x7d\x9c\xbd\x87\xc7\x45\xe4\xb2\xf4\xd6\xe0\x54\x88\x64\x66\x8e\xaa\x76\xc0\x14\x4c\xed\x60\x19\x68\x67\xee\xaf\x93\x52\xf6\x7c\x1d\x31\xc6\x70\x9d\x9d\x16\xf2\xa4\xd4\x65\xba\x19\x48\x71\x54\x15\xdd\xe4\x73\x00\x92\xdf\x2a\x6a\x91\xd1\xa4\x82\x67\x36\x09\x19\x92\xd8\x00\x6c\x50\x4f\xae\xdb\x68\x4e\x5d\x46\xfd\xc6\x25\x0b\xc9\xac\x5c\x81\x6b\x0d\xb2\xc2\x5e\x8a\xf5\x2d\x95\x8b\x3e\xf6\x32\x83\xbf\x6c\xb4\x16\x06\xbf\xb6\x8b\x77\x01\xfc\xda\x7c\x8e\xdb\x5b\xd2\x10\x0d\x77\xe6\x59\xb2\x48\xec\x83\xd0\xb9\xdf\xd8\x8c\x43\x7c\x0d\x36\x48\x1c\x08\xc0\x8e\x92\x1f\x4f\x04\x39\xa4\x31\x69\x0c\x8f\x44\x84\x48\x1c\xc6\xf5\xea\x28\x18\x9e\x2a\x5c\x97\xe9\x9e\x90\xe6\x93\xcb\xa4\xdc\x7c\x22\x91\x45\x31\x23\x32\x3f\xc5\x0a\xfb\x92\xda\x8c\x29\x66\x5c\xac\xd2\x02\x35\x01\x1f\xa9\x49\xce\x0f\xb9\x83\xbc\x0e\x17\x36\x17\x5e\x3f\xbe\x7b\x2d\x28\xcb\x1b\x45\x79\xa4\xce\x88\x7c\xc3\x21\x3c\x48\x65\x5c\x30\xc4\x56\x95\x7a\xe2\xa6\xad\x59\x0a\x90\x6c\x0d\xc0\xe8\xa3\xde\xe5\xaf\xa0\xf8\x2a\xdf\x07\xc2\xae\x01\x04\x94\x21\xae\xdf\x59\x26\x5c\x9a\x2c\xe5\xcf\x91\x65\x86\xe0\x89\xa4\xba\x9e\xeb\xdf\xfd\x24\x36\x91\x4b\xdd\x04\x5d\x6b\x59\x53\x47\xe7\xda\x43\x81\xda\x75\x84\x9d\x61\x79\xd2\x1e\x38\x4b\x72\xa5\x53\x90\x0a\x29\x64\x52\x41\x1f\x99\x04\xd5\xfa\x8e\xd4\xf9\xf9\x99\x6f\xcc\x5c\xf7\x66\xb0\x15\x92\xd3\x07\xc3\x2f\x2c\xe7\x48\xd0\x58\x4d\xbf\xa6\x08\x3d\xf8\x60\x2a\xbe\xef\xa7\xa8\x10\x3a\x90\x21\xe2\x43\x0c\xc1\x57\xf4\x3f\x58\x2b\xc4\xb6\x9e\x3e\x3f\x30\x10\x1c\xfe\xee\x95\xa4\x12\xeb\xd7\x97\x07\x29\x23\x2b\x31\x61\xd1\x0a\xec\xfb\xd0\xa3\xaf\x3b\x63\xc6\x29\x79\x21\xb4\xbd\xf5\x5d\x60\x0e\x60\xaf\x39\xf1\x85\x63\x08\xd4\xd6\xf0\x71\xe2\x66\x56\xbd\x19\xc9\x64\x13\xa2\x78\x8c\x3f\xf2\x38\xa1\xbe\x89\x4e\x41\x29\x04\x48\xe4\x69\xc5\xdf\x5a\x0a\x2a\x63\xa9\xc1\x95\xf1\x2b\x36\x3b\x68\x45\x75\xa0\x76\x46\x66\x36\x18\xf4\xd9\xb7\xe8\x8a\x95\x12\x43\x34\x5d\x46\x14\xb5\xa4\xe1\x6f\x31\xdf\xc4\xfe\x64\x15\x80\xa8\xcd\x88\x12\x7e\xbd\x71\xdb\x65\xf5\x90\x97\x84\x32\x04\x81\xd7\xa8\x55\x14\xe9\x36\x23\x6f\x4c\xbe\xba\x74\x74\x0d\x22\x78\x93\x9b\x5a\x87\x1a\x72\xc8\x80\x19\xc2\x08\x39\x0e\x51\xce\xec\x46\xd1\x4d\x03\x88\xe0\x61\xa2\xd8\x4f\x58\x02\x8a\xad\x0a\xab\xfd\xe8\xba\xf0\x8a\xe0\x97\xfc\x75\x16\x17\xf9\xc2\x75\x35\x9c\x4a\xb8\x46\x40\xf1\x24\xf2\x5c\x0b\x44\x65\x28\x06\xfa\xef\xad\x46\x9c\xc4\xb5\x7c\x92\x93\x02\xa1\xd0\xa1\xb1\x16\x0a\x8c\x25\x9f\x12\x73\x9a\x7c\xa1\xc2\x04\xb8\xd3\x64\x8e\xf5\x0c\x5d\x98\x9f\x1c\xf6\xf5\xf8\xd1\x25\x01\x70\x43\xf2\x73\xd0\xce\x0f\x55\x93\x75\xd8\x85\xbe\xb3\x27\x7d\x9a\x3d\xf9\xc1\xaa\x16\x6d\x4a\x10\xad\x36\x5f\x1d\x20\xca\x4b\x09\x91\x66\xee\x27\xfd\x1a\xde\x59\x07\x1e\xde\xad\x02\xe9\x51\x2c\xd4\x84\x03\xfb\xce\xe1\x9c\x69\x60\x17\x19\x3e\x2e\xe3\x5f\x36\x6e\x85\xfc\x14\xf2\xfa\x1c\x0a\x32\xc8\x45\xbb\x5f\xd9\x15\x0d\x66\x48\x3d\x3b\x85\x7c\x33\x26\xf3\x86\x71\xab\x17\x4a\x49\x65\xab\x6c\x2f\x73\x31\xe1\xfa\xd8\x43\x4b\xee\x22\x1b\x17\xda\x60\xf5\x8c\x7d\x99\xd2\x3d\xfb\x6c\x0a\x52\x86\xf0\x0b\x86\x4d\x0c\x35\x05\xf2\x12\x2f\x9c\x8d\x02\x41\xac\xe7\xcb\x2e\x51\xb6\x07\xaa\x66\x7d\x28\x92\x6c\x8f\xc6\xc9\xdc\x15\x70\x63\x2b\xed\x12\x2a\x17\xaa\xdd\x95\xbf\x63\x6b\x40\xbe\xdb\x3f\x57\x18\xd6\x25\x31\xcb\x24\x70\x5f\x1a\x64\xc3\x9d\x0b\x62\x36\x4e\xef\x18\x57\x00\xd0\x93\x06\x2c\xb1\xc3\xc2\xf6\x53\xff\x12\xc8\x00\x42\xc7\x50\x0d\x9b\x5a\x43\x7f\xe8\x92\x8b\xc8\xe1\xa1\xcd\x85\xb9\xb2\x28\x11\x54\x26\xe7\x9c\x29\x19\xf4\x4d\x2c\x90\x69\x14\x57\x01\xe3\x76\x71\x87\x78\x01\x10\xce\x43\x79\x08\x81\x7d\x4d\x56\xb5\x68\x54\x12\xd6\x87\x94\x4a\x14\x61\xf2\xe6\x87\x0d\x4d\x11\x3b\xc2\x71\x9c\x8e\xa0\x11\x21\x16\x7a\x1c\x3e\xd0\xdf\x9c\x35\x57\x7f\xbd\xd0\x3d\xcc\xef\x63\xd2\xd4\x03\x11\xcf\x6a\xe5\x1b\x7e\x20\x15\x96\x75\x98\x0c\xf8\x4e\xd7\xdc\x69\xb8\x71\xef\xcd\x58\x4f\x45\x1e\x66\xc4\xf5\x4f\xbf\xc9\x66\xbb\xf1\x88\xd2\x22\x3c\xae\x5a\xb1\xcb\x3d\x5e\xaf\x4e\x0d\x49\x52\x9e\x12\x78\x77\xd3\x4a\x9c\xb1\x5a\xcd\x27\x4d\x6e\xd1\xc9\xb8\xe1\xb4\x6c\x23\xb1\x54\x7c\xca\x92\x1b\xea\xd9\xc0\xc9\xd2\x7a\xd8\xa6\x2f\x92\x1e\xc0\xe8\x7a\x82\x71\xfd\x14\x03\xaf\x22\x1e\xb0\x3a\x5a\xa6\x41\x8a\x56\x78\x6d\x7d\xc3\x3d\x05\x79\x2d\x9c\x80\xfa\x3a\x55\x1b\xa3\x9a\x83\x23\xf4\x88\x53\x62\x0b\x78\x04\x62\x55\x50\xfc\x22\x20\xee\xd0\xcc\xcb\x33\xca\x47\xb3\x27\xef\x53\x7d\x48\x5f\x31\x2a\x14\x9d\xe8\x66\xb1\x0e\xf9\x54\x48\x9a\x41\x38\x7f\x4f\x58\x51\xd8\xde\x6c\x01\x2b\x0f\x94\x1f\xf6\xd4\xf6\x06\x1e\x39\xae\x27\xd9\xd4\x8b\x33\xd6\x83\x5f\x72\x76\x23\x1e\x09\x17\x40\xdb\xb1\x6b\x60\xa3\x21\x0b\x3a\xe1\x08\xed\xa6\x93\xb4\x33\xed\xf5\x98\x58\x4d\xf1\x0f\xfc\x19\xf8\xe4\xdd\x9f\x57\xec\x30\x1d\xd3\xc1\xd9\x38\x49\x85\x83\x8a\x3a\x31\xf5\x19\x15\x5a\x86\xfd\x96\x5f\x53\x88\xee\x8c\x77\xea\x3f\xe8\x96\x3b\x49\x57\x17\xf5\x52\x95\xd1\x50\x3e\xee\xeb\x41\x01\x0f\x76\x87\xc0\x9e\x73\x94\xbb\xd4\x11\xed\x00\x43\x67\xf2\x75\x97\xf2\x20\x1b\x60\x57\xbf\x57\xba\xd0\x19\xc9\x9f\x1e\xcd\x45\xba\x2e\xe7\x83\x9a\x62\x34\x08\xde\x7a\x97\xd4\xe8\x5a\x49\xbf\xf8\xae\x9d\xa5\xc2\xbf\x47\x2a\x2c\x74\xa1\x5e\x96\x08\x85\xf7\x6c\x7a\x65\x44\xb8\x08\x3b\xac\x07\x6d\x4a\x95\x3d\x2e\x96\x6b\x5b\x19\xbe\x89\xa3\xdd\x17\x9c\xcb\x26\xef\x8e\x1f\x90\x12\xdd\x2b\x82\xd9\xc4\x91\x2e\x03\xc4\x86\x80\x2b\xbe\xce\x6f\x82\x96\x0e\x06\xba\x69\xb9\x86\xee\xff\xd2\x1f\x8b\xf8\x3c\x05\xc1\xac\xac\x64\x7e\x0d\xeb\xee\x97\x7d\x5f\xf3\xe9\xc2\x91\x18\x13\xeb\x9e\xda\xb9\x43\x2d\xa4\xde\x46\xae\xf8\xc7\x50\xaf\xa6\xa4\x01\xb2\x69\xfe\x8e\xea\xaf\x59\x06\x40\xa9\xf5\xfc\x77\xe5\x46\x60\xb3\x63\x8f\x9b\x67\x88\x86\xe6\xb3\x85\xef\x04\xe3\x22\xbb\x22\x42\xd0\x23\x21\x89\xc3\x3f\x32\x15\x2a\xc2\x06\xc4\xa2\x7e\x41\xf5\x15\x3c\xed\x76\x9b\xea\x6c\x3a\x33\x1a\x7e\x74\x93\xd1\x0e\xcc\xbc\xf2\x9c\x6a\x00\x24\x7f\xe6\x85\xd5\x04\x1b\x79\x7a\xd3\x44\x4d\x3b\x48\x57\x7f\x63\xec\x3d\x12\xf4\xf2\xc4\x19\x22\x85\x92\xbc\x5d\xca\xc1\x13\x48\x3d\x9a\x07\xc6\x91\xfe\x02\xea\x81\x47\x17\xc4\xdb\xf8\x22\x0c\xf5\xc2\xf9\xf9\x71\x20\x41\x08\xdd\xc4\x43\x0c\x77\x9e\x19\xab\x2e\x4c\x97\x72\x45\x81\x58\x20\x6d\x5d\x16\xad\x71\xce\x2a\xb2\xde\x0a\xff\xd0\x0e\x85\x2c\x67\xbb\x6f\x39\x88\x62\x15\xd6\x0c\xdf\x12\x6c\x94\x74\xa0\x96\x7d\x7e\xb5\xf2\x3f\xb9\x33\xf5\x9b\x30\x86\x1d\xfd\xe2\x90\x63\xf9\x57\xe0\x00\xfb\xf0\xad\xc2\x52\x07\x45\xf2\x79\xfc\xcb\xc8\xa4\x8f\xdb\xa1\xcc\xb7\x05\x1e\xc4\x11\x20\x42\x64\x42\x08\x3f\x35\x35\x6e\xd4\xb7\x30\x61\xb9\x6c\xc9\x15\xa8\xb3\x94\x64\x06\x08\xad\xa9\x72\x6d\xfd\x56\x9e\x6b\xf3\x1b\x36\x2b\x9d\x18\xa0\x4b\x7d\xa5\x96\xd7\xc0\xbf\xe3\x28\xd5\xbc\x18\x3b\xc9\x5c\x48\x0f\x88\x2c\x7f\xdc\x94\x6a\x6b\xa4\x4e\x7b\xa4\x02\xae\xf4\xfb\xa0\x16\x3d\xe3\xf7\xc3\x82\x81\x6a\xc2\x3e\x75\xef\xc7\xd5\x82\x6c\xa4\xa7\xb0\x55\xa1\xd2\x65\x0a\x97\xf6\x3f\xd9\x59\x6e\xa1\x29\xeb\x35\xbf\x0d\x33\x27\x83\x93\x1e\xd1\xf2\x7a\x9a\xd9\x8c\xe4\x45\x08\x69\x53\xb8\x57\xb2\x0b\x4e\xea\xf9\xd3\x30\xa3\x80\xee\xb0\x9e\xe9\x27\xbc\xab\xa3\x96\x66\xc6\x89\xb6\x60\x4f\xd3\xe2\xbe\xcf\x31\xe2\xa1\x17\x16\x32\xdf\xf2\x18\x61\x0f\xa1\x1e\x40\xd7\x89\xd6\x0d\x14\x5b\x94\xc4\xb8\xa7\x2b\xb5\x3f\x98\xd0\xd5\x6a\x80\x45\x64\x74\x58\x82\x2c\xcc\x29\x0b\x28\x20\x4d\x61\xd7\xc8\xda\x0f\x1a\x53\xe6\x51\x5d\x0d\x2c\x52\x41\xfa\xd6\x6a\x3d\x3b\x5c\x8f\x1b\x0f\xa8\x27\x69\x3a\xc4\xa2\x58\x76\x59\xb6\x03\xfc\x34\x3f\x29\x01\x13\xb7\x10\x6e\x83\x29\xc4\xc9\xf6\x6d\xf1\x2a\x1d\x9e\xb5\xb1\x3d\xab\x50\xde\xd6\xfd\xf2\x73\x29\x9e\xb4\x6f\x67\x16\x65\x89\x11\x0f\x1b\x18\xb6\xbd\x1d\xe4\x50\x49\x8d\xb4\x01\x50\x53\x22\x75\xd4\x29\x92\xec\x73\xbb\x4f\xa9\x13\x2a\xd3\xa0\x0a\x75\xab\x3b\x6a\xd2\x14\x87\x51\x5a\xc0\xb9\xa5\x9f\xa7\x33\x15\xbf\xed\xf5\x98\x1c\x7a\x24\x36\x32\x30\xd4\x45\xe1\x95\xe3\x8b\xd2\x97\x29\xbe\x8e\xc8\xd0\x68\xbb\xd0\xad\xa4\x87\xbd\xa2\xda\xb4\x8e\x7a\x10\xcd\x11\x7a\x78\x0d\x93\xc2\x5c\x1c\xf0\x56\x5c\x02\x9e\x8a\xd4\x3c\x25\xb1\x94\xc5\x13\x95\x2e\x89\x5e\x13\xbe\xae\x87\x8c\x15\xa0\x11\xea\xc4\x1c\x53\xbf\xb3\x16\xd4\x46\x62\xeb\xf6\xaa\xc8\x92\x73\xaf\x9f\xe6\x95\xd9\x8c\x88\x52\xeb\x78\x1c\xba\xab\xe3\x5d\xf9\x21\xd1\x91\xe1\x87\x48\x43\xc1\xbe\x60\xd4\xf3\x57\x06\x9a\xda"

# twoN = vector_powers(TWO, BP_N);
_BP_TWO_N = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

# ip12 = inner_product(oneN, twoN);
_BP_IP12 = b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
_PRINT_INT = False
COUNT_STATE = False
slot_sizes = None

PRNG = crypto.prng(_ZERO)

# Aliasing
ubinascii = binascii
BP_LOG_N = _BP_LOG_N
BP_N = _BP_N
BP_M = _BP_M
ZERO = _ZERO
ONE = _ONE
TWO = _TWO
EIGHT = _EIGHT
INV_EIGHT = _INV_EIGHT
MINUS_ONE = _MINUS_ONE
MINUS_INV_EIGHT = _MINUS_INV_EIGHT
XMR_H = _XMR_H
XMR_HP = _XMR_HP
BP_GI_PRE = _BP_GI_PRE
BP_HI_PRE = _BP_HI_PRE
BP_TWO_N = _BP_TWO_N
BP_IP12 = _BP_IP12


#
# Rct keys operations
# tmp_x are global working registers to minimize memory allocations / heap fragmentation.
# Caution has to be exercised when using the registers and operations using the registers
#

_hasher = crypto.get_keccak()
_tmp_bf_0 = bytearray(32)
_tmp_bf_1 = bytearray(32)
_tmp_bf_2 = bytearray(32)
_tmp_bf_exp = bytearray(11 + 32 + 4)

_tmp_pt_1 = crypto.new_point()
_tmp_pt_2 = crypto.new_point()
_tmp_pt_3 = crypto.new_point()
_tmp_pt_4 = crypto.new_point()

_tmp_sc_1 = crypto.new_scalar()
_tmp_sc_2 = crypto.new_scalar()
_tmp_sc_3 = crypto.new_scalar()
_tmp_sc_4 = crypto.new_scalar()


def const(x):
    return x


def set_prng(o):
    global PRNG
    PRNG = o


def _eprint(*args, **kwargs):
    if not _PRINT_INT:
        return
    print(*args, **kwargs)


def _ehexlify(x):
    if not _PRINT_INT:
        return
    binascii.hexlify(x)


def _ensure_dst_key(dst=None):
    if dst is None:
        dst = bytearray(32)
    return dst


def memcpy(dst, dst_off, src, src_off, len):
    if dst is not None:
        _memcpy(dst, dst_off, src, src_off, len)
    return dst


def _alloc_scalars(num=1):
    return (crypto.new_scalar() for _ in range(num))


def _copy_key(dst, src):
    for i in range(32):
        dst[i] = src[i]
    return dst


def _init_key(val, dst=None):
    dst = _ensure_dst_key(dst)
    return _copy_key(dst, val)


def _gc_iter(i):
    if i & 127 == 0:
        gc.collect()


def _invert(dst, x=None, x_raw=None, raw=False):
    dst = _ensure_dst_key(dst) if not raw else (crypto.new_scalar() if not dst else dst)
    if x:
        crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.sc_inv_into(_tmp_sc_2, _tmp_sc_1 if x else x_raw)
    if raw:
        return crypto.sc_copy(dst, _tmp_sc_2)
    else:
        crypto.encodeint_into(dst, _tmp_sc_2)
        return dst


def _scalarmult_key(dst, P, s, s_raw=None, tmp_pt=_tmp_pt_1):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(tmp_pt, P)
    if s:
        crypto.decodeint_into_noreduce(_tmp_sc_1, s)
    crypto.scalarmult_into(tmp_pt, tmp_pt, _tmp_sc_1 if s else s_raw)
    crypto.encodepoint_into(dst, tmp_pt)
    return dst


def _scalarmultH(dst, x):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into(_tmp_sc_1, x)
    crypto.scalarmult_into(_tmp_pt_1, _XMR_HP, _tmp_sc_1)
    crypto.encodepoint_into(dst, _tmp_pt_1)
    return dst


def _scalarmult_base(dst, x):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.scalarmult_base_into(_tmp_pt_1, _tmp_sc_1)
    crypto.encodepoint_into(dst, _tmp_pt_1)
    return dst


def _sc_gen(dst=None):
    dst = _ensure_dst_key(dst)
    buff = PRNG.next(32, bytearray(32))
    crypto.decodeint_into(_tmp_sc_1, buff)
    #crypto.random_scalar(_tmp_sc_1)
    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _sc_add(dst, a, b):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.sc_add_into(_tmp_sc_3, _tmp_sc_1, _tmp_sc_2)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_sub(dst, a, b, a_raw=None, b_raw=None):
    dst = _ensure_dst_key(dst)
    if a:
        crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    if b:
        crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.sc_sub_into(_tmp_sc_3, _tmp_sc_1 if a else a_raw, _tmp_sc_2 if b else b_raw)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_mul(dst, a=None, b=None, a_raw=None, b_raw=None):
    dst = _ensure_dst_key(dst)
    if a:
        crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    if b:
        crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_1 if a else a_raw, _tmp_sc_2 if b else b_raw)
    crypto.encodeint_into(dst, _tmp_sc_3)
    return dst


def _sc_muladd(dst, a, b, c, a_raw=None, b_raw=None, c_raw=None, raw=False):
    dst = _ensure_dst_key(dst) if not raw else (dst if dst else crypto.new_scalar())
    if a:
        crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    if b:
        crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    if c:
        crypto.decodeint_into_noreduce(_tmp_sc_3, c)
    crypto.sc_muladd_into(
        _tmp_sc_4 if not raw else dst,
        _tmp_sc_1 if a else a_raw,
        _tmp_sc_2 if b else b_raw,
        _tmp_sc_3 if c else c_raw,
    )
    if not raw:
        crypto.encodeint_into(dst, _tmp_sc_4)
    return dst


def _sc_mulsub(dst, a, b, c):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.decodeint_into_noreduce(_tmp_sc_3, c)
    crypto.sc_mulsub_into(_tmp_sc_4, _tmp_sc_1, _tmp_sc_2, _tmp_sc_3)
    crypto.encodeint_into(dst, _tmp_sc_4)
    return dst


def _add_keys(dst, A, B):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(_tmp_pt_1, A)
    crypto.decodepoint_into(_tmp_pt_2, B)
    crypto.point_add_into(_tmp_pt_3, _tmp_pt_1, _tmp_pt_2)
    crypto.encodepoint_into(dst, _tmp_pt_3)
    return dst


def _sub_keys(dst, A, B):
    dst = _ensure_dst_key(dst)
    crypto.decodepoint_into(_tmp_pt_1, A)
    crypto.decodepoint_into(_tmp_pt_2, B)
    crypto.point_sub_into(_tmp_pt_3, _tmp_pt_1, _tmp_pt_2)
    crypto.encodepoint_into(dst, _tmp_pt_3)
    return dst


def _add_keys2(dst, a, b, B):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.decodepoint_into(_tmp_pt_1, B)
    crypto.add_keys2_into(_tmp_pt_2, _tmp_sc_1, _tmp_sc_2, _tmp_pt_1)
    crypto.encodepoint_into(dst, _tmp_pt_2)
    return dst


def _add_keys3(dst, a, A, b, B):
    dst = _ensure_dst_key(dst)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    crypto.decodepoint_into(_tmp_pt_1, A)
    crypto.decodepoint_into(_tmp_pt_2, B)
    crypto.add_keys3_into(_tmp_pt_3, _tmp_sc_1, _tmp_pt_1, _tmp_sc_2, _tmp_pt_2)
    crypto.encodepoint_into(dst, _tmp_pt_3)
    return dst


def _hash_to_scalar(dst, data):
    dst = _ensure_dst_key(dst)
    crypto.hash_to_scalar_into(_tmp_sc_1, data)
    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _hash_vct_to_scalar(dst, data):
    dst = _ensure_dst_key(dst)
    _hasher.reset()
    for x in data:
        _hasher.update(x)
    dst = _hasher.digest(dst)

    crypto.decodeint_into(_tmp_sc_1, dst)
    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _get_exponent(dst, base, idx):
    dst = _ensure_dst_key(dst)
    salt = b"bulletproof"
    lsalt = const(11)  # len(salt)
    final_size = lsalt + 32 + uvarint_size(idx)
    memcpy(_tmp_bf_exp, 0, base, 0, 32)
    memcpy(_tmp_bf_exp, 32, salt, 0, lsalt)
    dump_uvarint_b_into(idx, _tmp_bf_exp, 32 + lsalt)
    crypto.keccak_hash_into(_tmp_bf_1, _tmp_bf_exp, final_size)
    crypto.hash_to_point_into(_tmp_pt_4, _tmp_bf_1)
    crypto.encodepoint_into(dst, _tmp_pt_4)
    return dst


#
# Key Vectors
#


class KeyVBase:
    """
    Base KeyVector object
    """

    __slots__ = ("current_idx", "size")

    def __init__(self, elems=64):
        self.current_idx = 0
        self.size = elems

    def idxize(self, idx):
        if idx < 0:
            idx = self.size + idx
        if idx >= self.size:
            raise IndexError("Index out of bounds: %s vs %s" % (idx, self.size))
        return idx

    def __getitem__(self, item):
        raise ValueError("Not supported")

    def __setitem__(self, key, value):
        raise ValueError("Not supported")

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.size:
            raise StopIteration
        else:
            self.current_idx += 1
            return self[self.current_idx - 1]

    def __len__(self):
        return self.size

    def to(self, idx, buff=None, offset=0):
        buff = _ensure_dst_key(buff)
        return memcpy(buff, offset, self[self.idxize(idx)], 0, 32)

    def read(self, idx, buff, offset=0):
        raise ValueError

    def slice(self, res, start, stop):
        for i in range(start, stop):
            res[i - start] = self[i]
        return res

    def slice_view(self, start, stop):
        return KeyVSliced(self, start, stop)

    def assrt(self, cond, msg=None, *args, **kwargs):
        if not cond:
            raise ValueError(msg)

    def sdump(self):
        return None

    def sload(self, st):
        return None

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = 0  # super().getsize(real, name, sslot_sizes) if isinstance(super(), KeyVBase) else 0
        return p + 2 * SIZE_INT if not real else (p + sizeof(KeyVBaseNULL) + sslot_sizes(self, KeyVBase.__slots__, real, name))


KeyVBaseNULL = KeyVBase()


_CHBITS = const(5)
_CHSIZE = const(1 << _CHBITS)


class KeyV(KeyVBase):
    """
    KeyVector abstraction
    Constant precomputed buffers = bytes, frozen. Same operation as normal.

    Non-constant KeyVector is separated to _CHSIZE elements chunks to avoid problems with
    the heap fragmentation. In this it is more probable that the chunks are correctly
    allocated as smaller continuous memory is required. Chunk is assumed to
    have _CHSIZE elements at all times to minimize corner cases handling. BP require either
    multiple of _CHSIZE elements vectors or less than _CHSIZE.

    Some chunk-dependent cases are not implemented as they are currently not needed in the BP.
    """

    __slots__ = ("d", "mv", "const", "cur", "chunked")

    def __init__(self, elems=64, buffer=None, const=False, no_init=False, buffer_chunked=False):
        super().__init__(elems)
        self.d = None
        self.mv = None
        self.const = const
        self.cur = _ensure_dst_key()
        self.chunked = False
        if no_init:
            pass
        elif buffer:
            self.d = buffer  # can be immutable (bytes)
            self.size = len(buffer) // 32 if not buffer_chunked else elems
            self.chunked = buffer_chunked
        else:
            self._set_d(elems)

        if not no_init:
            self._set_mv()

    @staticmethod
    def chunk_size():
        return _CHSIZE

    def _set_d(self, elems):
        if elems > _CHSIZE and elems % _CHSIZE == 0:
            self.chunked = True
            gc.collect()
            self.d = [bytearray(32 * _CHSIZE) for _ in range(elems // _CHSIZE)]

        else:
            self.chunked = False
            gc.collect()
            self.d = bytearray(32 * elems)

    def _set_mv(self):
        if not self.chunked:
            self.mv = memoryview(self.d)

    def __getitem__(self, item):
        """
        Returns corresponding 32 byte array.
        Creates new memoryview on access.
        """
        if self.chunked:
            return self.to(item)
        item = self.idxize(item)
        return self.mv[item * 32 : (item + 1) * 32]

    def __setitem__(self, key, value):
        if self.chunked:
            self.read(key, value)
            return
        if self.const:
            raise ValueError("Constant KeyV")
        ck = self[key]
        for i in range(32):
            ck[i] = value[i]

    def to(self, idx, buff=None, offset=0):
        idx = self.idxize(idx)
        if self.chunked:
            memcpy(
                buff if buff else self.cur,
                offset,
                self.d[idx >> _CHBITS],
                (idx & (_CHSIZE - 1)) << 5,
                32,
            )
        else:
            memcpy(buff if buff else self.cur, offset, self.d, idx << 5, 32)
        return buff if buff else self.cur

    def read(self, idx, buff, offset=0):
        idx = self.idxize(idx)
        if self.chunked:
            memcpy(self.d[idx >> _CHBITS], (idx & (_CHSIZE - 1)) << 5, buff, offset, 32)
        else:
            memcpy(self.d, idx << 5, buff, offset, 32)

    def resize(self, nsize, chop=False, realloc=False):
        if self.size == nsize:
            return self

        if self.chunked and nsize <= _CHSIZE:
            self.chunked = False  # de-chunk
            if self.size > nsize and realloc:
                gc.collect()
                self.d = bytearray(self.d[0][: nsize << 5])
            elif self.size > nsize and not chop:
                gc.collect()
                self.d = self.d[0][: nsize << 5]
            else:
                gc.collect()
                self.d = bytearray(nsize << 5)

        elif self.chunked and self.size < nsize:
            if nsize % _CHSIZE != 0 or realloc or chop:
                raise ValueError("Unsupported")  # not needed
            for i in range((nsize - self.size) // _CHSIZE):
                self.d.append(bytearray(32 * _CHSIZE))

        elif self.chunked:
            if nsize % _CHSIZE != 0:
                raise ValueError("Unsupported")  # not needed
            for i in range((self.size - nsize) // _CHSIZE):
                self.d.pop()
            if realloc:
                for i in range(nsize // _CHSIZE):
                    self.d[i] = bytearray(self.d[i])

        else:
            if self.size > nsize and realloc:
                gc.collect()
                self.d = bytearray(self.d[: nsize << 5])
            elif self.size > nsize and not chop:
                gc.collect()
                self.d = self.d[: nsize << 5]
            else:
                gc.collect()
                self.d = bytearray(nsize << 5)

        self.size = nsize
        self._set_mv()

    def realloc(self, nsize, collect=False):
        self.d = None
        self.mv = None
        if collect:
            gc.collect()  # gc collect prev. allocation

        self._set_d(nsize)
        self.size = nsize
        self._set_mv()

    def realloc_init_from(self, nsize, src, offset=0, collect=False):
        if not isinstance(src, KeyV):
            raise ValueError("KeyV supported only")
        self.realloc(nsize, collect)

        if not self.chunked and not src.chunked:
            memcpy(self.d, 0, src.d, offset << 5, nsize << 5)

        elif self.chunked and not src.chunked or self.chunked and src.chunked:
            for i in range(nsize):
                self.read(i, src.to(i + offset))

        elif not self.chunked and src.chunked:
            for i in range(nsize >> _CHBITS):
                memcpy(
                    self.d,
                    i << 11,
                    src.d[i + (offset >> _CHBITS)],
                    (offset & (_CHSIZE - 1)) << 5 if i == 0 else 0,
                    nsize << 5 if i <= nsize >> _CHBITS else (nsize & _CHSIZE) << 5,
                )

    def sdump(self):
        self.assrt(self.size <= const(1152921504606846976), "Size too big")
        return self.d, (self.size | (bool(self.chunked) << 60))  # packing saves 8B for boolean (self.chunked)

    def sload(self, st):
        self.d, s = st
        self.size = s &(~(1<<60))
        self.chunked = (s & (1<<60)) > 0
        self._set_mv()

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        if self.const:
            return (p + 2 + SIZE_SC + 2) if not real else (p + sizeof(self) + sslot_sizes(self, ("mv", "const", "cur", "chunked"), real, name))
        return (p + 2 + SIZE_SC + 2 + self.size * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, KeyV.__slots__, real, name))


class KeyVEval(KeyVBase):
    """
    KeyVector computed / evaluated on demand
    """

    __slots__ = ("fnc", "raw", "scalar", "buff")

    def __init__(self, elems=64, src=None, raw=False, scalar=True):
        super().__init__(elems)
        self.fnc = src
        self.raw = raw
        self.scalar = scalar
        self.buff = (
            _ensure_dst_key()
            if not raw
            else (crypto.new_scalar() if scalar else crypto.new_point())
        )

    def __getitem__(self, item):
        return self.fnc(self.idxize(item), self.buff)

    def to(self, idx, buff=None, offset=0):
        self.fnc(self.idxize(idx), self.buff)
        if self.raw:
            if offset != 0:
                raise ValueError("Not supported")
            if self.scalar and buff:
                return crypto.sc_copy(buff, self.buff)
            elif self.scalar:
                return self.buff
            else:
                raise ValueError("Not supported")
        else:
            memcpy(buff, offset, self.buff, 0, 32)
        return buff if buff else self.buff

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2 + 2 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVSized(KeyVBase):
    """
    Resized vector, wrapping possibly larger vector
    (e.g., precomputed, but has to have exact size for further computations)
    """

    __slots__ = ("wrapped",)

    def __init__(self, wrapped, new_size):
        super().__init__(new_size)
        self.wrapped = wrapped

    def __getitem__(self, item):
        return self.wrapped[self.idxize(item)]

    def __setitem__(self, key, value):
        self.wrapped[self.idxize(key)] = value

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 1) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVWrapped(KeyVBase):
    """
    Resized vector, wrapping possibly larger vector
    (e.g., precomputed, but has to have exact size for further computations)
    """

    __slots__ = ("wrapped",)

    def __init__(self, wrapped, new_size, raw=False, sc=True):
        super().__init__(new_size)
        self.wrapped = wrapped
        self.raw = raw
        self.sc = sc
        self.cur = bytearray(32) if not raw else (crypto.new_scalar() if sc else crypto.new_point())

    def __getitem__(self, item):
        return self.wrapped[self.idxize(item)]

    def __setitem__(self, key, value):
        self.wrapped[self.idxize(key)] = value

    def to(self, idx, buff=None, offset=0):
        buff = buff if buff else self.cur
        if self.raw:
            if self.sc:
                return crypto.sc_copy(self.cur, self[idx])
            else:
                raise ValueError()
        else:
            return memcpy(buff, offset, self[idx], 0, 32)

    def read(self, idx, buff, offset=0):
        if self.raw:
            if self.sc:
                return crypto.sc_copy(self.wrapped[self.idxize(idx)], buff)
            else:
                raise ValueError()
        else:
            return memcpy(self.wrapped[self.idxize(idx)], 0, buff, offset, 32)

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2 + 2 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVConst(KeyVBase):
    __slots__ = ("elem",)

    def __init__(self, size, elem, copy=True):
        super().__init__(size)
        self.elem = _init_key(elem) if copy else elem

    def __getitem__(self, item):
        return self.elem

    def to(self, idx, buff=None, offset=0):
        memcpy(buff, offset, self.elem, 0, 32)
        return buff if buff else self.elem

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVPrecomp(KeyVBase):
    """
    Vector with possibly large size and some precomputed prefix.
    Usable for Gi vector with precomputed usual sizes (i.e., 2 output transactions)
    but possible to compute further
    """

    __slots__ = ("precomp_prefix", "aux_comp_fnc", "buff")

    def __init__(self, size, precomp_prefix, aux_comp_fnc):
        super().__init__(size)
        self.precomp_prefix = precomp_prefix
        self.aux_comp_fnc = aux_comp_fnc
        self.buff = _ensure_dst_key()

    def __getitem__(self, item):
        item = self.idxize(item)
        if item < len(self.precomp_prefix):
            return self.precomp_prefix[item]
        return self.aux_comp_fnc(item, self.buff)

    def to(self, idx, buff=None, offset=0):
        item = self.idxize(idx)
        if item < len(self.precomp_prefix):
            return self.precomp_prefix.to(item, buff if buff else self.buff, offset)
        self.aux_comp_fnc(item, self.buff)
        memcpy(buff, offset, self.buff, 0, 32)
        return buff if buff else self.buff

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2 + SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVSliced(KeyVBase):
    """
    Sliced in-memory vector version, remapping
    """

    __slots__ = ("wrapped", "offset")

    def __init__(self, src, start=0, stop=None):
        stop = stop if stop is not None else len(src)
        super().__init__(stop - start)
        self.wrapped = src
        self.offset = start

    def __getitem__(self, item):
        return self.wrapped[self.offset + self.idxize(item)]

    def __setitem__(self, key, value):
        self.wrapped[self.offset + self.idxize(key)] = value

    def resize(self, nsize, chop=False):
        raise ValueError("Not supported")

    def to(self, idx, buff=None, offset=0):
        return self.wrapped.to(self.offset + self.idxize(idx), buff, offset)

    def read(self, idx, buff, offset=0):
        return self.wrapped.read(self.offset + self.idxize(idx), buff, offset)

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVPowers(KeyVBase):
    """
    Vector of x^i. Allows only sequential access (no jumping). Resets on [0,1] access.
    """

    __slots__ = ("x", "raw", "cur", "last_idx")

    def __init__(self, size, x, raw=False, **kwargs):
        super().__init__(size)
        self.x = x if not raw else crypto.decodeint_into_noreduce(None, x)
        self.raw = raw
        self.cur = bytearray(32) if not raw else crypto.new_scalar()
        self.last_idx = 0

    def __getitem__(self, item):
        prev = self.last_idx
        item = self.idxize(item)
        self.last_idx = item

        if item == 0:
            return (
                _copy_key(self.cur, _ONE)
                if not self.raw
                else crypto.decodeint_into_noreduce(self.cur, _ONE)
            )
        elif item == 1:
            return (
                _copy_key(self.cur, self.x)
                if not self.raw
                else crypto.sc_copy(self.cur, self.x)
            )
        elif item == prev:
            return self.cur
        elif item == prev + 1:
            return (
                _sc_mul(self.cur, self.cur, self.x)
                if not self.raw
                else crypto.sc_mul_into(self.cur, self.cur, self.x)
            )
        else:
            raise IndexError("Only linear scan allowed: %s, %s" % (prev, item))

    def reset(self):
        return self[0]

    def rewind(self, n):
        while n > 0:
            if not self.raw:
                _sc_mul(self.cur, self.cur, self.x)
            else:
                crypto.sc_mul_into(self.cur, self.cur, self.x)
            self.last_idx += 1
            n -= 1

    def set_state(self, idx, val):
        self.last_idx = idx
        if self.raw:
            return crypto.sc_copy(self.cur, val)
        else:
            return _copy_key(self.cur, val)

    def sdump(self):
        return self.cur, self.last_idx

    def sload(self, rec):
        self.cur, self.last_idx = rec

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 2 + 2 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVPrngMask(KeyVBase):
    """
    Vector of random elements. Allows only sequential access (no jumping). Resets on [0,1] access.
    """

    __slots__ = ("raw", "sc", "cur", "seed", "prng", "allow_nonlinear", "last_idx")

    def __init__(self, size, seed, raw=False, allow_nonlinear=False, **kwargs):
        super().__init__(size)
        self.last_idx = 0
        self.raw = raw
        self.sc = crypto.new_scalar()
        self.cur = bytearray(32)
        self.seed = bytes(seed)
        self.prng = crypto.prng(seed)
        self.allow_nonlinear = allow_nonlinear

    def reset(self):
        self.prng.reset(self.seed)
        return self._next()

    def _next(self):
        self.prng.next(32, self.cur)
        crypto.decodeint_into(self.sc, self.cur)
        return self.sc if self.raw else crypto.encodeint_into(self.cur, self.sc)

    def __getitem__(self, item):
        prev = self.last_idx
        item = self.idxize(item)
        self.last_idx = item

        if item == 0:
            return self.reset()
        elif item == prev:
            return self.cur if not self.raw else self.sc
        elif item == prev + 1:
            return self._next()
        else:
            if not self.allow_nonlinear:
                raise IndexError("Only linear scan allowed: %s, %s" % (prev, item))

            if item < prev:
                self.reset()
                prev = 0

            blocksize = self.prng.BLOCK_SIZE if hasattr(self.prng, 'BLOCK_SIZE') else 64
            rev = blocksize * (item - prev - 1)
            self.prng.rewind(rev)
            return self._next()

    def to(self, idx, buff=None, offset=0):
        if not buff:
            return self[idx]
        buff = _ensure_dst_key(buff)
        return memcpy(buff, offset, self[idx], 0, 32)

    def sdump(self):
        return self.last_idx, self.prng, self.cur

    def sload(self, st):
        self.last_idx, self.prng, self.cur = st
        crypto.decodeint_into(self.sc, self.cur)

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 3 + 4 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyR0(KeyVBase):
    """
    Vector r0. Allows only sequential access (no jumping). Resets on [0,1] access.
    zt_i = z^{2 + \floor{i/N}} 2^{i % N}
    r0_i = ((a_{Ri} + z) y^{i}) + zt_i

    Could be composed from smaller vectors, but RAW returns are required
    """

    __slots__ = (
        "N",
        "aR",
        "raw",
        "y",
        "yp",
        "z",
        "zt",
        "p2",
        "res",
        "cur",
        "last_idx",
    )

    def __init__(self, size, N, aR, y, z, raw=False, **kwargs):
        super().__init__(size)
        self.N = N
        self.aR = aR
        self.raw = raw
        self.y = crypto.decodeint_into_noreduce(None, y)
        self.yp = crypto.new_scalar()  # y^{i}
        self.z = crypto.decodeint_into_noreduce(None, z)
        self.zt = crypto.new_scalar()  # z^{2 + \floor{i/N}}
        self.p2 = crypto.new_scalar()  # 2^{i \% N}
        self.res = crypto.new_scalar()  # tmp_sc_1

        self.cur = bytearray(32) if not raw else None
        self.last_idx = 0
        self.reset()

    def reset(self):
        crypto.decodeint_into_noreduce(self.yp, _ONE)
        crypto.decodeint_into_noreduce(self.p2, _ONE)
        crypto.sc_mul_into(self.zt, self.z, self.z)

    def __getitem__(self, item):
        prev = self.last_idx
        item = self.idxize(item)
        self.last_idx = item

        # Const init for eval
        if item == 0:  # Reset on first item access
            self.reset()

        elif item == prev + 1:
            crypto.sc_mul_into(self.yp, self.yp, self.y)  # ypow
            if item % self.N == 0:
                crypto.sc_mul_into(self.zt, self.zt, self.z)  # zt
                crypto.decodeint_into_noreduce(self.p2, _ONE)  # p2 reset
            else:
                crypto.decodeint_into_noreduce(self.res, _TWO)  # p2
                crypto.sc_mul_into(self.p2, self.p2, self.res)  # p2

        elif item == prev:  # No advancing
            pass

        else:
            raise IndexError("Only linear scan allowed")

        # Eval r0[i]
        if (
            item == 0 or item != prev
        ):  # if True not present, fails with cross dot product
            crypto.decodeint_into_noreduce(self.res, self.aR.to(item))  # aR[i]
            crypto.sc_add_into(self.res, self.res, self.z)  # aR[i] + z
            crypto.sc_mul_into(self.res, self.res, self.yp)  # (aR[i] + z) * y^i
            crypto.sc_muladd_into(
                self.res, self.zt, self.p2, self.res
            )  # (aR[i] + z) * y^i + z^{2 + \floor{i/N}} 2^{i \% N}

        if self.raw:
            return self.res

        crypto.encodeint_into(self.cur, self.res)
        return self.cur

    def to(self, idx, buff=None, offset=0):
        r = self[idx]
        if buff is None:
            return r
        return memcpy(buff, offset, r, 0, 32)

    def sdump(self):
        return self.yp, self.zt, self.p2, self.last_idx

    def sload(self, st):
        self.yp, self.zt, self.p2, self.last_idx = st

    def getsize(self, real=False, name="", sslot_sizes=slot_sizes):
        p = super().getsize(real, name, sslot_sizes)
        return (p + 4 + 7 * SIZE_SC) if not real else (p + sizeof(self) + sslot_sizes(self, self.__slots__, real, name))


class KeyVZtwo(KeyVBase):
    """
    Ztwo vector - see vector_z_two_i
    """

    def __init__(self, N, logN, M, zpow, twoN, raw=False):
        super().__init__(N * M)
        self.N = N
        self.logN = logN
        self.M = M
        self.zpow = zpow
        self.twoN = twoN
        self.raw = raw
        self.sc = crypto.new_scalar()
        self.cur = bytearray(32) if not raw else None

    def __getitem__(self, item):
        _vector_z_two_i(self.logN, self.zpow, self.twoN, self.idxize(item), self.sc)
        if self.raw:
            return self.sc

        crypto.encodeint_into(self.cur, self.sc)
        return self.cur


def _ensure_dst_keyvect(dst=None, size=None):
    if dst is None:
        dst = KeyV(elems=size)
        return dst
    if size is not None and size != len(dst):
        dst.resize(size)
    return dst


def _const_vector(val, elems=_BP_N, copy=True):
    return KeyVConst(elems, val, copy)


def _vector_sum_aA(dst, a, A, a_raw=None):
    """
    \sum_{i=0}^{|A|}  a_i A_i
    """
    dst = _ensure_dst_key(dst)
    crypto.identity_into(_tmp_pt_2)

    for i in range(len(a or a_raw)):
        if a:
            crypto.decodeint_into_noreduce(_tmp_sc_1, a.to(i))
        crypto.decodepoint_into(_tmp_pt_3, A.to(i))
        crypto.scalarmult_into(_tmp_pt_1, _tmp_pt_3, _tmp_sc_1)
        crypto.point_add_into(_tmp_pt_2, _tmp_pt_2, _tmp_pt_1)
        _gc_iter(i)
    crypto.encodepoint_into(dst, _tmp_pt_2)
    return dst


def _vector_exponent_custom(A, B, a, b, dst=None, a_raw=None, b_raw=None):
    """
    \\sum_{i=0}^{|A|}  a_i A_i + b_i B_i
    """
    dst = _ensure_dst_key(dst)
    crypto.identity_into(_tmp_pt_2)

    for i in range(len(a or a_raw)):
        if a:
            crypto.decodeint_into_noreduce(_tmp_sc_1, a.to(i))
        crypto.decodepoint_into(_tmp_pt_3, A.to(i))
        if b:
            crypto.decodeint_into_noreduce(_tmp_sc_2, b.to(i))
        crypto.decodepoint_into(_tmp_pt_4, B.to(i))
        crypto.add_keys3_into(
            _tmp_pt_1,
            _tmp_sc_1 if a else a_raw.to(i),
            _tmp_pt_3,
            _tmp_sc_2 if b else b_raw.to(i),
            _tmp_pt_4,
        )
        crypto.point_add_into(_tmp_pt_2, _tmp_pt_2, _tmp_pt_1)
        _gc_iter(i)
    crypto.encodepoint_into(dst, _tmp_pt_2)
    return dst


def _vector_powers(x, n, dst=None, dynamic=False, **kwargs):
    """
    r_i = x^i
    """
    if dynamic:
        return KeyVPowers(n, x, **kwargs)
    dst = _ensure_dst_keyvect(dst, n)
    if n == 0:
        return dst
    dst.read(0, _ONE)
    if n == 1:
        return dst
    dst.read(1, x)

    crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.decodeint_into_noreduce(_tmp_sc_2, x)
    for i in range(2, n):
        crypto.sc_mul_into(_tmp_sc_1, _tmp_sc_1, _tmp_sc_2)
        crypto.encodeint_into(_tmp_bf_0, _tmp_sc_1)
        dst.read(i, _tmp_bf_0)
        _gc_iter(i)
    return dst


def _vector_power_sum(x, n, dst=None):
    """
    \\sum_{i=0}^{n-1} x^i
    """
    dst = _ensure_dst_key(dst)
    if n == 0:
        return _copy_key(dst, _ZERO)
    if n == 1:
        _copy_key(dst, _ONE)

    crypto.decodeint_into_noreduce(_tmp_sc_1, x)
    crypto.decodeint_into_noreduce(_tmp_sc_3, _ONE)
    crypto.sc_add_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_1)
    crypto.sc_copy(_tmp_sc_2, _tmp_sc_1)

    for i in range(2, n):
        crypto.sc_mul_into(_tmp_sc_2, _tmp_sc_2, _tmp_sc_1)
        crypto.sc_add_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_2)
        _gc_iter(i)

    return crypto.encodeint_into(dst, _tmp_sc_3)


def _inner_product(a, b, dst=None):
    """
    \\sum_{i=0}^{|a|} a_i b_i
    """
    if len(a) != len(b):
        raise ValueError("Incompatible sizes of a and b")
    dst = _ensure_dst_key(dst)
    crypto.sc_init_into(_tmp_sc_1, 0)

    for i in range(len(a)):
        crypto.decodeint_into_noreduce(_tmp_sc_2, a.to(i))
        crypto.decodeint_into_noreduce(_tmp_sc_3, b.to(i))
        crypto.sc_muladd_into(_tmp_sc_1, _tmp_sc_2, _tmp_sc_3, _tmp_sc_1)
        _gc_iter(i)

    crypto.encodeint_into(dst, _tmp_sc_1)
    return dst


def _hadamard_fold(v, a, b, into=None, into_offset=0, vR=None, vRoff=0, full_v=False):
    """
    Folds a curvepoint array using a two way scaled Hadamard product

    ln = len(v); h = ln // 2
    v_i = a v_i + b v_{h + i}
    """
    h = len(v) if full_v else (len(v) // 2)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    into = into if into else v

    for i in range(h):
        crypto.decodepoint_into(_tmp_pt_1, v.to(i))
        crypto.decodepoint_into(_tmp_pt_2, v.to(h + i) if not vR else vR.to(i + vRoff))
        crypto.add_keys3_into(_tmp_pt_3, _tmp_sc_1, _tmp_pt_1, _tmp_sc_2, _tmp_pt_2)
        crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_3)
        into.read(i + into_offset, _tmp_bf_0)
        _gc_iter(i)

    return into


def _hadamard_fold_linear(v, a, b, into=None, into_offset=0):
    """
    Folds a curvepoint array using a two way scaled Hadamard product.
    Iterates v linearly to support linear-scan evaluated vectors (on the fly)

    ln = len(v); h = ln // 2
    v_i = a v_i + b v_{h + i}
    """
    h = len(v) // 2
    into = into if into else v

    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    for i in range(h):
        crypto.decodepoint_into(_tmp_pt_1, v.to(i))
        crypto.scalarmult_into(_tmp_pt_1, _tmp_pt_1, _tmp_sc_1)
        crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_1)
        into.read(i + into_offset, _tmp_bf_0)
        _gc_iter(i)

    crypto.decodeint_into_noreduce(_tmp_sc_1, b)
    for i in range(h):
        crypto.decodepoint_into(_tmp_pt_1, v.to(i + h))
        crypto.scalarmult_into(_tmp_pt_1, _tmp_pt_1, _tmp_sc_1)
        crypto.decodepoint_into(_tmp_pt_2, into.to(i + into_offset))
        crypto.point_add_into(_tmp_pt_1, _tmp_pt_1, _tmp_pt_2)
        crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_1)
        into.read(i + into_offset, _tmp_bf_0)

        _gc_iter(i)
    return into


def _scalar_fold(v, a, b, into=None, into_offset=0, vR=None, vRoff=0, full_v=False):
    """
    ln = len(v); h = ln // 2
    v_i = a v_i + b v_{h + i}
    """
    h = len(v) if full_v else (len(v) // 2)
    crypto.decodeint_into_noreduce(_tmp_sc_1, a)
    crypto.decodeint_into_noreduce(_tmp_sc_2, b)
    into = into if into else v

    for i in range(h):
        crypto.decodeint_into_noreduce(_tmp_sc_3, v.to(i))
        crypto.decodeint_into_noreduce(_tmp_sc_4, v.to(h + i) if not vR else vR.to(i + vRoff))
        crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_1)
        crypto.sc_mul_into(_tmp_sc_4, _tmp_sc_4, _tmp_sc_2)
        crypto.sc_add_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_4)
        crypto.encodeint_into(_tmp_bf_0, _tmp_sc_3)
        into.read(i + into_offset, _tmp_bf_0)
        _gc_iter(i)

    return into


def _cross_inner_product(l0, r0, l1, r1):
    """
    t1   = l0 . r1 + l1 . r0
    t2   = l1 . r1
    """
    sc_t1 = crypto.new_scalar()
    sc_t2 = crypto.new_scalar()
    tl = crypto.new_scalar()
    tr = crypto.new_scalar()

    for i in range(len(l0)):
        crypto.decodeint_into_noreduce(tl, l0.to(i))
        crypto.decodeint_into_noreduce(tr, r1.to(i))
        crypto.sc_muladd_into(sc_t1, tl, tr, sc_t1)

        crypto.decodeint_into_noreduce(tl, l1.to(i))
        crypto.sc_muladd_into(sc_t2, tl, tr, sc_t2)

        crypto.decodeint_into_noreduce(tr, r0.to(i))
        crypto.sc_muladd_into(sc_t1, tl, tr, sc_t1)

        _gc_iter(i)

    return crypto.encodeint(sc_t1), crypto.encodeint(sc_t2)


def _vector_gen(dst, size, op):
    dst = _ensure_dst_keyvect(dst, size)
    for i in range(size):
        dst.to(i, _tmp_bf_0)
        op(i, _tmp_bf_0)
        dst.read(i, _tmp_bf_0)
        _gc_iter(i)
    return dst


def _vector_dup(x, n, dst=None):
    dst = _ensure_dst_keyvect(dst, n)
    for i in range(n):
        dst[i] = x
        _gc_iter(i)
    return dst


def _vector_add(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        _sc_add(_tmp_bf_1, a.to(i), b.to(i))
        dst.read(i, _tmp_bf_1)
        _gc_iter(i)
    return dst


def _vector_subtract(a, b, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        _sc_sub(_tmp_bf_1, a.to(i), b.to(i))
        dst.read(i, _tmp_bf_1)
        _gc_iter(i)
    return dst


def _vector_scalar(a, x, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        _sc_mul(dst[i], a[i], x)
        _gc_iter(i)
    return dst


def _vector_scalar2(a, x, dst=None):
    dst = _ensure_dst_keyvect(dst, len(a))
    for i in range(len(a)):
        _scalarmult_key(dst[i], a[i], x)
        _gc_iter(i)
    return dst


def _vector_sum(a, dst=None):
    dst = _ensure_dst_key(dst)
    _copy_key(dst, ZERO)
    for i in range(len(a)):
        _sc_add(dst, dst, a[i])
        _gc_iter(i)
    return dst


def _vector_z_two_i(logN, zpow, twoN, i, dst_sc=None):
    """
    0...N|N+1...2N|2N+1...3N|....
    zt[i] = z^b 2^c, where
      b = 2 + blockNumber. BlockNumber is idx of N block
      c = i % N = i - N * blockNumber
    """
    j = i >> logN
    crypto.decodeint_into_noreduce(_tmp_sc_1, zpow.to(j + 2))
    crypto.decodeint_into_noreduce(_tmp_sc_2, twoN.to(i & ((1 << logN) - 1)))
    crypto.sc_mul_into(dst_sc, _tmp_sc_1, _tmp_sc_2)
    return dst_sc


def _vector_z_two(N, logN, M, zpow, twoN, zero_twos=None, dynamic=False, **kwargs):
    if dynamic:
        return KeyVZtwo(N, logN, M, zpow, twoN, **kwargs)

    # Original algorithm from Monero
    zero_twos = _ensure_dst_keyvect(zero_twos, M * N)
    for i in range(M * N):
        zero_twos[i] = ZERO
        for j in range(1, M + 1):
            if i >= (j - 1) * N and i < j * N:
                _sc_muladd(
                    zero_twos[i], zpow[1 + j], twoN[i - (j - 1) * N], zero_twos[i]
                )
        _gc_iter(i)
    return zero_twos


def _hash_cache_mash(dst, hash_cache, *args):
    dst = _ensure_dst_key(dst)
    _hasher.reset()
    _hasher.update(hash_cache)

    for x in args:
        if x is None:
            break
        _hasher.update(x)
    _hasher.digest(dst)

    crypto.decodeint_into(_tmp_sc_1, dst)
    crypto.encodeint_into(hash_cache, _tmp_sc_1)
    _copy_key(dst, hash_cache)
    return dst


def _init_exponents(ln=64):
    Gi = KeyV(ln)
    Hi = KeyV(ln)
    for i in range(ln):
        _get_exponent(Hi[i], XMR_H, i * 2)
        _get_exponent(Gi[i], XMR_H, i * 2 + 1)
    return Gi, Hi


def _vect2buff(vect):
    buff = b""
    for i in range(len(vect)):
        cur = vect[i]
        for j in range(32):
            buff += b"\\x%02x" % cur[j]
    return buff


def _key2buff(hx):
    hxs = b""
    for i in hx:
        hxs += b"\\x%02x" % i
    return hxs


def _is_reduced(sc):
    return crypto.encodeint_into(_tmp_bf_0, crypto.decodeint_into(_tmp_sc_1, sc)) == sc


def _init_constants(ln=64):
    Gi, Hi = _init_exponents(ln)
    GiB = _vect2buff(Gi)
    HiB = _vect2buff(Hi)
    oneN = _vector_powers(ONE, ln)
    oneNB = _vect2buff(oneN)
    twoN = _vector_powers(TWO, ln)
    twoNB = _vect2buff(twoN)
    ip12 = _inner_product(oneN, twoN)
    ip12B = _key2buff(ip12)
    return Gi, GiB, Hi, HiB, oneN, oneNB, twoN, twoNB, ip12, ip12B


class MultiExpEval(object):
    """
    MultiExp object similar to MultiExp array of [(scalar, point), ]
    MultiExp computes simply: res = \sum_i scalar_i * point_i
    Straus / Pippenger algorithms are implemented in the original Monero C++ code for the speed
    but the memory cost is around 1 MB which is not affordable here in HW devices.

    Moreover, Monero needs speed for very fast verification for blockchain verification which is not
    priority in this use case.
    """

    def __init__(self, size=None):
        self.size = size if size else None

    def __len__(self):
        return self.size

    def __getitem__(self, item):
        raise IndexError()

    @staticmethod
    def eval_data(dst, data, GiHi=False):
        dst = _ensure_dst_key(dst)
        crypto.identity_into(_tmp_pt_1)
        for i in range(len(data)):
            sci, pti = data[i]
            crypto.decodeint_into_noreduce(_tmp_sc_1, sci)
            crypto.decodepoint_into(_tmp_pt_2, pti)
            crypto.scalarmult_into(_tmp_pt_3, _tmp_pt_2, _tmp_sc_1)
            crypto.point_add_into(_tmp_pt_1, _tmp_pt_1, _tmp_pt_3)
        crypto.encodepoint_into(dst, _tmp_pt_1)
        return dst

    def eval(self, dst, GiHi=False):
        return MultiExpEval.eval_data(dst, self, GiHi)


class MultiExp(MultiExpEval):
    """
    Simple MultiExp holder
    Supports on the fly evaluation and/or static array
    """

    def __init__(
        self, size=None, scalars=None, points=None, scalar_fnc=None, point_fnc=None
    ):
        super().__init__(size)
        self.current_idx = 0

        self.scalars = scalars if scalars else []
        self.points = points if points else []
        self.scalar_fnc = scalar_fnc
        self.point_fnc = point_fnc
        if (scalars or points) and size is None:
            self.size = max(
                len(scalars) if scalars else 0, len(points) if points else 0
            )
        else:
            self.size = 0

    def add_pair(self, scalar, point):
        self.scalars.append(scalar)
        self.points.append(point)
        self.size = len(self.scalars)

    def add_scalar(self, scalar):
        self.scalars.append(_init_key(scalar))
        self.size = len(self.scalars)

    def get_scalar(self, idx):
        return (
            self.scalar_fnc(idx, None)
            if idx >= len(self.scalars)
            else self.scalars[idx]
        )

    def get_point(self, idx):
        return (
            self.point_fnc(idx, None) if idx >= len(self.points) else self.points[idx]
        )

    def get_idx(self, idx):
        return self.get_scalar(idx), self.get_point(idx)

    def __getitem__(self, item):
        return self.get_idx(item)

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.size:
            raise StopIteration
        else:
            self.current_idx += 1
            return self[self.current_idx - 1]


class MultiExpSequential(MultiExp):
    """
    MultiExp holder with sequential evaluation
    """

    def __init__(
        self, size=None, scalars=None, points=None, scalar_fnc=None, point_fnc=None
    ):
        super().__init__(
            size,
            scalars=scalars,
            points=points,
            scalar_fnc=scalar_fnc,
            point_fnc=point_fnc,
        )
        self.current_idx = 0
        self.acc = crypto.identity()
        self.tmp = _ensure_dst_key()
        self.eval_idx = 0

    def add_pair(self, scalar, point):
        self._acc(scalar, point)

    def add_scalar(self, scalar):
        self._acc(scalar, self.get_point(self.current_idx))

    def _acc(self, scalar, point):
        crypto.decodeint_into_noreduce(_tmp_sc_1, scalar)
        crypto.decodepoint_into(_tmp_pt_2, point)
        crypto.scalarmult_into(_tmp_pt_3, _tmp_pt_2, _tmp_sc_1)
        crypto.point_add_into(self.acc, self.acc, _tmp_pt_3)
        self.current_idx += 1
        self.size += 1

    def eval(self, dst, GiHi=False):
        dst = _ensure_dst_key(dst)
        return crypto.encodepoint_into(dst, self.acc)


class MergedMultiExp(MultiExpEval):
    def __init__(self, *args):
        super().__init__()
        self.current_idx = 0
        self.exps = args if len(args) > 0 else []
        self.size = 0
        self.bnds = [0]
        for x in args:
            self.size += len(x)
            self.bnds.append(self.bnds[-1] + len(x))

    def add(self, exp):
        self.exps.append(exp)
        self.size += len(exp)
        self.bnds.append(self.bnds[-1] + len(exp))
        return self

    def _get_chunk(self, idx):
        if idx >= self.size:
            raise ValueError("Out of bounds")
        x = 0
        while self.bnds[x] < idx and x < len(self.exps):
            x += 1
        return x - 1

    def get_idx(self, idx):
        ch_idx = self._get_chunk(idx)
        acc_idx = self.bnds[ch_idx]
        return self.exps[ch_idx].get_idx(idx - acc_idx)

    def __getitem__(self, item):
        return self.get_idx(item)

    def __setitem__(self, key, value):
        raise ValueError("Not supported")

    def __iter__(self):
        self.current_idx = 0
        return self

    def __next__(self):
        if self.current_idx >= self.size:
            raise StopIteration
        else:
            self.current_idx += 1
            return self[self.current_idx - 1]

    def eval(self, dst, GiHi=False):
        dst = _ensure_dst_key(dst)
        acc = crypto.new_point()
        tmp = crypto.new_point()
        for sub in self.exps:
            sub.eval(tmp, GiHi)
            crypto.point_add_into(acc, acc, tmp)

        crypto.encodepoint_into(dst, acc)
        return dst


def _multiexp(dst=None, data=None, GiHi=False):
    return data.eval(dst, GiHi)


def _e_xL(sv, idx, d=None, is_a=True):
    j, i = idx // _BP_N, idx % _BP_N
    r = None
    if j >= len(sv):
        r = _ZERO if is_a else _MINUS_ONE
    elif sv[j][i // 8] & (1 << i % 8):
        r = _ONE if is_a else _ZERO
    else:
        r = _ZERO if is_a else _MINUS_ONE
    if d:
        return memcpy(d, 0, r, 0, 32)
    return r


if COUNT_STATE:
    from monero_glue.xmr.size_counter import *

    class BpSizeCounter(SizeCounter):
        def __init__(self, real=False, do_track=True, do_trace=False):
            super().__init__(real, do_track, do_trace)

        def check_type(self, tp, v, name, real):
            if tp in (KeyV, KeyVPowers, KeyVEval, KeyVPrecomp, KeyR0, KeyVPrngMask):
                c = v.getsize(real, name, sslot_sizes=self.slot_sizes)
            elif tp == type(_tmp_sc_1):
                c = SIZE_SC if not real else sizeof(v)
            elif tp == type(_tmp_pt_1):
                c = SIZE_PT if not real else sizeof(v)
            else:
                print('Unknown type: ', name, ', v', v, ', tp', tp)
                return 0

            self.tailsum(c, name, True)
            return c


class BulletProofBuilder:
    STATE_VARS = ('use_det_masks', 'proof_sec',
                  'do_blind', 'offload', 'batching', 'off_method', 'nprime_thresh', 'off2_thresh',
                  'MN', 'M', 'logMN', 'sv', 'gamma',
                  'A', 'S', 'T1', 'T2', 'tau1', 'tau2', 'taux', 'mu', 't', 'ts', 'x', 'x_ip', 'y', 'z', 'zc',  # V
                  'l0l1r0r1st', 'hash_cache', 'nprime', 'round', 'rho', 'alpha', 'Xbuffs',  # l, r
                  'w_round', 'winv', 'cL', 'cR', 'LcA', 'LcB', 'RcA', 'RcB',
                  'HprimeLRst', 'a', 'b',
                  'offstate', 'offpos', 'blinds')

    def __init__(self):
        self.use_det_masks = True
        self.proof_sec = None

        self.Gprec = KeyV(buffer=BP_GI_PRE, const=True)
        self.Hprec = KeyV(buffer=BP_HI_PRE, const=True)
        self.twoN = None
        self.fnc_det_mask = None

        self.tmp_sc_1 = crypto.new_scalar()
        self.tmp_det_buff = bytearray(64 + 1 + 4)

        self.gc_fnc = gc.collect
        self.gc_trace = None

        self.do_blind = True
        self.offload = False

        # Number of elements per one vector to batch in one message.
        # Message can contain multiple vectors.
        self.batching = 32

        # 0 = full offload, no blinding, just encrypted dummy storage
        # 1 = offload dot product, blinding (cL, cR, LcA, LcB, RcA, RcB)
        # 2 = offload dot product + folding.
        self.off_method = 0

        # Threshold for in-memory operation per one vector.
        self.nprime_thresh = 64

        # Threshold for in-memory operation with off_method=2.
        # When reached, host sends vectors for the last folding to the host,
        # then host operates in-memory (requires off2_thresh <= nprime_thresh)
        self.off2_thresh = 32

        self.MN = 1
        self.M = 1
        self.logMN = 1
        self.Gprec2 = None
        self.Hprec2 = None

        # Values, blinding masks
        self.sv = None
        self.gamma = None

        # Bulletproof result / intermediate state
        self.V = None
        self.A = None
        self.S = None
        self.T1 = None
        self.T2 = None
        self.tau1 = None
        self.tau2 = None
        self.taux = None
        self.mu = None
        self.t = None
        self.ts = None
        self.x = None
        self.x_ip = None
        self.y = None
        self.z = None
        self.zc = None
        self.l = None
        self.r = None
        self.rho = None
        self.alpha = None
        self.l0l1r0r1st = None
        self.hash_cache = None
        self.Xbuffs = [None, None, None, None, None, None, None]  # Gprime, Hprime, aprime, bprime, L, R, V
        self.Xprime = [None, None, None, None]  # Gprime, Hprime, aprime, bprime KeyVs

        self.L = None
        self.R = None
        self.a = None
        self.b = None

        # Folding (w), incremental Lc, Rc computation
        self.nprime = None
        self.round = 0
        self.w_round = None
        self.winv = None
        self.cL = None
        self.cR = None
        self.LcA = None
        self.LcB = None
        self.RcA = None
        self.RcB = None
        self.tmp_k_1 = None

        # Folding in round 0
        self.yinvpowL = None
        self.yinvpowR = None
        self.tmp_pt = None
        self.HprimeL = None
        self.HprimeR = None
        self.HprimeLRst = None

        # Offloading state management
        self.offstate = 0
        self.offpos = 0

        # 2 blinds per vector, one for lo, one for hi. 2*i, 2*i+1. Ordering G, H, a, b
        # blinds[0] current blinds
        # blinds[1] new blinds
        self.blinds = [[], []]

    def _save_xbuff(self, idx, val):
        self.Xbuffs[idx] = val.sdump()

    def _load_xbuff(self, idx):
        if not self.Xbuffs[idx]:
            return None
        kv = KeyV(0, no_init=True)
        kv.sload(self.Xbuffs[idx])
        self.Xbuffs[idx] = None
        self.gc(1)
        return kv

    def dump_xbuffs(self):
        if self.round > 0 and self.Gprime:
            self._save_xbuff(0, self.Gprime)
            self.Gprime = None
        if self.round > 0 and self.Hprime:
            self._save_xbuff(1, self.Hprime)
            self.Hprime = None
        if self.aprime:
            self._save_xbuff(2, self.aprime)
            self.aprime = None
        if self.bprime:
            self._save_xbuff(3, self.bprime)
            self.bprime = None
        if self.L:
            self._save_xbuff(4, self.L)
            self.L = None
        if self.R:
            self._save_xbuff(5, self.R)
            self.R = None
        if self.V:
            self._save_xbuff(6, self.V)
            self.V = None

    def load_xbuffs(self):
        if self.round > 0:
            self.Gprime = self._load_xbuff(0)
            self.Hprime = self._load_xbuff(1)
        self.aprime = self._load_xbuff(2)
        self.bprime = self._load_xbuff(3)
        self.L = self._load_xbuff(4)
        self.R = self._load_xbuff(5)
        self.V = self._load_xbuff(6)

    def dump_state(self, state=None):
        state = state if state is not None else [None] * len(BulletProofBuilder.STATE_VARS)
        if len(state) != len(BulletProofBuilder.STATE_VARS):
            state += [None] * (len(BulletProofBuilder.STATE_VARS) - len(state))

        # Serialize KeyV to buffers
        self.dump_xbuffs()
        self.gc(1)

        if COUNT_STATE:
            ctr_i = BpSizeCounter(False, False, False)
            ctr_r = BpSizeCounter(True, True, True)

        for ix, x in enumerate(BulletProofBuilder.STATE_VARS):
            v = getattr(self, x, None)
            setattr(self, x, None)
            state[ix] = v
            if COUNT_STATE:
                ctr_i.comp_size(v, x)
                ctr_r.comp_size(v, x)
        self.gc(1)

        if COUNT_STATE:
            ctr_r.acc += sizeof(state)
            _eprint('!!!!!!!!!!!!!!!!Dump finished: ', ctr_i.acc, ': r: ', ctr_r.acc)
            ctr_i.report()
            ctr_r.report()
            self.gc(1)
        return state

    def load_state(self, state):
        for ix, x in enumerate(BulletProofBuilder.STATE_VARS):
            if state[ix] is None:
                continue
            setattr(self, x, state[ix])
            state[ix] = None
        self.gc(1)

        # Unserialize KeyV buffers
        self.load_xbuffs()
        self.gc(1)

    @property
    def Gprime(self):
        return self.Xprime[0] if self.Xprime else None

    @property
    def Hprime(self):
        return self.Xprime[1] if self.Xprime else None

    @property
    def aprime(self):
        return self.Xprime[2] if self.Xprime else None

    @property
    def bprime(self):
        return self.Xprime[3] if self.Xprime else None

    @Gprime.setter
    def Gprime(self, val):
        self.Xprime[0] = val

    @Hprime.setter
    def Hprime(self, val):
        self.Xprime[1] = val

    @aprime.setter
    def aprime(self, val):
        self.Xprime[2] = val

    @bprime.setter
    def bprime(self, val):
        self.Xprime[3] = val

    def gc(self, *args):
        if self.gc_trace:
            self.gc_trace(*args)
        if self.gc_fnc:
            self.gc_fnc()

    def assrt(self, cond, msg=None, *args, **kwargs):
        if not cond:
            raise ValueError(msg)

    def aX_vcts(self, sv, MN):
        aL = KeyVEval(MN, lambda i, d: _e_xL(sv, i, d, True))
        aR = KeyVEval(MN, lambda i, d: _e_xL(sv, i, d, False))
        return aL, aR

    def _det_mask_init(self):
        memcpy(self.tmp_det_buff, 0, self.proof_sec, 0, len(self.proof_sec))

    def _det_mask(self, i, is_sL=True, dst=None):
        dst = _ensure_dst_key(dst)
        if self.fnc_det_mask:
            return self.fnc_det_mask(i, is_sL, dst)
        self.tmp_det_buff[64] = int(is_sL)
        memcpy(self.tmp_det_buff, 65, _ZERO, 0, 4)
        dump_uvarint_b_into(i, self.tmp_det_buff, 65)
        crypto.hash_to_scalar_into(self.tmp_sc_1, self.tmp_det_buff)
        crypto.encodeint_into(dst, self.tmp_sc_1)
        return dst

    def _gprec_aux(self, size):
        return KeyVPrecomp(
            size, self.Gprec, lambda i, d: _get_exponent(d, _XMR_H, i * 2 + 1)
        )

    def _hprec_aux(self, size):
        return KeyVPrecomp(
            size, self.Hprec, lambda i, d: _get_exponent(d, _XMR_H, i * 2)
        )

    def _two_aux(self, size):
        # Simple recursive exponentiation from precomputed results
        if self.twoN is None:
            self.twoN = KeyV(buffer=BP_TWO_N, const=True)

        lx = len(self.twoN)

        def pow_two(i, d=None):
            if i < lx:
                return self.twoN[i]

            d = _ensure_dst_key(d)
            flr = i // 2

            lw = pow_two(flr)
            rw = pow_two(flr + 1 if flr != i / 2.0 else lw)
            return _sc_mul(d, lw, rw)

        return KeyVPrecomp(size, self.twoN, pow_two)

    def sL_vct(self, ln=_BP_N, allow_nonlinear=False):
        return (
            KeyVPrngMask(ln, _ZERO, allow_nonlinear=allow_nonlinear) #crypto.random_bytes(32))
            # KeyVEval(ln, lambda i, dst: self._det_mask(i, True, dst))
            if self.use_det_masks
            else self.sX_gen(ln)
        )

    def sR_vct(self, ln=_BP_N, allow_nonlinear=False):
        return (
            KeyVPrngMask(ln, _ONE, allow_nonlinear=allow_nonlinear)  # crypto.random_bytes(32))
            # KeyVEval(ln, lambda i, dst: self._det_mask(i, False, dst))
            if self.use_det_masks
            else self.sX_gen(ln)
        )

    def sX_gen(self, ln=_BP_N):
        gc.collect()
        buff = bytearray(ln * 32)
        buff_mv = memoryview(buff)
        sc = crypto.new_scalar()
        for i in range(ln):
            buff0 = PRNG.next(32, bytearray(32))
            crypto.decodeint_into(sc, buff0)
            crypto.random_scalar_into(sc)
            crypto.encodeint_into(buff_mv[i * 32 : (i + 1) * 32], sc)
            _gc_iter(i)
        return KeyV(buffer=buff)

    def vector_exponent(self, a, b, dst=None, a_raw=None, b_raw=None):
        return _vector_exponent_custom(self.Gprec, self.Hprec, a, b, dst, a_raw, b_raw)

    def prove(self, sv, gamma):
        return self.prove_batch([sv], [gamma])

    def prove_setup_(self, sv, gamma):
        self.assrt(len(sv) == len(gamma), "|sv| != |gamma|")
        self.assrt(len(sv) > 0, "sv empty")

        self.proof_sec = crypto.random_bytes(64)
        self._det_mask_init()
        gc.collect()
        sv = [crypto.encodeint(x) for x in sv]
        gamma = [crypto.encodeint(x) for x in gamma]

        M, logM = 1, 0
        while M <= _BP_M and M < len(sv):
            logM += 1
            M = 1 << logM
        MN = M * _BP_N

        V = _ensure_dst_keyvect(None, len(sv))
        for i in range(len(sv)):
            _add_keys2(_tmp_bf_0, gamma[i], sv[i], _XMR_H)
            _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
            V.read(i, _tmp_bf_0)

        aL, aR = self.aX_vcts(sv, MN)
        return M, logM, aL, aR, V, gamma

    def prove_batch_(self, sv, gamma):
        M, logM, aL, aR, V, gamma = self.prove_setup_(sv, gamma)
        hash_cache = _ensure_dst_key()
        while True:
            self.gc(10)
            r = self._prove_batch_main_(
                V, gamma, aL, aR, hash_cache, logM, _BP_LOG_N, M, _BP_N
            )
            if r[0]:
                break
        return r[1]

    def _prove_batch_main_(self, V, gamma, aL, aR, hash_cache, logM, logN, M, N):
        logMN = logM + logN
        MN = M * N
        _hash_vct_to_scalar(hash_cache, V)

        # Extended precomputed GiHi
        Gprec = self._gprec_aux(MN)
        Hprec = self._hprec_aux(MN)

        # PHASE 1
        A, S, T1, T2, taux, mu, t, l, r, y, x_ip, hash_cache = self._prove_phase1_(
            N, M, logMN, V, gamma, aL, aR, hash_cache, Gprec, Hprec
        )

        # PHASE 2
        L, R, a, b = self._prove_loop_(
            MN, logMN, l, r, y, x_ip, hash_cache, Gprec, Hprec
        )

        return (
            1,
            Bulletproof(
                V=V, A=A, S=S, T1=T1, T2=T2, taux=taux, mu=mu, L=L, R=R, a=a, b=b, t=t
            ),
        )

    def _prove_phase1_(self, N, M, logMN, V, gamma, aL, aR, hash_cache, Gprec, Hprec):
        MN = M * N

        # PAPER LINES 38-39, compute A = 8^{-1} ( \alpha G + \sum_{i=0}^{MN-1} a_{L,i} \Gi_i + a_{R,i} \Hi_i)
        alpha = _sc_gen()
        A = _ensure_dst_key()
        _vector_exponent_custom(Gprec, Hprec, aL, aR, A)
        _add_keys(A, A, _scalarmult_base(_tmp_bf_1, alpha))
        _scalarmult_key(A, A, _INV_EIGHT)
        self.gc(11)

        # PAPER LINES 40-42, compute S =  8^{-1} ( \rho G + \sum_{i=0}^{MN-1} s_{L,i} \Gi_i + s_{R,i} \Hi_i)
        sL = self.sL_vct(MN)
        sR = self.sR_vct(MN)
        rho = _sc_gen()
        S = _ensure_dst_key()
        _vector_exponent_custom(Gprec, Hprec, sL, sR, S)
        _add_keys(S, S, _scalarmult_base(_tmp_bf_1, rho))
        _scalarmult_key(S, S, _INV_EIGHT)
        self.gc(12)

        # PAPER LINES 43-45
        y = _ensure_dst_key()
        _hash_cache_mash(y, hash_cache, A, S)
        if y == _ZERO:
            return (0,)

        z = _ensure_dst_key()
        _hash_to_scalar(hash_cache, y)
        _copy_key(z, hash_cache)
        zc = crypto.decodeint_into_noreduce(None, z)
        if z == _ZERO:
            return (0,)

        # Polynomial construction by coefficients
        # l0 = aL - z           r0   = ((aR + z) . ypow) + zt
        # l1 = sL               r1   =   sR      . ypow
        l0 = KeyVEval(
            MN, lambda i, d: _sc_sub(d, aL.to(i), None, None, zc)  # noqa: F821
        )
        l1 = sL
        self.gc(13)

        # This computes the ugly sum/concatenation from PAPER LINE 65
        # r0_i = ((a_{Ri} + z) y^{i}) + zt_i
        # r1_i = s_{Ri} y^{i}
        r0 = KeyR0(MN, N, aR, y, z)
        ypow = KeyVPowers(MN, y, raw=True)
        r1 = KeyVEval(
            MN, lambda i, d: _sc_mul(d, sR.to(i), None, ypow[i])  # noqa: F821
        )
        del aR
        self.gc(14)

        # Evaluate per index
        #  - $t_1 = l_0 . r_1 + l_1 . r0$
        #  - $t_2 = l_1 . r_1$
        #  - compute then T1, T2, x
        t1, t2 = _cross_inner_product(l0, r0, l1, r1)

        # PAPER LINES 47-48, Compute: T1, T2
        # T1 = 8^{-1} (\tau_1G + t_1H )
        # T2 = 8^{-1} (\tau_2G + t_2H )
        tau1, tau2 = _sc_gen(), _sc_gen()
        T1, T2 = _ensure_dst_key(), _ensure_dst_key()

        _add_keys2(T1, tau1, t1, _XMR_H)
        _scalarmult_key(T1, T1, _INV_EIGHT)

        _add_keys2(T2, tau2, t2, _XMR_H)
        _scalarmult_key(T2, T2, _INV_EIGHT)
        del (t1, t2)
        self.gc(16)

        # PAPER LINES 49-51, compute x
        x = _ensure_dst_key()
        _hash_cache_mash(x, hash_cache, z, T1, T2)
        if x == _ZERO:
            return (0,)

        # Second pass, compute l, r
        # Offloaded version does this incrementally and produces l, r outs in chunks
        # Message offloaded sends blinded vectors with random constants.
        #  - $l_i = l_{0,i} + xl_{1,i}
        #  - $r_i = r_{0,i} + xr_{1,i}
        #  - $t   = l . r$
        l = _ensure_dst_keyvect(None, MN)
        r = _ensure_dst_keyvect(None, MN)
        ts = crypto.new_scalar()
        for i in range(MN):
            _sc_muladd(_tmp_bf_0, x, l1.to(i), l0.to(i))
            l.read(i, _tmp_bf_0)

            _sc_muladd(_tmp_bf_1, x, r1.to(i), r0.to(i))
            r.read(i, _tmp_bf_1)

            _sc_muladd(ts, _tmp_bf_0, _tmp_bf_1, None, c_raw=ts, raw=True)

        t = crypto.encodeint(ts)
        del (l0, l1, sL, sR, r0, r1, ypow, ts)
        self.gc(17)

        # PAPER LINES 52-53, Compute \tau_x
        taux = _ensure_dst_key()
        _sc_mul(taux, tau1, x)
        _sc_mul(_tmp_bf_0, x, x)
        _sc_muladd(taux, tau2, _tmp_bf_0, taux)
        del (tau1, tau2)

        zpow = crypto.sc_mul_into(None, zc, zc)
        for j in range(1, len(V) + 1):
            _sc_muladd(taux, None, gamma[j - 1], taux, a_raw=zpow)
            crypto.sc_mul_into(zpow, zpow, zc)
        del (zc, zpow)

        self.gc(18)
        mu = _ensure_dst_key()
        _sc_muladd(mu, x, rho, alpha)
        del (rho, alpha)
        self.gc(19)

        # PAPER LINES 32-33
        x_ip = _hash_cache_mash(None, hash_cache, x, taux, mu, t)
        if x_ip == _ZERO:
            return 0, None

        return A, S, T1, T2, taux, mu, t, l, r, y, x_ip, hash_cache

    def _prove_loop_(self, MN, logMN, l, r, y, x_ip, hash_cache, Gprec, Hprec):
        nprime = MN
        aprime = l
        bprime = r

        yinvpowL = KeyVPowers(MN, _invert(_tmp_bf_0, y), raw=True)
        yinvpowR = KeyVPowers(MN, _tmp_bf_0, raw=True)
        tmp_pt = crypto.new_point()

        Gprime = Gprec
        HprimeL = KeyVEval(
            MN, lambda i, d: _scalarmult_key(d, Hprec.to(i), None, yinvpowL[i])
        )
        HprimeR = KeyVEval(
            MN, lambda i, d: _scalarmult_key(d, Hprec.to(i), None, yinvpowR[i], tmp_pt)
        )
        Hprime = HprimeL
        self.gc(20)

        L = _ensure_dst_keyvect(None, logMN)
        R = _ensure_dst_keyvect(None, logMN)
        cL = _ensure_dst_key()
        cR = _ensure_dst_key()
        winv = _ensure_dst_key()
        w_round = _ensure_dst_key()
        tmp = _ensure_dst_key()
        _tmp_k_1 = _ensure_dst_key()
        round = 0

        # PAPER LINE 13
        while nprime > 1:
            # PAPER LINE 15
            npr2 = nprime
            nprime >>= 1
            self.gc(22)

            # PAPER LINES 16-17
            # cL = \ap_{\left(\inta\right)} \cdot \bp_{\left(\intb\right)}
            # cR = \ap_{\left(\intb\right)} \cdot \bp_{\left(\inta\right)}
            _inner_product(
                aprime.slice_view(0, nprime), bprime.slice_view(nprime, npr2), cL
            )

            _inner_product(
                aprime.slice_view(nprime, npr2), bprime.slice_view(0, nprime), cR
            )
            self.gc(23)

            # PAPER LINES 18-19
            # Lc = 8^{-1} \left(\left( \sum_{i=0}^{\np} \ap_{i}\quad\Gp_{i+\np} + \bp_{i+\np}\Hp_{i} \right)
            # 		    + \left(c_L x_{ip}\right)H \right)
            _vector_exponent_custom(
                Gprime.slice_view(nprime, npr2),
                Hprime.slice_view(0, nprime),
                aprime.slice_view(0, nprime),
                bprime.slice_view(nprime, npr2),
                _tmp_bf_0,
            )

            # In round 0 backup the y^{prime - 1}
            if round == 0:
                yinvpowR.set_state(yinvpowL.last_idx, yinvpowL.cur)

            _sc_mul(tmp, cL, x_ip)
            _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(_tmp_k_1, tmp))
            _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
            L.read(round, _tmp_bf_0)
            self.gc(24)

            # Rc = 8^{-1} \left(\left( \sum_{i=0}^{\np} \ap_{i+\np}\Gp_{i}\quad + \bp_{i}\quad\Hp_{i+\np} \right)
            #           + \left(c_R x_{ip}\right)H \right)
            _vector_exponent_custom(
                Gprime.slice_view(0, nprime),
                Hprime.slice_view(nprime, npr2),
                aprime.slice_view(nprime, npr2),
                bprime.slice_view(0, nprime),
                _tmp_bf_0,
            )

            _sc_mul(tmp, cR, x_ip)
            _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(_tmp_k_1, tmp))
            _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
            R.read(round, _tmp_bf_0)
            self.gc(25)

            # PAPER LINES 21-22
            _hash_cache_mash(w_round, hash_cache, L.to(round), R.to(round))
            if w_round == _ZERO:
                return (0,)

            # PAPER LINES 24-25, fold {G~, H~}
            _invert(winv, w_round)
            self.gc(26)

            # PAPER LINES 28-29, fold {a, b} vectors
            # aprime's high part is used as a buffer for other operations
            _scalar_fold(aprime, w_round, winv)
            aprime.resize(nprime)
            self.gc(27)

            _scalar_fold(bprime, winv, w_round)
            bprime.resize(nprime)
            self.gc(28)

            # First fold produced to a new buffer, smaller one (G~ on-the-fly)
            Gprime_new = KeyV(nprime) if round == 0 else Gprime
            Gprime = _hadamard_fold(Gprime, winv, w_round, Gprime_new, 0)
            Gprime.resize(nprime)
            self.gc(30)

            # Hadamard fold for H is special - linear scan only.
            # Linear scan is slow, thus we have HprimeR.
            if round == 0:
                Hprime_new = KeyV(nprime)
                Hprime = _hadamard_fold(
                    Hprime, w_round, winv, Hprime_new, 0, HprimeR, nprime
                )
                # Hprime = _hadamard_fold_linear(Hprime, w_round, winv, Hprime_new, 0)

            else:
                _hadamard_fold(Hprime, w_round, winv)
                Hprime.resize(nprime)

            if round == 0:
                # del (Gprec, Hprec, yinvpowL, HprimeL)
                del (Gprec, Hprec, yinvpowL, yinvpowR, HprimeL, HprimeR, tmp_pt)

            self.gc(31)
            round += 1

        return L, R, aprime.to(0), bprime.to(0)

    def _comp_m(self, ln):
        M, logM = 1, 0
        while M <= _BP_M and M < ln:
            logM += 1
            M = 1 << logM
        MN = M * _BP_N
        return M, logM, MN

    def _comp_V(self, sv, gamma):
        V = _ensure_dst_keyvect(None, len(sv))
        for i in range(len(sv)):
            _add_keys2(_tmp_bf_0, gamma[i], sv[i], _XMR_H)
            _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
            V.read(i, _tmp_bf_0)
        return V

    def prove_setup(self, sv, gamma):
        self.assrt(len(sv) == len(gamma), "|sv| != |gamma|")
        self.assrt(len(sv) > 0, "sv empty")

        self.proof_sec = b"\x00"*32  #crypto.random_bytes(64)
        self._det_mask_init()
        gc.collect()
        self.sv = [crypto.encodeint(x) for x in sv]
        gamma = [crypto.encodeint(x) for x in gamma]

        M, logM, MN = self._comp_m(len(self.sv))
        V = self._comp_V(self.sv, gamma)
        aL, aR = self.aX_vcts(self.sv, MN)
        return M, logM, aL, aR, V, gamma

    def prove_batch(self, sv, gamma):
        M, logM, aL, aR, V, gamma = self.prove_setup(sv, gamma)
        hash_cache = _ensure_dst_key()
        while True:
            self.gc(10)
            r = self._prove_batch_main(
                V, gamma, aL, aR, hash_cache, logM, _BP_LOG_N, M, _BP_N
            )
            if r[0]:
                break
        return r[1]

    def prove_batch_off(self, sv, gamma, buffers=None):
        M, logM, aL, aR, V, gamma = self.prove_setup(sv, gamma)
        hash_cache = _ensure_dst_key()

        logMN = logM + _BP_LOG_N
        MN = M * _BP_N
        _hash_vct_to_scalar(hash_cache, V)

        # Extended precomputed GiHi
        Gprec = self._gprec_aux(MN)
        Hprec = self._hprec_aux(MN)
        self.offload = True
        return self._prove_phase1(
            _BP_N, M, logMN, V, gamma, aL, aR, hash_cache, Gprec, Hprec, buffers
        )

    def prove_batch_off_step(self, buffers=None):
        if self.offstate == 0:
            return self._phase1_lr()
        elif self.offstate == 1:
            return self._phase1_post()
        elif self.offstate == 2:
            return self._phase2_loop_offdot(buffers)
        elif self.offstate in [3, 4, 5, 6]:
            return self._phase2_loop_fold(buffers)
        elif self.offstate in [20, 21, 22, 23, 24, 25]:
            return self._phase2_loop0_clcr(buffers)
        elif self.offstate == 10:
            return self._phase2_loop_full()
        elif self.offstate == 12:
            return self._phase2_final()
        else:
            raise ValueError('Internal state error')

    def _prove_batch_main(self, V, gamma, aL, aR, hash_cache, logM, logN, M, N):
        logMN = logM + logN
        MN = M * N
        _hash_vct_to_scalar(hash_cache, V)

        # Extended precomputed GiHi
        Gprec = self._gprec_aux(MN)
        Hprec = self._hprec_aux(MN)

        # PHASE 1
        self._prove_phase1(
            N, M, logMN, V, gamma, aL, aR, hash_cache, Gprec, Hprec
        )

        # PHASE 2
        L, R, a, b = self._prove_loop(
            MN, logMN, self.l, self.r, self.y, self.x_ip, self.hash_cache, Gprec, Hprec
        )

        return (
            1,
            Bulletproof(
                V=self.V, A=self.A, S=self.S, T1=self.T1, T2=self.T2, taux=self.taux, mu=self.mu,
                L=L, R=R, a=a, b=b, t=self.t
            ),
        )

    def _comp_l0l1r0r1(self, MN, aL, aR, sL, sR, y, z, zc, l0l1r0r1st=None):
        # Polynomial construction by coefficients
        # l0 = aL - z           r0   = ((aR + z) . ypow) + zt
        # l1 = sL               r1   =   sR      . ypow
        l0 = KeyVEval(MN, lambda i, d: _sc_sub(d, aL.to(i), None, None, zc))
        l1 = sL
        self.gc(13)

        # This computes the ugly sum/concatenation from PAPER LINE 65
        # r0_i = ((a_{Ri} + z) y^{i}) + zt_i
        # r1_i = s_{Ri} y^{i}
        r0 = KeyR0(MN, _BP_N, aR, y, z)
        ypow = KeyVPowers(MN, y, raw=True)
        r1 = KeyVEval(MN, lambda i, d: _sc_mul(d, sR.to(i), None, None, ypow[i]))

        if l0l1r0r1st:
            sL.sload(l0l1r0r1st[0])
            sR.sload(l0l1r0r1st[1])
            r0.sload(l0l1r0r1st[2])
            ypow.sload(l0l1r0r1st[3])
        return l0, l1, r0, r1, ypow

    def _sdump_l0l1r0r1(self, l1, sR, r0, ypow):
        return l1.sdump(), sR.sdump(), r0.sdump(), ypow.sdump()

    def _prove_phase1(self, N, M, logMN, V, gamma, aL, aR, hash_cache, Gprec, Hprec, buffers=None):
        self.MN = M * N
        self.M = M
        self.logMN = logMN
        self.V = V
        self.gamma = gamma
        self.hash_cache = hash_cache
        self.Gprec2, self.Hprec2 = Gprec, Hprec

        # PAPER LINES 38-39, compute A = 8^{-1} ( \alpha G + \sum_{i=0}^{MN-1} a_{L,i} \Gi_i + a_{R,i} \Hi_i)
        self.alpha = _sc_gen()
        self.A = _ensure_dst_key()
        if buffers and len(buffers) > 0:  # computed by the host, \sum_{i=0}^{MN-1} a_{L,i} \Gi_i
            self.A = buffers[0]
        else:
            _vector_exponent_custom(Gprec, Hprec, aL, aR, self.A)
        _add_keys(self.A, self.A, _scalarmult_base(_tmp_bf_1, self.alpha))
        _scalarmult_key(self.A, self.A, _INV_EIGHT)
        self.gc(11)

        # PAPER LINES 40-42, compute S =  8^{-1} ( \rho G + \sum_{i=0}^{MN-1} s_{L,i} \Gi_i + s_{R,i} \Hi_i)
        sL = self.sL_vct(self.MN)
        sR = self.sR_vct(self.MN)
        self.rho = _sc_gen()
        self.S = _ensure_dst_key()
        _vector_exponent_custom(Gprec, Hprec, sL, sR, self.S)
        _add_keys(self.S, self.S, _scalarmult_base(_tmp_bf_1, self.rho))
        _scalarmult_key(self.S, self.S, _INV_EIGHT)
        self.gc(12)

        # PAPER LINES 43-45
        self.y = _ensure_dst_key()
        _hash_cache_mash(self.y, self.hash_cache, self.A, self.S)
        if self.y == _ZERO:
            return (0,)

        self.z = _ensure_dst_key()
        _hash_to_scalar(self.hash_cache, self.y)
        _copy_key(self.z, self.hash_cache)
        self.zc = crypto.decodeint_into_noreduce(None, self.z)
        if self.z == _ZERO:
            return (0,)

        # Polynomial construction by coefficients
        l0, l1, r0, r1, ypow = self._comp_l0l1r0r1(self.MN, aL, aR, sL, sR, self.y, self.z, self.zc)
        del (aL, aR, sL, sR, ypow)
        self.gc(14)

        # Evaluate per index
        #  - $t_1 = l_0 . r_1 + l_1 . r0$
        #  - $t_2 = l_1 . r_1$
        #  - compute then T1, T2, x
        t1, t2 = _cross_inner_product(l0, r0, l1, r1)

        # PAPER LINES 47-48, Compute: T1, T2
        # T1 = 8^{-1} (\tau_1G + t_1H )
        # T2 = 8^{-1} (\tau_2G + t_2H )
        self.tau1, self.tau2 = _sc_gen(), _sc_gen()
        self.T1, self.T2 = _ensure_dst_key(), _ensure_dst_key()

        _add_keys2(self.T1, self.tau1, t1, _XMR_H)
        _scalarmult_key(self.T1, self.T1, _INV_EIGHT)

        _add_keys2(self.T2, self.tau2, t2, _XMR_H)
        _scalarmult_key(self.T2, self.T2, _INV_EIGHT)
        del (t1, t2)
        self.gc(16)

        # PAPER LINES 49-51, compute x
        self.x = _ensure_dst_key()
        _hash_cache_mash(self.x, self.hash_cache, self.z, self.T1, self.T2)
        if self.x == _ZERO:
            return (0,)

        if not self.offload:
            return self._phase1_fulllr(l0, l1, r0, r1)

        # Offloading code
        del(l0, l1, r0, r1)
        self.gc(17)

        self.ts = crypto.new_scalar()
        self._prove_new_blinds()
        self.offstate = 0
        self.offpos = 0
        return self._phase1_lr()

    def _phase1_fulllr(self, l0, l1, r0, r1):
        # Second pass, compute l, r
        # Offloaded version does this incrementally and produces l, r outs in chunks
        # Message offloaded sends blinded vectors with random constants.
        #  - $l_i = l_{0,i} + xl_{1,i}
        #  - $r_i = r_{0,i} + xr_{1,i}
        #  - $t   = l . r$
        self.l = _ensure_dst_keyvect(None, self.MN)
        self.r = _ensure_dst_keyvect(None, self.MN)
        ts = crypto.new_scalar()
        for i in range(self.MN):
            _sc_muladd(_tmp_bf_0, self.x, l1.to(i), l0.to(i))
            self.l.read(i, _tmp_bf_0)

            _sc_muladd(_tmp_bf_1, self.x, r1.to(i), r0.to(i))
            self.r.read(i, _tmp_bf_1)

            _sc_muladd(ts, _tmp_bf_0, _tmp_bf_1, None, c_raw=ts, raw=True)

        self.t = crypto.encodeint(ts)
        del (l0, l1, r0, r1, ts)
        self.gc(17)

        return self._phase1_post()

    def _phase1_lr(self):
        """
        Computes l, r vectors per chunks
        """
        _eprint('Phase1_lr, state: %s, off: %s, MN: %s' % (self.offstate, self.offpos, self.MN))
        self.gc(2)
        l = KeyV(self.batching)
        self.gc(3)
        r = KeyV(self.batching)
        self.gc(4)

        # Reconstruct l0, l1, r0, r1 from the saved state
        aL, aR = self.aX_vcts(self.sv, self.MN)
        sL, sR = self.sL_vct(self.MN), self.sR_vct(self.MN)
        l0, l1, r0, r1, ypow = self._comp_l0l1r0r1(self.MN, aL, aR, sL, sR,
                                                   self.y, self.z, self.zc, self.l0l1r0r1st)
        self.l0l1r0r1st = None
        del (aL, aR, sL)
        self.gc(14)

        for i in range(self.offpos, self.offpos + self.batching):
            bloff = int(i >= (self.MN >> 1))
            _sc_muladd(_tmp_bf_0, self.x, l1.to(i), l0.to(i))
            _sc_muladd(_tmp_bf_1, self.x, r1.to(i), r0.to(i))
            _sc_muladd(self.ts, _tmp_bf_0, _tmp_bf_1, None, c_raw=self.ts, raw=True)
            _sc_mul(_tmp_bf_0, _tmp_bf_0, None, b_raw=self.blinds[0][4+bloff])  # blinding a
            _sc_mul(_tmp_bf_1, _tmp_bf_1, None, b_raw=self.blinds[0][6+bloff])  # blinding b
            l.read(i - self.offpos, _tmp_bf_0)
            r.read(i - self.offpos, _tmp_bf_1)
        del(l0, r1)
        self.gc(5)

        self.offstate = 0
        self.offpos += self.batching
        if self.offpos >= self.MN:
            self.t = crypto.encodeint(self.ts)
            del(self.ts, self.l0l1r0r1st)
            _eprint('Moving to next state')
            self.offstate = 1
            self.offpos = 0

        else:
            self.l0l1r0r1st = self._sdump_l0l1r0r1(l1, sR, r0, ypow)

        ld, rd = l.d, r.d
        del(l1, r0, ypow, sR, l, r)
        self.gc(6)
        return ld, rd

    def _phase1_post(self):
        """
        Part after l, r, t are computed.
        Offstate = 1
        """
        _eprint('phase1_post, state: %s, off: %s' % (self.offstate, self.offpos))

        # PAPER LINES 52-53, Compute \tau_x
        self.taux = _ensure_dst_key()
        _sc_mul(self.taux, self.tau1, self.x)
        _sc_mul(_tmp_bf_0, self.x, self.x)
        _sc_muladd(self.taux, self.tau2, _tmp_bf_0, self.taux)
        del (self.tau1, self.tau2)
        self.gc(10)

        zpow = crypto.sc_mul_into(None, self.zc, self.zc)
        for j in range(1, len(self.V) + 1):
            _sc_muladd(self.taux, None, self.gamma[j - 1], self.taux, a_raw=zpow)
            crypto.sc_mul_into(zpow, zpow, self.zc)
        self.sv = None
        self.gamma = None
        del (self.zc, zpow)
        self.gc(18)

        self.mu = _ensure_dst_key()
        _sc_muladd(self.mu, self.x, self.rho, self.alpha)
        del (self.rho, self.alpha)
        self.gc(19)

        # PAPER LINES 32-33
        self.x_ip = _hash_cache_mash(None, self.hash_cache, self.x, self.taux, self.mu, self.t)
        if self.x_ip == _ZERO:
            return 0, None

        # prepare for looping
        self.offstate = 20 if self.off_method == 0 else 2
        self.offpos = 0
        self.round = 0
        self.nprime = self.MN >> 1
        _eprint('MN: %s, nprime: %s' % (self.MN, self.nprime))
        self.L = _ensure_dst_keyvect(None, self.logMN)
        self.R = _ensure_dst_keyvect(None, self.logMN)
        self.gc(20)

        if self.l is None:
            self.l = tuple()
            self.r = self.l

        return self.y,

    def _new_blinds(self, ix):
        if self.blinds[ix] is None or len(self.blinds[ix]) != 8 or self.blinds[ix][0] is None:
            self.blinds[ix] = [(crypto.random_scalar() if self.do_blind else crypto.sc_init(1)) for _ in range(8)]
        else:
            for i in range(8):
                if self.do_blind:
                    crypto.random_scalar_into(self.blinds[ix][i])
                else:
                    # Neutral blinds for multiplicative / additive masking (only in meth3)
                    c = 0 if i < 4 and i % 2 == 0 and self.off_method >= 3 and self.round == 0 else 1
                    crypto.sc_init_into(self.blinds[ix][i], c)

    def _swap_blinds(self):
        self.blinds[0], self.blinds[1] = self.blinds[1], self.blinds[0]

    def _prove_new_blinds(self):
        self._new_blinds(0)

    def _prove_new_blindsN(self):
        self._new_blinds(1)

    def _phase2_loop0_clcr(self, buffers):
        """
        Loop0 for offloaded operation.
        Caller passes a[0..nprime], b[nprime..np2] in chunks
        1 sub phase: a0, b1, G1, H0   - computes cL, Lc; state = 20
        2 sub phase: a1, b0, G0, H1   - computes cR, Rc; state = 21
        state 22, 23 = folding; G, H from the memory
        state 24, 25 = folding a, b; maps to state 5, 6
        """
        _eprint('phase2_loop0_clcr, state: %s, off: %s, round: %s, nprime: %s' % (self.offstate, self.offpos, self.round, self.nprime))
        if self.round == 0 and (self.Gprime is None or self.Hprime is None or self.HprimeL is None):
            self._phase2_loop_body_r0init()

        if self.cL is None or (self.offstate == 20 and self.offpos == 0):
            self.cL = _ensure_dst_key()
            self.cR = _ensure_dst_key()
            self.winv = _ensure_dst_key()
            self.w_round = _ensure_dst_key()

        if self.LcA is None or (self.offstate == 20 and self.offpos == 0):
            crypto.identity_into(_tmp_pt_1)
            self.LcA = bytearray(crypto.encodepoint(_tmp_pt_1))
            self.LcB = bytearray(crypto.encodepoint(_tmp_pt_1))
            self.RcA = bytearray(crypto.encodepoint(_tmp_pt_1))
            self.RcB = bytearray(crypto.encodepoint(_tmp_pt_1))

        a, b = KeyV(self.batching, buffers[0]), KeyV(self.batching, buffers[1])
        G, H = None, None
        if self.round == 0:
            if self.offstate == 20:
                H = KeyVSliced(self.Hprime, self.offpos, min(self.offpos + self.batching, self.nprime))
                G = KeyVSliced(self.Gprime, self.nprime + self.offpos, self.nprime + min(self.offpos + self.batching, 2 * self.nprime))
            else:
                G = KeyVSliced(self.Gprime, self.offpos, min(self.offpos + self.batching, self.nprime))
                H = KeyVSliced(self.Hprime, self.nprime + self.offpos, self.nprime + min(self.offpos + self.batching, 2 * self.nprime))
        else:
            G, H = KeyV(self.batching, buffers[2]), KeyV(self.batching, buffers[3])

        cX = self.cL if self.offstate == 20 else self.cR
        XcA = self.LcA if self.offstate == 20 else self.RcA
        XcB = self.LcB if self.offstate == 20 else self.RcB
        tmp = _ensure_dst_key()
        self.gc(2)

        for i in range(len(a)):
            _sc_muladd(cX, a.to(i), b.to(i), cX)  # cX dot product

            _scalarmult_key(tmp, G.to(i), a.to(i))  # XcA scalarmult
            _add_keys(XcA, XcA, tmp)

            _scalarmult_key(tmp, H.to(i), b.to(i))  # XcA scalarmult
            _add_keys(XcB, XcB, tmp)

        self.gc(10)
        self.offpos += min(len(a), self.batching)
        if self.offpos >= self.nprime:# * 2:
            # Unblinding vectors with half-blinded masks
            # Ordering: G,  H,  a,  b,  (01, 23, 45, 67)
            # State 20: G1, H0, a0, b1; 1, 2, 4, 7
            # State 21: G0, H1, a1, b0; 0, 3, 5, 6
            blidx = (1, 2, 4, 7) if self.offstate == 20 else (0, 3, 5, 6)
            cbl = [self.blinds[0][x] for x in blidx]

            # unblind cX
            _sc_mul(tmp, a_raw=cbl[2], b_raw=cbl[3])
            _invert(tmp, tmp)
            _sc_mul(cX, cX, tmp)

            # unblind XcA
            _sc_mul(tmp, a_raw=cbl[2], b_raw=cbl[0] if self.round > 0 else crypto.decodeint(_ONE))
            _invert(tmp, tmp)
            _scalarmult_key(XcA, XcA, tmp)

            # unblind XcB
            _sc_mul(tmp, a_raw=cbl[3], b_raw=cbl[1] if self.round > 0 else crypto.decodeint(_ONE))
            _invert(tmp, tmp)
            _scalarmult_key(XcB, XcB, tmp)
            self.gc(11)

            if self.offstate == 20:  # Finish Lc
                # print('x_ip: ', ubinascii.hexlify(self.x_ip))
                _eprint('r: %s, cL ' % self.round, ubinascii.hexlify(self.cL))
                _add_keys(_tmp_bf_0, self.LcA, self.LcB)
                _sc_mul(tmp, self.cL, self.x_ip)
                _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(self.tmp_k_1, tmp))
                _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
                self.L.read(self.round, _tmp_bf_0)
                _eprint('r: %s, Lc ' % self.round, ubinascii.hexlify(self.L.to(self.round)))
                self.gc(12)

            elif self.offstate == 21:  # finish Rc, w
                # print('x_ip: ', ubinascii.hexlify(self.x_ip))
                _eprint('r: %s, cR ' % self.round, ubinascii.hexlify(self.cR))
                _add_keys(_tmp_bf_0, self.RcA, self.RcB)
                _sc_mul(tmp, self.cR, self.x_ip)
                _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(self.tmp_k_1, tmp))
                _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
                self.R.read(self.round, _tmp_bf_0)
                _eprint('r: %s, Rc ' % self.round, ubinascii.hexlify(self.R.to(self.round)))
                self.gc(13)

                # PAPER LINES 21-22
                _hash_cache_mash(self.w_round, self.hash_cache, self.L.to(self.round), self.R.to(self.round))
                if self.w_round == _ZERO:
                    return (0,)

                # PAPER LINES 24-25, fold {G~, H~}
                _invert(self.winv, self.w_round)
                self.gc(26)
                _eprint('r: %s, w0 ' % self.round, ubinascii.hexlify(self.w_round))
                _eprint('r: %s, wi ' % self.round, ubinascii.hexlify(self.winv))

                # New blinding factors to use for newly folded vectors
                self._prove_new_blindsN()
                self.gc(14)

            else:
                raise ValueError('Invalid state: %s' % self.offstate)

            self.offpos = 0
            self.offstate += 1
            _eprint('Moved to state ', self.offstate)

        self.gc(15)
        if self.round == 0:
            self._phase2_loop_body_r0dump()

        # In the round0 we do Trezor folding anyway due to G, H being only on the Trezor
        # Optimization: aprime, bprime could be computed on the Host
        if self.offstate >= 22:
            _eprint('Move to state 3 (folding)')
            self.offstate = 3

            if self.off_method >= 2:
                _eprint('fold offload')
                return self._compute_folding_consts()

    def _phase2_loop_offdot(self, buffers):
        """
        Comp computes dot products, blinded, de-blind
        Computes cL, cR, Lc, Rc, w
        Offstate = 2
        """
        _eprint('_phase2_loop_offdot, state: %s, off: %s, round: %s, nprime: %s' % (self.offstate, self.offpos, self.round, self.nprime))
        if not self.w_round:
            self.winv = _ensure_dst_key()
            self.w_round = _ensure_dst_key()

        if self.Gprime is None and self.round == 0:
            self._phase2_loop_body_r0init()

        self.gc(2)
        tmp = _ensure_dst_key()
        self.tmp_k_1 = _ensure_dst_key()

        cL, cR = buffers[0], buffers[1]
        LcA, LcB = buffers[2], buffers[3]
        RcA, RcB = buffers[4], buffers[5]

        # blind masks: G0 G1 H0 H1 a0 a1 b0 b1
        # blind masks: 0  1  2  3  4  5  6  7
        ibls = [_invert(None, crypto.encodeint(x)) for x in self.blinds[0]]

        cL = _sc_mul(cL, cL, ibls[4])  # unblind a0
        cL = _sc_mul(cL, cL, ibls[7])  # unblind b1

        cR = _sc_mul(cR, cR, ibls[5])  # unblind a1
        cR = _sc_mul(cR, cR, ibls[6])  # unblind b0
        self.gc(10)

        _eprint('r:', self.round, 'cL', _ehexlify(cL))
        _eprint('r:', self.round, 'cR', _ehexlify(cR))

        # products from round 0 are not blinded as Gprime and Hprime are protocol constants
        if self.round == 0:
            ibls[0], ibls[1], ibls[2], ibls[3] = _ONE, _ONE, _ONE, _ONE

        LcA = _scalarmult_key(LcA, LcA, _sc_mul(None, ibls[4], ibls[1]))  # a0 G1
        RcA = _scalarmult_key(RcA, RcA, _sc_mul(None, ibls[5], ibls[0]))  # a1 G0

        LcB = _scalarmult_key(LcB, LcB, _sc_mul(None, ibls[7], ibls[2]))  # b1 H0
        RcB = _scalarmult_key(RcB, RcB, _sc_mul(None, ibls[6], ibls[3]))  # b0 H1
        del(ibls)
        self.gc(11)

        _add_keys(LcA, LcA, LcB)
        _sc_mul(tmp, cL, self.x_ip)
        _add_keys(LcA, LcA, _scalarmultH(self.tmp_k_1, tmp))
        _scalarmult_key(LcA, LcA, _INV_EIGHT)
        self.L.read(self.round, LcA)
        del(cL, LcA, LcB)
        self.gc(12)

        _add_keys(RcA, RcA, RcB)
        _sc_mul(tmp, cR, self.x_ip)
        _add_keys(RcA, RcA, _scalarmultH(self.tmp_k_1, tmp))
        _scalarmult_key(RcA, RcA, _INV_EIGHT)
        self.R.read(self.round, RcA)
        del(cR, RcA, RcB, tmp)
        self.gc(13)

        _eprint('r:', self.round, 'Lc', _ehexlify(self.L.to(self.round)))
        _eprint('r:', self.round, 'Rc', _ehexlify(self.R.to(self.round)))

        # PAPER LINES 21-22
        _hash_cache_mash(self.w_round, self.hash_cache, self.L.to(self.round), self.R.to(self.round))
        if self.w_round == _ZERO:
            return (0,)

        # PAPER LINES 24-25, fold {G~, H~}
        _invert(self.winv, self.w_round)
        self.gc(14)

        _eprint('r:', self.round, 'w0', _ehexlify(self.w_round))
        _eprint('r:', self.round, 'w1', _ehexlify(self.winv))

        # New blinding factors to use for newly folded vectors
        self._prove_new_blindsN()
        self.offstate, self.offpos = 3, 0
        self.gc(15)

        # Backup state if needed
        if self.round == 0:
            self._phase2_loop_body_r0dump()

        # If the first round of the ofdot, we cannot do in
        if self.off_method >= 1 and self.round == 0:
            _eprint('Fold now')
            tconst = self._compute_folding_consts() if self.off_method >= 2 else None
            return tconst

        # When offloading also the folding - return blinding constants
        if self.off_method >= 2 and self.nprime <= self.off2_thresh:
            _eprint('Off2, fold anyway - threshold reached')
            return

        # Offload the folding - compute constants
        if self.off_method >= 2:
            _eprint('fold offload')
            tconst = self._compute_folding_consts()

            # State 20 - clcr, dot products by the host
            self.offstate = 2
            self.nprime >>= 1
            self.round += 1
            self._swap_blinds()
            if self.round == 1:
                self._phase2_loop_body_r0del()
            self.Gprime = None
            self.Hprime = None
            self.aprime = None
            self.bprime = None
            return tconst

    def _compute_folding_consts(self):
        """
        Computes offloaded folding constants
        """
        # Constatns: 4 per vector.
        # Example, folding of the Gprime:
        # Gp_{LO, i} = m_0 bl0^{-1} w^{-1} G_i   +   m_0 bl1^{-1} w G_{i+h}, i \in [0,        nprime/2]
        # Gp_{HI, i} = m_1 bl0^{-1} w^{-1} G_i   +   m_1 bl1^{-1} w G_{i+h}, i \in [nprime/2, nprime]
        # w constants: G H a b: -1 1 1 -1
        # blinvs indices: [2 * (i // 4) + (i % 2)]: 0 1 0 1, 2 3 2 3, ...
        #
        # Method 3 blinding for LO parts: (m_0 w^{-1} + bl0)
        w0 = crypto.decodeint_into_noreduce(None, self.w_round)
        wi = crypto.sc_inv_into(None, w0)
        blinvs = [crypto.new_scalar(), crypto.new_scalar()]
        tconst = [_ensure_dst_key() for _ in range(4*4)]
        for i in range(16):
            off_gh = self.round == 0 and self.off_method >= 2 and i < 8

            if i % 4 == 0:
                if off_gh:  # (Gprime, HPrime) round 0
                    crypto.sc_init_into(blinvs[1], 1)

                    # Offload initial G, H folding in a special way. Only the low parts. Additive mask.
                    if self.off_method >= 3:
                        crypto.sc_copy(blinvs[0], self.blinds[0][2 * (i // 4)])
                    else:
                        crypto.sc_init_into(blinvs[0], 1)

                else:
                    crypto.sc_inv_into(blinvs[0], self.blinds[0][2 * (i // 4)])
                    crypto.sc_inv_into(blinvs[1], self.blinds[0][2 * (i // 4) + 1])

            mi = self.blinds[1][i // 2]
            bi = blinvs[i % 2]
            x0, x1 = (wi, w0) if i // 4 in (0, 3) else (w0, wi)
            xi = x0 if i % 2 == 0 else x1

            crypto.sc_mul_into(_tmp_sc_1, mi, xi)

            # meth3 LO special additive mask (later removed by -biG)
            if off_gh and self.off_method >= 3 and (i % 2) == 0:
                crypto.sc_add_into(_tmp_sc_1, _tmp_sc_1, bi)
            elif not off_gh:
                crypto.sc_mul_into(_tmp_sc_1, _tmp_sc_1, bi)

            crypto.encodeint_into(tconst[i], _tmp_sc_1)

        del(blinvs, w0, wi)
        self.gc(22)
        return tconst

    def _phase2_loop_r0foldGH(self, buffers, tgt):
        """
        Initial folding of the Gprime, Hprime
        Folding constants are special for LO vectors - another random constant is introduced so
        High parts constants are 1 as the original G, H vectors are unblinded in the round 0.

        E.g., constants for G: (\theta_{G_{LO}} w \pi_{G_{LO}}, \theta_{G_{HI}} w^{-1})
        Host computes the folding with G, obtains:
        G_{LO} = (\theta_{G_{LO}} w + \pi_{G_{LO}}) G_i + \theta_{G_{LO}} w^{-1} G_{i+nprime}
        G_{HI} = (\theta_{G_{HI}} w + \pi_{G_{LO}}) G_i + \theta_{G_{HI}} w^{-1} G_{i+nprime}

        Both (G_{LO}, G_{HI}) contain extraneous \pi_{G_{LO}} G_i, thus we compute it here and host subtracts.
        Thus here produce just \pi_{G_{LO}} G_i for G_{LO} (and for H respectivelly)
        off_method = 3
        """
        _eprint('_phase2_loop_r0foldGH, state: %s, off: %s, round: %s, nprime: %s, btch: %s' % (self.offstate, self.offpos, self.round, self.nprime, self.batching))
        self.gc(2)

        if self.Gprime is None or self.HprimeL is None:
            self._phase2_loop_body_r0init()

        msk = self.blinds[0][2*(self.offstate - 3)]
        vct = self.Gprime if self.offstate == 3 else self.Hprime
        fld = KeyV(tgt)

        for i in range(0, tgt):
            _scalarmult_key(_tmp_bf_0, vct.to(self.offpos + i), None, msk)
            fld.read(i, _tmp_bf_0)
            _gc_iter(i)

        self.offpos += tgt
        return fld

    def _phase2_loop_ufold(self, buffers, tgt, inmem=False):
        """
        Universal folding
        """
        _eprint('_phase2_loop_ufold, state: %s, off: %s, round: %s, nprime: %s, btch: %s' % (self.offstate, self.offpos, self.round, self.nprime, self.batching))

        # Input buffer processing.
        # The first round has in-memory G, H buffers
        lo, hi = None, None

        if self.round == 0 and self.offstate in (3, 4):
            if self.Gprime is None or self.HprimeL is None:
                self._phase2_loop_body_r0init()

            if self.offpos == 0 and self.offstate == 4 and self.off_method <= 2:
                self.yinvpowR.reset()
                self.yinvpowR.rewind(self.nprime)

            if self.offstate == 3:
                lo = KeyVSliced(self.Gprime, self.offpos, min(self.offpos + tgt, self.nprime))
                hi = KeyVSliced(self.Gprime, self.nprime + self.offpos, self.nprime + min(self.offpos + tgt, 2 * self.nprime))
            else:
                lo = KeyVSliced(self.HprimeL, self.offpos, min(self.offpos + tgt, self.nprime))
                hi = KeyVSliced(self.HprimeR, self.nprime + self.offpos, self.nprime + min(self.offpos + tgt, 2 * self.nprime))

        else:
            lo, hi = KeyV(len(buffers[0])//32, buffers[0]), KeyV(len(buffers[1])//32, buffers[1])

        # In memory caching from some point
        self.gc(5)
        self.assrt(self.off_method < 2 or self.off2_thresh <= self.nprime_thresh, "off2 threshold invalid")
        fld = None

        if inmem:
            if self.offpos == 0:  # allocate in-memory buffers now
                fldS = KeyV(self.nprime)
                self.Xprime[self.offstate - 3] = fldS
            fld = KeyVSliced(self.Xprime[self.offstate - 3], self.offpos, min(self.offpos + tgt, self.nprime))
        else:
            fld = KeyV(tgt)

        # Consider blinding by halves
        # Folding has 4 different blind masks
        self.gc(10)
        if self.round == 0 and self.offstate in [3, 4]:
            blinv = (_ONE, _ONE)  # no blinding for in-memory Gprime, Hprime in the round 0
        else:
            blinv = (_invert(None, x_raw=self.blinds[0][2*(self.offstate - 3)]),
                     _invert(None, x_raw=self.blinds[0][2*(self.offstate - 3) + 1]))

        nbli  = None if inmem else (
            self.blinds[1][2*(self.offstate - 3)],
            self.blinds[1][2*(self.offstate - 3) + 1]
        )

        a0 = crypto.new_scalar()
        b0 = crypto.new_scalar()
        if self.offstate in [3, 6]:
            crypto.decodeint_into_noreduce(a0, _sc_mul(None, self.winv, blinv[0]))
            crypto.decodeint_into_noreduce(b0, _sc_mul(None, self.w_round, blinv[1]))
        elif self.offstate in [4, 5]:
            crypto.decodeint_into_noreduce(a0, _sc_mul(None, self.w_round, blinv[0]))
            crypto.decodeint_into_noreduce(b0, _sc_mul(None, self.winv, blinv[1]))

        del(blinv)
        self.gc(12)
        if self.offstate in [3, 4]:  # G, H
            for i in range(0, tgt):
                crypto.decodepoint_into(_tmp_pt_1, lo.to(i))
                crypto.decodepoint_into(_tmp_pt_2, hi.to(i))
                crypto.add_keys3_into(_tmp_pt_3, a0, _tmp_pt_1, b0, _tmp_pt_2)
                if nbli:
                    noff = int(i + self.offpos >= (self.nprime>>1))
                    crypto.scalarmult_into(_tmp_pt_3, _tmp_pt_3, nbli[noff])  # blind again
                crypto.encodepoint_into(_tmp_bf_0, _tmp_pt_3)
                fld.read(i, _tmp_bf_0)
                _gc_iter(i)

        elif self.offstate in [5, 6]:  # a, b
            for i in range(0, tgt):
                crypto.decodeint_into_noreduce(_tmp_sc_3, lo.to(i))
                crypto.decodeint_into_noreduce(_tmp_sc_4, hi.to(i))
                crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_3, a0)
                crypto.sc_mul_into(_tmp_sc_4, _tmp_sc_4, b0)
                crypto.sc_add_into(_tmp_sc_3, _tmp_sc_3, _tmp_sc_4)
                if nbli:
                    noff = int(i + self.offpos >= (self.nprime>>1))
                    crypto.sc_mul_into(_tmp_sc_3, _tmp_sc_3, nbli[noff])  # blind again
                crypto.encodeint_into(_tmp_bf_0, _tmp_sc_3)
                fld.read(i, _tmp_bf_0)
                _gc_iter(i)

        del(a0, b0, lo, hi, nbli)
        self.gc(15)

        self.offpos += tgt
        return fld

    def _phase2_loop_fold(self, buffers):
        """
        Computes folding per partes
        States: 3, 4, 5, 6
        """
        # _eprint('phase2_loop_fold, state: %s, off: %s, round: %s, nprime: %s, btch: %s' % (self.offstate, self.offpos, self.round, self.nprime, self.batching))
        self.gc(2)

        cbatching = self.batching
        if self.round == 0 and self.offstate in (3, 4):
            cbatching *= 2  # same memory usage as no input is given

        tgt = min(cbatching, self.nprime)
        inmem = self.round > 0 and (self.nprime <= self.nprime_thresh or (self.off_method >= 2 and self.nprime <= self.off2_thresh))

        if self.off_method == 3 and self.round == 0 and self.offstate in (3, 4):
            fld = self._phase2_loop_r0foldGH(buffers, tgt)
        else:
            fld = self._phase2_loop_ufold(buffers, tgt, inmem)

        # State transition
        if self.offpos >= self.nprime:
            self.offpos = 0
            self.offstate += 1
            _eprint('Moved to state %s, npr %s' % (self.offstate, self.nprime))

            if self.nprime == 1:
                if self.offstate == 6:
                    self.a = fld.to(0)

                if self.offstate == 7:
                    self.b = fld.to(0)

        if self.offstate >= 7 or (self.round == 0 and self.off_method >= 2 and self.offstate >= 5):
            self.nprime >>= 1
            self.round += 1

            if self.round == 1:
                self._phase2_loop_body_r0del()

            self.gc(16)

            if inmem:
                self.offstate = 10  # finish in-memory, _phase2_loop_full

            elif self.off_method >= 1:
                self.offstate = 2   # another loop, cLcR offdot

            else:
                self.offstate = 20  # manual cLcR

            _eprint('Moved to state', self.offstate)

            # Rotate blindings
            self._swap_blinds()

        elif self.round == 0 and self.offstate in (3, 4):
            self._phase2_loop_body_r0dump()

        if self.nprime <= 0:
            self.offstate = 12  # final, _phase2_final
            _eprint('Terminating')

        if not inmem:
            fldd = fld.d
            del(fld)
            return fldd

    def _phase2_final(self):
        return (
            1,
            Bulletproof(
                V=self.V, A=self.A, S=self.S, T1=self.T1, T2=self.T2, taux=self.taux, mu=self.mu, L=self.L, R=self.R, a=self.a, b=self.b, t=self.t
            ),
        )

    def _phase2_loop_full(self):
        while self.nprime >= 1:
            self._phase2_loop_body()
        self.a = self.aprime.to(0)
        self.b = self.bprime.to(0)
        return self._phase2_final()

    def _phase2_loop_body_r0init(self):
        """
        Initializes Gprime, HPrime for the round0, state in self.HprimeLRst
        """
        # _eprint('_phase2_loop_body_r0init, state: %s, off: %s' % (self.offstate, self.offpos))
        if self.Gprec is None or self.Hprec2 is None:
            self.Gprec2 = self._gprec_aux(self.MN)
            self.Hprec2 = self._hprec_aux(self.MN)

        self.yinvpowL = KeyVPowers(self.MN, _invert(_tmp_bf_0, self.y), raw=True)
        self.yinvpowR = KeyVPowers(self.MN, _tmp_bf_0, raw=True)
        self.tmp_pt = crypto.new_point()

        self.Gprime = self.Gprec2
        self.HprimeL = KeyVEval(
            self.MN, lambda i, d: _scalarmult_key(d, self.Hprec2.to(i), None, self.yinvpowL[i])
        )

        self.HprimeR = KeyVEval(
            self.MN, lambda i, d: _scalarmult_key(d, self.Hprec2.to(i), None, self.yinvpowR[i], self.tmp_pt)
        )
        self.Hprime = self.HprimeL

        if self.HprimeLRst:
            self.yinvpowL.sload(self.HprimeLRst[0])
            self.yinvpowR.sload(self.HprimeLRst[1])
            self.HprimeLRst = None

        self.gc(34)

    def _phase2_loop_body_r0del(self):
        del (self.Gprec2, self.Hprec2, self.yinvpowL, self.yinvpowR, self.HprimeL, self.HprimeR, self.tmp_pt, self.HprimeLRst)

    def _phase2_loop_body_r0clear(self):
        self.yinvpowL = None
        self.yinvpowR = None
        self.HprimeL = None
        self.HprimeR = None
        self.tmp_pt = None
        self.Gprec2 = None
        self.Hprec2 = None

    def _phase2_loop_body_r0dump(self):
        self.HprimeLRst = self.yinvpowL.sdump(), self.yinvpowR.sdump()
        self._phase2_loop_body_r0clear()

    def _phase2_loop_body(self):
        """
        One loop for the prover loop.
        Assumes nprime = MN/2 on the beginning.
        """
        _eprint('_phase2_loop_body, state: %s, off: %s' % (self.offstate, self.offpos))
        _eprint('wloop: M: %s, r: %s, nprime: %s' % (self.M, self.round, self.nprime))

        if self.round == 0 and (self.Gprime is None or len(self.Gprime) != 2*self.nprime):
            self._phase2_loop_body_r0init()

        if self.cL is None:
            self.cL = _ensure_dst_key()
            self.cR = _ensure_dst_key()

        # PAPER LINE 15
        nprime = self.nprime
        npr2 = self.nprime * 2
        cL = self.cL
        cR = self.cR
        self.tmp = _ensure_dst_key()
        self.gc(22)

        # PAPER LINES 16-17
        # cL = \ap_{\left(\inta\right)} \cdot \bp_{\left(\intb\right)}
        # cR = \ap_{\left(\intb\right)} \cdot \bp_{\left(\inta\right)}
        _inner_product(
            self.aprime.slice_view(0, nprime), self.bprime.slice_view(nprime, npr2), cL
        )

        _inner_product(
            self.aprime.slice_view(nprime, npr2), self.bprime.slice_view(0, nprime), cR
        )
        # _eprint('r: %s, cL ' % self.round, ubinascii.hexlify(cL))
        # _eprint('r: %s, cR ' % self.round, ubinascii.hexlify(cR))
        self.gc(23)

        # PAPER LINES 18-19
        # Lc = 8^{-1} \left(\left( \sum_{i=0}^{\np} \ap_{i}\quad\Gp_{i+\np} + \bp_{i+\np}\Hp_{i} \right)
        # 		    + \left(c_L x_{ip}\right)H \right)
        _vector_exponent_custom(
            self.Gprime.slice_view(nprime, npr2),
            self.Hprime.slice_view(0, nprime),
            self.aprime.slice_view(0, nprime),
            self.bprime.slice_view(nprime, npr2),
            _tmp_bf_0,
        )

        # In round 0 backup the y^{prime - 1}
        if self.round == 0:
            self.yinvpowR.set_state(self.yinvpowL.last_idx, self.yinvpowL.cur)

        _sc_mul(self.tmp, cL, self.x_ip)
        _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(self.tmp_k_1, self.tmp))
        _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
        self.L.read(self.round, _tmp_bf_0)
        self.gc(24)

        # Rc = 8^{-1} \left(\left( \sum_{i=0}^{\np} \ap_{i+\np}\Gp_{i}\quad + \bp_{i}\quad\Hp_{i+\np} \right)
        #           + \left(c_R x_{ip}\right)H \right)
        _vector_exponent_custom(
            self.Gprime.slice_view(0, nprime),
            self.Hprime.slice_view(nprime, npr2),
            self.aprime.slice_view(nprime, npr2),
            self.bprime.slice_view(0, nprime),
            _tmp_bf_0,
        )

        _sc_mul(self.tmp, cR, self.x_ip)
        _add_keys(_tmp_bf_0, _tmp_bf_0, _scalarmultH(self.tmp_k_1, self.tmp))
        _scalarmult_key(_tmp_bf_0, _tmp_bf_0, _INV_EIGHT)
        self.R.read(self.round, _tmp_bf_0)
        self.gc(25)

        # _eprint('r: %s, Lc ' % self.round, ubinascii.hexlify(self.L.to(self.round)))
        # _eprint('r: %s, Rc ' % self.round, ubinascii.hexlify(self.R.to(self.round)))

        # PAPER LINES 21-22
        _hash_cache_mash(self.w_round, self.hash_cache, self.L.to(self.round), self.R.to(self.round))
        if self.w_round == _ZERO:
            return (0,)

        # PAPER LINES 24-25, fold {G~, H~}
        _invert(self.winv, self.w_round)
        self.gc(26)

        # _eprint('r: %s, w0 ' % self.round, ubinascii.hexlify(self.w_round))
        # _eprint('r: %s, wi ' % self.round, ubinascii.hexlify(self.winv))

        # PAPER LINES 28-29, fold {a, b} vectors
        # aprime's high part is used as a buffer for other operations
        _scalar_fold(self.aprime, self.w_round, self.winv)
        self.aprime.resize(nprime)
        self.gc(27)

        _scalar_fold(self.bprime, self.winv, self.w_round)
        self.bprime.resize(nprime)
        self.gc(28)

        # First fold produced to a new buffer, smaller one (G~ on-the-fly)
        Gprime_new = KeyV(nprime) if self.round == 0 else self.Gprime
        self.Gprime = _hadamard_fold(self.Gprime, self.winv, self.w_round, Gprime_new, 0)
        self.Gprime.resize(nprime)
        self.gc(30)

        # Hadamard fold for H is special - linear scan only.
        # Linear scan is slow, thus we have HprimeR.
        if self.round == 0:
            Hprime_new = KeyV(nprime)
            self.Hprime = _hadamard_fold(
                self.Hprime, self.w_round, self.winv, Hprime_new, 0, self.HprimeR, nprime
            )
            # Hprime = _hadamard_fold_linear(Hprime, w_round, winv, Hprime_new, 0)

        else:
            _hadamard_fold(self.Hprime, self.w_round, self.winv)
            self.Hprime.resize(nprime)

        # _eprint('r: %s, ap ' % self.round, ubinascii.hexlify(self.aprime.d[-64:]))
        # _eprint('r: %s, bp ' % self.round, ubinascii.hexlify(self.bprime.d[-64:]))
        # _eprint('r: %s, Gp ' % self.round, ubinascii.hexlify(self.Gprime.d[-64:]))
        # _eprint('r: %s, Hp ' % self.round, ubinascii.hexlify(self.Hprime.d[-64:]))

        if self.round == 0:
            # del (Gprec, Hprec, yinvpowL, HprimeL)
            del (self.Gprec2, self.Hprec2, self.yinvpowL, self.yinvpowR, self.HprimeL, self.HprimeR, self.tmp_pt)

        self.gc(31)
        self.round += 1
        self.nprime >>= 1

    def _prove_loop(self, MN, logMN, l, r, y, x_ip, hash_cache, Gprec, Hprec):
        """
        Prover phase 2 - loop.
        Used only for in-memory computations.
        """
        self.nprime = MN >> 1
        self.aprime = l
        self.bprime = r
        self.hash_cache = hash_cache
        self.x_ip = x_ip
        self.y = y

        self.Gprec2 = Gprec
        self.Hprec2 = Hprec
        self.gc(20)

        self.L = _ensure_dst_keyvect(None, logMN)
        self.R = _ensure_dst_keyvect(None, logMN)
        self.cL = _ensure_dst_key()
        self.cR = _ensure_dst_key()
        self.winv = _ensure_dst_key()
        self.w_round = _ensure_dst_key()
        self.tmp = _ensure_dst_key()
        self.tmp_k_1 = _ensure_dst_key()
        self.round = 0

        # PAPER LINE 13
        while self.nprime >= 1:
            self._phase2_loop_body()
            self.gc(31)

        return self.L, self.R, self.aprime.to(0), self.bprime.to(0)

    def verify(self, proof):
        return self.verify_batch([proof])

    def verify_batch(self, proofs, single_optim=True):
        """
        BP batch verification
        :param proofs:
        :param single_optim: single proof memory optimization
        :return:
        """
        max_length = 0
        for proof in proofs:
            self.assrt(_is_reduced(proof.taux), "Input scalar not in range")
            self.assrt(_is_reduced(proof.mu), "Input scalar not in range")
            self.assrt(_is_reduced(proof.a), "Input scalar not in range")
            self.assrt(_is_reduced(proof.b), "Input scalar not in range")
            self.assrt(_is_reduced(proof.t), "Input scalar not in range")
            self.assrt(len(proof.V) >= 1, "V does not have at least one element")
            self.assrt(len(proof.L) == len(proof.R), "|L| != |R|")
            self.assrt(len(proof.L) > 0, "Empty proof")
            max_length = max(max_length, len(proof.L))

        self.assrt(max_length < 32, "At least one proof is too large")

        maxMN = 1 << max_length
        logN = 6
        N = 1 << logN
        tmp = _ensure_dst_key()

        # setup weighted aggregates
        is_single = len(proofs) == 1 and single_optim  # ph4
        z1 = _init_key(_ZERO)
        z3 = _init_key(_ZERO)
        m_z4 = _vector_dup(_ZERO, maxMN) if not is_single else None
        m_z5 = _vector_dup(_ZERO, maxMN) if not is_single else None
        m_y0 = _init_key(_ZERO)
        y1 = _init_key(_ZERO)
        muex_acc = _init_key(_ONE)

        Gprec = self._gprec_aux(maxMN)
        Hprec = self._hprec_aux(maxMN)

        for proof in proofs:
            M = 1
            logM = 0
            while M <= _BP_M and M < len(proof.V):
                logM += 1
                M = 1 << logM

            self.assrt(len(proof.L) == 6 + logM, "Proof is not the expected size")
            MN = M * N
            weight_y = crypto.encodeint(crypto.random_scalar())
            weight_z = crypto.encodeint(crypto.random_scalar())

            # Reconstruct the challenges
            hash_cache = _hash_vct_to_scalar(None, proof.V)
            y = _hash_cache_mash(None, hash_cache, proof.A, proof.S)
            self.assrt(y != _ZERO, "y == 0")
            z = _hash_to_scalar(None, y)
            _copy_key(hash_cache, z)
            self.assrt(z != _ZERO, "z == 0")

            x = _hash_cache_mash(None, hash_cache, z, proof.T1, proof.T2)
            self.assrt(x != _ZERO, "x == 0")
            x_ip = _hash_cache_mash(None, hash_cache, x, proof.taux, proof.mu, proof.t)
            self.assrt(x_ip != _ZERO, "x_ip == 0")

            # PAPER LINE 61
            _sc_mulsub(m_y0, proof.taux, weight_y, m_y0)
            zpow = _vector_powers(z, M + 3)

            k = _ensure_dst_key()
            ip1y = _vector_power_sum(y, MN)
            _sc_mulsub(k, zpow.to(2), ip1y, _ZERO)
            for j in range(1, M + 1):
                self.assrt(j + 2 < len(zpow), "invalid zpow index")
                _sc_mulsub(k, zpow.to(j + 2), _BP_IP12, k)

            # VERIFY_line_61rl_new
            _sc_muladd(tmp, z, ip1y, k)
            _sc_sub(tmp, proof.t, tmp)

            _sc_muladd(y1, tmp, weight_y, y1)
            weight_y8 = _init_key(weight_y)
            weight_y8 = _sc_mul(None, weight_y, _EIGHT)

            muex = MultiExpSequential(points=[pt for pt in proof.V])
            for j in range(len(proof.V)):
                _sc_mul(tmp, zpow.to(j + 2), weight_y8)
                muex.add_scalar(_init_key(tmp))

            _sc_mul(tmp, x, weight_y8)
            muex.add_pair(_init_key(tmp), proof.T1)

            xsq = _ensure_dst_key()
            _sc_mul(xsq, x, x)

            _sc_mul(tmp, xsq, weight_y8)
            muex.add_pair(_init_key(tmp), proof.T2)

            weight_z8 = _init_key(weight_z)
            weight_z8 = _sc_mul(None, weight_z, _EIGHT)

            muex.add_pair(weight_z8, proof.A)
            _sc_mul(tmp, x, weight_z8)
            muex.add_pair(_init_key(tmp), proof.S)

            _multiexp(tmp, muex, False)
            _add_keys(muex_acc, muex_acc, tmp)
            del muex

            # Compute the number of rounds for the inner product
            rounds = logM + logN
            self.assrt(rounds > 0, "Zero rounds")

            # PAPER LINES 21-22
            # The inner product challenges are computed per round
            w = _ensure_dst_keyvect(None, rounds)
            for i in range(rounds):
                _hash_cache_mash(_tmp_bf_0, hash_cache, proof.L[i], proof.R[i])
                w.read(i, _tmp_bf_0)
                self.assrt(w.to(i) != _ZERO, "w[i] == 0")

            # Basically PAPER LINES 24-25
            # Compute the curvepoints from G[i] and H[i]
            yinvpow = _init_key(_ONE)
            ypow = _init_key(_ONE)
            yinv = _invert(None, y)
            self.gc(61)

            winv = _ensure_dst_keyvect(None, rounds)
            for i in range(rounds):
                _invert(_tmp_bf_0, w.to(i))
                winv.read(i, _tmp_bf_0)
                self.gc(62)

            g_scalar = _ensure_dst_key()
            h_scalar = _ensure_dst_key()
            twoN = self._two_aux(N)
            for i in range(MN):
                _copy_key(g_scalar, proof.a)
                _sc_mul(h_scalar, proof.b, yinvpow)

                for j in range(rounds - 1, -1, -1):
                    J = len(w) - j - 1

                    if (i & (1 << j)) == 0:
                        _sc_mul(g_scalar, g_scalar, winv.to(J))
                        _sc_mul(h_scalar, h_scalar, w.to(J))
                    else:
                        _sc_mul(g_scalar, g_scalar, w.to(J))
                        _sc_mul(h_scalar, h_scalar, winv.to(J))

                # Adjust the scalars using the exponents from PAPER LINE 62
                _sc_add(g_scalar, g_scalar, z)
                self.assrt(2 + i // N < len(zpow), "invalid zpow index")
                self.assrt(i % N < len(twoN), "invalid twoN index")
                _sc_mul(tmp, zpow.to(2 + i // N), twoN.to(i % N))
                _sc_muladd(tmp, z, ypow, tmp)
                _sc_mulsub(h_scalar, tmp, yinvpow, h_scalar)

                if not is_single:  # ph4
                    m_z4.read(i, _sc_mulsub(_tmp_bf_0, g_scalar, weight_z, m_z4[i]))
                    m_z5.read(i, _sc_mulsub(_tmp_bf_0, h_scalar, weight_z, m_z5[i]))
                else:
                    _sc_mul(tmp, g_scalar, weight_z)
                    _sub_keys(
                        muex_acc, muex_acc, _scalarmult_key(tmp, Gprec.to(i), tmp)
                    )

                    _sc_mul(tmp, h_scalar, weight_z)
                    _sub_keys(
                        muex_acc, muex_acc, _scalarmult_key(tmp, Hprec.to(i), tmp)
                    )

                if i != MN - 1:
                    _sc_mul(yinvpow, yinvpow, yinv)
                    _sc_mul(ypow, ypow, y)
                if i & 15 == 0:
                    self.gc(62)

            del (g_scalar, h_scalar, twoN)
            self.gc(63)

            _sc_muladd(z1, proof.mu, weight_z, z1)
            muex = MultiExpSequential(
                point_fnc=lambda i, d: proof.L[i // 2]
                if i & 1 == 0
                else proof.R[i // 2]
            )
            for i in range(rounds):
                _sc_mul(tmp, w.to(i), w.to(i))
                _sc_mul(tmp, tmp, weight_z8)
                muex.add_scalar(tmp)
                _sc_mul(tmp, winv.to(i), winv.to(i))
                _sc_mul(tmp, tmp, weight_z8)
                muex.add_scalar(tmp)

            acc = _multiexp(None, muex, False)
            _add_keys(muex_acc, muex_acc, acc)

            _sc_mulsub(tmp, proof.a, proof.b, proof.t)
            _sc_mul(tmp, tmp, x_ip)
            _sc_muladd(z3, tmp, weight_z, z3)

        _sc_sub(tmp, m_y0, z1)
        z3p = _sc_sub(None, z3, y1)

        check2 = crypto.encodepoint(
            crypto.ge25519_double_scalarmult_base_vartime(
                crypto.decodeint(z3p), crypto.xmr_H(), crypto.decodeint(tmp)
            )
        )
        _add_keys(muex_acc, muex_acc, check2)

        if not is_single:  # ph4
            muex = MultiExpSequential(
                point_fnc=lambda i, d: Gprec.to(i // 2)
                if i & 1 == 0
                else Hprec.to(i // 2)
            )
            for i in range(maxMN):
                muex.add_scalar(m_z4[i])
                muex.add_scalar(m_z5[i])
            _add_keys(muex_acc, muex_acc, _multiexp(None, muex, True))

        if muex_acc != _ONE:
            raise ValueError("Verification failure at step 2")
        return True


# Exports:
ensure_dst_keyvect = _ensure_dst_keyvect
multiexp = _multiexp
vector_exponent_custom = _vector_exponent_custom
hadamard_fold = _hadamard_fold
scalar_fold = _scalar_fold
inner_product = _inner_product
vector_sum_aA = _vector_sum_aA
invert = _invert
scalarmult_key = _scalarmult_key
