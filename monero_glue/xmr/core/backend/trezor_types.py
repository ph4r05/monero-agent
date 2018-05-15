import ctypes as ct


FE = ct.c_uint32 * 10
MODM = ct.c_uint32 * 9
KEY_BUFF = ct.c_byte * 32


class Ge25519(ct.Structure):
    _fields_ = [
        ('x', FE),
        ('y', FE),
        ('z', FE),
        ('t', FE),
    ]


class Ge25519_p1p1(ct.Structure):
    _fields_ = [
        ('x', FE),
        ('y', FE),
        ('z', FE),
        ('t', FE),
    ]


class Ge25519_niels(ct.Structure):
    _fields_ = [
        ('ysubx', FE),
        ('xaddy', FE),
        ('t2d', FE),
    ]


class Ge25519_pniels(ct.Structure):  # projective Cached / Deuis
    _fields_ = [
        ('ysubx', FE),
        ('xaddy', FE),
        ('z', FE),
        ('t2d', FE),
    ]


XmrAmount = ct.c_uint64

# XmrKey is not a structure but a direct buffer so it can be used
# in the transaction in a straightforward way.
XmrKey = KEY_BUFF


class XmrCtKey(ct.Structure):
    _fields_ = [
        ('dest', XmrKey),
        ('mask', XmrKey),
    ]


XmrKey64 = XmrKey * 64


class XmrBoroSig(ct.Structure):
    _fields_ = [
        ('s0', XmrKey64),
        ('s1', XmrKey64),
        ('ee', XmrKey),
    ]


class XmrRangeSig(ct.Structure):
    _fields_ = [
        ('asig', XmrBoroSig),
        ('Ci', XmrKey64),
    ]


# ./sha2.h: 56
class struct__SHA256_CTX(ct.Structure):
    __slots__ = ['state', 'bitcount', 'buffer']
    _fields_ = [
        ('state', ct.c_uint32 * 8),
        ('bitcount', ct.c_uint64),
        ('buffer', ct.c_uint32 * (64 // ct.sizeof(ct.c_uint32))),
    ]


SHA256_CTX = struct__SHA256_CTX  # ./sha2.h: 56


# ./sha3.h: 60
class struct_SHA3_CTX(ct.Structure):
    __slots__ = ['hash', 'message', 'rest', 'block_size']

    _fields_ = [
        ('hash', ct.c_uint64 * 25),
        ('message', ct.c_uint64 * 24),
        ('rest', ct.c_uint),
        ('block_size', ct.c_uint),
    ]


SHA3_CTX = struct_SHA3_CTX


# ./blake256.h: 45
class struct_anon_2(ct.Structure):
    __slots__ = ['h', 's', 't', 'buflen', 'nullt', 'buf']
    _fields_ = [
        ('h', ct.c_uint32 * 8),
        ('s', ct.c_uint32 * 4),
        ('t', ct.c_uint32 * 2),
        ('buflen', ct.c_size_t),
        ('nullt', ct.c_uint8),
        ('buf', ct.c_ubyte * 64),
    ]


BLAKE256_CTX = struct_anon_2  # ./blake256.h: 45


# ./groestl.h: 54
class union_anon_3(ct.Union):
    __slots__ = ['wide', 'narrow']
    _fields_ = [
        ('wide', ct.c_uint64 * 16),
        ('narrow', ct.c_uint32 * 32),
    ]


# ./groestl.h: 59
class struct_anon_4(ct.Structure):
    __slots__ = ['buf', 'ptr', 'state', 'count']
    _fields_ = [
        ('buf', ct.c_ubyte * 128),
        ('ptr', ct.c_size_t),
        ('state', union_anon_3),
        ('count', ct.c_uint64),
    ]


sph_groestl_big_context = struct_anon_4  # ./groestl.h: 59
GROESTL512_CTX = sph_groestl_big_context # ./groestl.h: 61


class UnionHasher(ct.Union):
    __slots__ = ['sha2', 'sha3', 'blake', 'groestl']
    _fields_ = [
        ('sha2', SHA256_CTX),
        ('sha3', SHA3_CTX),
        ('blake', BLAKE256_CTX),
        ('groestl', GROESTL512_CTX),
    ]


# ./hasher.h: 61
class struct_anon_7(ct.Structure):
    __slots__ = ['type', 'ctx']
    _fields_ = [
        ('type', ct.c_int),
        ('ctx', UnionHasher),
    ]


Hasher = struct_anon_7


