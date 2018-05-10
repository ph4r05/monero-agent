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


class XmrKey(ct.Structure):
    _fields_ = [
        ('data', KEY_BUFF),
    ]


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

