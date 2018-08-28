from monero_glue.xmr import crypto
from monero_glue.xmr.sub.recode import recode_msg
from monero_serialize import xmrtypes


def recode_rangesig(rsig, encode=True, copy=False):
    """
    In - place rsig recoding
    :param rsig:
    :param encode: if true encodes to byte representation, otherwise decodes from byte representation
    :param copy:
    :return:
    """
    recode_int = crypto.encodeint if encode else crypto.decodeint
    recode_point = crypto.encodepoint if encode else crypto.decodepoint
    nrsig = rsig
    if copy:
        nrsig = xmrtypes.RangeSig()
        nrsig.Ci = [None] * 64
        nrsig.asig = xmrtypes.BoroSig()
        nrsig.asig.s0 = [None] * 64
        nrsig.asig.s1 = [None] * 64

    for i in range(len(rsig.Ci)):
        nrsig.Ci[i] = recode_point(rsig.Ci[i])
    for i in range(len(rsig.asig.s0)):
        nrsig.asig.s0[i] = recode_int(rsig.asig.s0[i])
    for i in range(len(rsig.asig.s1)):
        nrsig.asig.s1[i] = recode_int(rsig.asig.s1[i])
    nrsig.asig.ee = recode_int(rsig.asig.ee)
    return nrsig


def flatten_rsig(rsig):
    """
    Rsig -> byte array
    :param rsig:
    :return:
    """
    res = b""

    for i in range(len(rsig.asig.s0)):
        res += bytes(rsig.asig.s0[i])
    for i in range(len(rsig.asig.s1)):
        res += bytes(rsig.asig.s1[i])
    res += bytes(rsig.asig.ee)
    for i in range(len(rsig.Ci)):
        res += bytes(rsig.Ci[i])
    return res


def inflate_rsig(buff, rsig=None):
    """
    Rsig binary repr -> byte encoded repr
    :param rsig:
    :return:
    """
    if rsig is None:
        rsig = xmrtypes.RangeSig()
        rsig.Ci = [None] * 64
        rsig.asig = xmrtypes.BoroSig()
        rsig.asig.s0 = [None] * 64
        rsig.asig.s1 = [None] * 64

    for i in range(64):
        rsig.asig.s0[i], buff = buff[:32], buff[32:]
    for i in range(64):
        rsig.asig.s1[i], buff = buff[:32], buff[32:]
    rsig.asig.ee, buff = buff[:32], buff[32:]
    for i in range(64):
        rsig.Ci[i], buff = buff[:32], buff[32:]
    return rsig


def recode_rct(rv, encode=True):
    """
    Recodes RCT MGs signatures from raw forms to bytearrays so it works with serialization
    :param rv:
    :param encode: if true encodes to byte representation, otherwise decodes from byte representation
    :return:
    """
    rv.p.MGs = recode_msg(rv.p.MGs, encode=encode)
    return rv
