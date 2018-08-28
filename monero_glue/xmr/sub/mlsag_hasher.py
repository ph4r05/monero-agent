from monero_glue.xmr import crypto
from monero_glue.xmr.sub.keccak_hasher import HashWrapper
from monero_serialize import xmrserialize


class PreMlsagHasher(object):
    """
    Iterative construction of the pre_mlsag_hash
    """

    def __init__(self, state=None):
        from monero_glue.xmr.sub.keccak_hasher import HashWrapper, KeccakXmrArchive

        self.is_simple = state[0] if state else None
        self.state = state[1] if state else 0
        self.kc_master = HashWrapper(state[2] if state else crypto.get_keccak())
        self.rsig_hasher = state[3] if state else crypto.get_keccak()
        self.rtcsig_hasher = None
        if state:
            self.rtcsig_hasher = KeccakXmrArchive(state[4]) if state[4] else None
        else:
            self.rtcsig_hasher = KeccakXmrArchive()

    def state_save(self):
        return (
            self.is_simple,
            self.state,
            self.kc_master.ctx,
            self.rsig_hasher,
            self.rtcsig_hasher.ctx() if self.rtcsig_hasher else None,
        )

    def state_load(self, x):
        from monero_glue.xmr.sub.keccak_hasher import HashWrapper, KeccakXmrArchive

        self.is_simple = x[0]
        self.state = x[1]
        self.kc_master = HashWrapper(x[2])
        self.rsig_hasher = x[3]
        if x[4]:
            self.rtcsig_hasher = KeccakXmrArchive(x[4])
        else:
            self.rtcsig_hasher = None

    def init(self, is_simple):
        if self.state != 0:
            raise ValueError("State error")

        self.state = 1
        self.is_simple = is_simple

    async def set_message(self, message):
        self.kc_master.update(message)

    async def set_type_fee(self, rv_type, fee):
        if self.state != 1:
            raise ValueError("State error")
        self.state = 2

        from monero_serialize.xmrtypes import RctSigBase

        rfields = RctSigBase.f_specs()
        await self.rtcsig_hasher.message_field(None, field=rfields[0], fvalue=rv_type)
        await self.rtcsig_hasher.message_field(None, field=rfields[1], fvalue=fee)

    async def set_pseudo_out(self, out):
        if self.state != 2 and self.state != 3:
            raise ValueError("State error")
        self.state = 3

        from monero_serialize.xmrtypes import KeyV

        await self.rtcsig_hasher.field(out, KeyV.ELEM_TYPE)

    async def set_ecdh(self, ecdh):
        if self.state != 2 and self.state != 3 and self.state != 4:
            raise ValueError("State error")
        self.state = 4

        from monero_serialize.xmrtypes import EcdhInfo

        await self.rtcsig_hasher.field(ecdh, EcdhInfo.ELEM_TYPE)

    async def set_out_pk(self, out_pk, mask=None):
        if self.state != 4 and self.state != 5:
            raise ValueError("State error")
        self.state = 5

        from monero_serialize.xmrtypes import ECKey

        await self.rtcsig_hasher.field(mask if mask else out_pk.mask, ECKey)

    async def rctsig_base_done(self):
        if self.state != 5:
            raise ValueError("State error")
        self.state = 6

        c_hash = self.rtcsig_hasher.get_digest()
        self.kc_master.update(c_hash)
        self.rtcsig_hasher = None

    async def rsig_val(self, p, bulletproof, raw=False):
        if self.state == 8:
            raise ValueError("State error")

        if raw:
            self.rsig_hasher.update(p)
            return

        if bulletproof:
            self.rsig_hasher.update(p.A)
            self.rsig_hasher.update(p.S)
            self.rsig_hasher.update(p.T1)
            self.rsig_hasher.update(p.T2)
            self.rsig_hasher.update(p.taux)
            self.rsig_hasher.update(p.mu)
            for i in range(len(p.L)):
                self.rsig_hasher.update(p.L[i])
            for i in range(len(p.R)):
                self.rsig_hasher.update(p.R[i])
            self.rsig_hasher.update(p.a)
            self.rsig_hasher.update(p.b)
            self.rsig_hasher.update(p.t)

        else:
            for i in range(64):
                self.rsig_hasher.update(p.asig.s0[i])
            for i in range(64):
                self.rsig_hasher.update(p.asig.s1[i])
            self.rsig_hasher.update(p.asig.ee)
            for i in range(64):
                self.rsig_hasher.update(p.Ci[i])

    async def get_digest(self):
        if self.state != 6:
            raise ValueError("State error")
        self.state = 8

        c_hash = self.rsig_hasher.digest()
        self.rsig_hasher = None

        self.kc_master.update(c_hash)
        return self.kc_master.digest()


async def get_pre_mlsag_hash(rv):
    """
    Generates final message for the Ring CT signature

    :param rv:
    :type rv: RctSig
    :return:
    """
    from monero_glue.xmr.sub.keccak_hasher import get_keccak_writer
    from monero_serialize.xmrtypes import RctType

    kc_master = HashWrapper(crypto.get_keccak())
    kc_master.update(rv.message)

    is_simple = rv.type in [RctType.Simple, RctType.SimpleBulletproof]
    inputs = len(rv.pseudoOuts) if is_simple else 0
    outputs = len(rv.ecdhInfo)

    kwriter = get_keccak_writer()
    ar = xmrserialize.Archive(kwriter, True)
    await rv.serialize_rctsig_base(ar, inputs, outputs)
    c_hash = kwriter.get_digest()
    kc_master.update(c_hash)

    kc = crypto.get_keccak()
    if rv.type in [RctType.FullBulletproof, RctType.SimpleBulletproof]:
        for p in rv.p.bulletproofs:
            kc.update(p.A)
            kc.update(p.S)
            kc.update(p.T1)
            kc.update(p.T2)
            kc.update(p.taux)
            kc.update(p.mu)
            for i in range(len(p.L)):
                kc.update(p.L[i])
            for i in range(len(p.R)):
                kc.update(p.R[i])
            kc.update(p.a)
            kc.update(p.b)
            kc.update(p.t)

    else:
        for r in rv.p.rangeSigs:
            for i in range(64):
                kc.update(r.asig.s0[i])
            for i in range(64):
                kc.update(r.asig.s1[i])
            kc.update(r.asig.ee)
            for i in range(64):
                kc.update(r.Ci[i])

    c_hash = kc.digest()
    kc_master.update(c_hash)
    return kc_master.digest()
