# import gc
# import micropython
# import ustruct
#
# from trezor import log
#
# from apps.monero import layout
# from apps.monero.controller import misc
# from apps.monero.xmr import common, crypto, monero
# from apps.monero.xmr.enc import aescbc
# from apps.monero.xmr.serialize.int_serialize import dump_uvarint_b, load_uvarint_b

from hashlib import sha256
import struct as ustruct

from monero_glue.compat import gc
from monero_glue.compat import micropython
from monero_glue.compat import log
from monero_glue.hwtoken import misc
from monero_glue.xmr import common, crypto, monero
from monero_glue.xmr.enc import aescbc
from monero_serialize.core.int_serialize import load_uvarint_b

from .consts import *


def memcpy(dst, dst_off, src, src_off, ln):
    for i in range(ln):
        dst[dst_off + i] = src[src_off + i]
    return dst


class LiteProtocol(object):
    """
    Lite protocol
    """

    def __init__(self, **kwargs):
        self.creds = None
        self.ctx = None
        self.iface = None

        self.state = None
        self.options = None
        self.sig_mode = 0
        self.a = None
        self.A = None
        self.b = None
        self.B = None

        self.key_enc = None
        self.tx_state = None
        self.r = None
        self.R = None

        self.ctx_f = None
        self.ctx_h = None
        self.H = None
        self.c = None

        self.ctx_amount = None
        self.KV = None

        self.ctx_commitment = None
        self.C = None

        self.iv = bytearray(16)
        self.c_msg = None
        self.c_offset = 0
        self.c_p1 = 0
        self.c_p2 = 0

        self.r_msg = bytearray(2048)
        self.r_len = 0

    def _log_trace(self, x=None, collect=False):
        log.debug(
            __name__,
            "Log trace %s, ... F: %s A: %s, S: %s",
            x,
            gc.mem_free(),
            gc.mem_alloc(),
            micropython.stack_use(),
        )
        if collect:
            gc.collect()

    def assrt(self, condition, msg=None):
        """
        Asserts condition
        :param condition:
        :param msg:
        :return:
        """
        if condition:
            return
        raise ValueError("Assertion error%s" % (" : %s" % msg if msg else ""))

    async def init(self, ctx, msg):
        from apps.monero.controller import wrapper

        self.ctx = ctx
        self.creds = await wrapper.monero_get_creds(
            self.ctx, msg.address_n or (), msg.network_type
        )
        self._state_init()
        self.a = self.creds.view_key_private
        self.A = self.creds.view_key_public
        self.b = self.creds.spend_key_private
        self.B = self.creds.spend_key_public
        self.key_enc = crypto.random_bytes(
            32
        )  # WARNING: potentially dangerous for whole session.

    def _state_init(self):
        self.ctx_f = crypto.get_keccak()
        self.ctx_h = crypto.get_keccak()
        self.ctx_amount = sha256()
        self.ctx_commitment = sha256()

    def _reset_io(self):
        self.r_len = 0
        self.c_offset = 0

    def _assert_available(self, ln=32):
        if len(self.c_msg) < self.c_offset + ln:
            raise ValueError("Wrong length")

    def _fetch_view(self):
        mv = memoryview(self.c_msg)
        return mv[self.c_offset :]

    def _fetch(self, ln=32, shift=True):
        data = self.c_msg[self.c_offset : self.c_offset + ln]
        if len(data) != ln:
            raise ValueError("Wrong length")

        if shift:
            self.c_offset += ln
        return data

    def _fetch_decrypt(self, ln=32):
        data = self._fetch(ln)
        return aescbc.decrypt(self.key_enc, data, self.iv)

    def _fetch_decrypt_key(self):
        buff = self._fetch()
        if buff == b"\x00" * 32:
            return self.a
        elif buff == b"\xff" * 32:
            return self.b
        else:
            return crypto.decodeint(aescbc.decrypt(self.key_enc, buff, self.iv))

    def _fetch_u32(self):
        return (
            (self._fetch_u8() << 24)
            | (self._fetch_u8() << 16)
            | (self._fetch_u8() << 8)
            | self._fetch_u8()
        )

    def _fetch_u16(self):
        return (self._fetch_u8() << 8) | self._fetch_u8()

    def _fetch_u8(self):
        d = self._fetch(1)[0]
        return int(d) & 0xff

    def _fetch_t(self):
        t = self._fetch_u8()
        if t & 0x1f == 0x1f:
            t = (t << 8) | self._fetch_u8()
        return t

    def _fetch_l(self):
        l = self._fetch_u8()
        if l & 0x80 != 0:
            l &= 0x7f
        if l == 1:
            l = self._fetch_u8()
        elif l == 2:
            l = self._fetch_u16()
        else:
            l = -1
        return l

    def _insert(self, buff, ln=None):
        if ln is None:
            ln = len(buff)
        memcpy(self.r_msg, self.r_len, buff, 0, ln)
        self.r_len += ln

    def _insert_encrypt(self, buff, ln=None):
        enc = aescbc.encrypt(self.key_enc, buff, self.iv)
        self._insert(enc, len(enc))

    def _insert_u8(self, x):
        self.r_msg[self.r_len] = x & 0xff
        self.r_len += 1

    def _insert_u16(self, x):
        self._insert_u8(x >> 8)
        self._insert_u8(x)

    def _insert_u32(self, x):
        self._insert_u8(x >> 24)
        self._insert_u8(x >> 16)
        self._insert_u8(x >> 8)
        self._insert_u8(x)

    def _insert_t(self, t):
        if t & 0xff00:
            self._insert_u16(t)
        else:
            self._insert_u8(t)

    def _insert_tl(self, t, l):
        self._insert_t(t)
        if l < 128:
            self._insert_u8(l)
        elif l < 256:
            self._insert_u16(0x8100 | l)
        else:
            self._insert_u8(0x82)
            self._insert_u16(l)

    async def blind(self):
        AKout = self._fetch_decrypt(32)
        k = self._fetch(32)
        v = self._fetch(32)

        self.ctx_amount.update(AKout)
        self.ctx_amount.update(k)
        self.ctx_amount.update(v)

        AKout = crypto.hash_to_scalar(AKout)
        k = crypto.sc_add(crypto.decodeint(k), AKout)

        AKout = crypto.hash_to_scalar(crypto.encodeint(AKout))
        v = crypto.sc_add(crypto.decodeint(v), AKout)

        self._insert(crypto.encodeint(v))
        self._insert(crypto.encodeint(k))
        return SW_OK

    def unblind_int(self, v, k, AKout):
        AKout = crypto.hash_to_scalar(AKout)
        k = crypto.sc_sub(crypto.decodeint(k), AKout)

        AKout = crypto.hash_to_scalar(crypto.encodeint(AKout))
        v = crypto.sc_sub(crypto.decodeint(v), AKout)

        return v, k, AKout

    async def unblind(self):
        AKout = self._fetch_decrypt(32)
        k = self._fetch(32)
        v = self._fetch(32)

        v, k, AKout = self.unblind_int(v, k, AKout)

        self._insert(crypto.encodeint(v))
        self._insert(crypto.encodeint(k))
        return SW_OK

    async def put_key(self):
        sec = crypto.decodeint(self._fetch(32))
        pub = crypto.decodepoint(self._fetch(32))
        if not crypto.point_eq(pub, crypto.scalarmult_base(sec)):
            return SW_WRONG_DATA
        self.a = sec

        sec = crypto.decodeint(self._fetch(32))
        pub = crypto.decodepoint(self._fetch(32))
        if not crypto.point_eq(pub, crypto.scalarmult_base(sec)):
            return SW_WRONG_DATA
        self.b = sec
        return SW_OK

    async def get_key(self):
        if self.c_p1 == 1:
            self._insert(crypto.encodepoint(self.A))
            self._insert(crypto.encodepoint(self.B))
            self._insert(self.creds.address)

        elif self.c_p1 == 2:
            # TODO: await layout.require_confirm_watchkey(self.ctx)
            self._insert(crypto.encodeint(self.a))

        else:
            return SW_WRONG_P1P2
        return SW_OK

    async def verify_key(self):
        priv = self._fetch_decrypt_key()
        pub = crypto.decodepoint(self._fetch())
        computed_pub = crypto.identity()
        verified = 0

        if self.c_p1 == 0:
            computed_pub = crypto.scalarmult_base(priv)
        elif self.c_p1 == 1:
            pub = self.A
        elif self.c_p1 == 2:
            pub = self.B
        else:
            return SW_WRONG_P1P2

        if crypto.point_eq(computed_pub, pub):
            verified = 1

        self._insert_u32(verified)
        self._insert(self.creds.address)
        return SW_OK

    async def chacha8_prekey(self):
        abt = bytearray(65)
        memcpy(abt, 0, crypto.encodeint(self.a), 0, 32)
        memcpy(abt, 32, crypto.encodeint(self.b), 0, 32)
        abt[64] = 0x8c
        pre = crypto.keccak_hash(abt)

        # gibberish expansion to 200 bytes, different from Ledger as it uses 200B of keccak state
        for i in range(6):
            self._insert(pre)
        self._insert(pre[:8])
        return SW_OK

    async def sc_add(self):
        s1 = crypto.decodeint(self._fetch())
        s2 = crypto.decodeint(self._fetch())
        self._insert(crypto.encodeint(crypto.sc_add(s1, s2)))
        return SW_OK

    async def sc_sub(self):
        s1 = crypto.decodeint(self._fetch())
        s2 = crypto.decodeint(self._fetch())
        self._insert(crypto.encodeint(crypto.sc_sub(s1, s2)))
        return SW_OK

    async def scal_mul_key(self):
        pub = crypto.decodepoint(self._fetch())
        sec = crypto.decodeint(self._fetch_decrypt())
        self._insert(crypto.encodepoint(crypto.scalarmult(pub, sec)))
        return SW_OK

    async def scal_mul_base(self):
        sec = crypto.decodeint(self._fetch_decrypt())
        self._insert(crypto.encodepoint(crypto.scalarmult_base(sec)))
        return SW_OK

    async def generate_keypair(self):
        sec = crypto.random_scalar()
        pub = crypto.scalarmult_base(sec)
        self._insert(crypto.encodepoint(pub))
        self._insert_encrypt(crypto.encodeint(sec))
        return SW_OK

    async def secret_key_to_public_key(self):
        return await self.scal_mul_base()

    async def generate_key_derivation(self):
        pub = crypto.decodepoint(self._fetch())
        sec = self._fetch_decrypt_key()
        der = crypto.generate_key_derivation(pub, sec)
        self._insert_encrypt(crypto.encodepoint(der))
        return SW_OK

    async def derivation_to_scalar(self):
        der = crypto.decodepoint(self._fetch_decrypt())
        output_index = self._fetch_u32()
        res = crypto.derivation_to_scalar(der, output_index)
        self._insert_encrypt(crypto.encodeint(res))
        return SW_OK

    async def derive_public_key(self):
        derivation = crypto.decodepoint(self._fetch_decrypt())
        output_index = self._fetch_u32()
        pub = crypto.decodepoint(self._fetch())
        drvpub = crypto.derive_public_key(derivation, output_index, pub)
        self._insert(crypto.encodepoint(drvpub))
        return SW_OK

    async def derive_secret_key(self):
        derivation = crypto.decodepoint(self._fetch_decrypt())
        output_index = self._fetch_u32()
        sec = self._fetch_decrypt_key()
        drvsec = crypto.derive_secret_key(derivation, output_index, sec)
        self._insert_encrypt(crypto.encodeint(drvsec))
        return SW_OK

    async def generate_key_image(self):
        pub = self._fetch()
        sec = crypto.decodeint(self._fetch_decrypt())
        image = monero.generate_key_image(pub, sec)
        self._insert(crypto.encodepoint(image))
        return SW_OK

    async def derive_subaddress_public_key(self):
        pub = crypto.decodepoint(self._fetch())
        derivation = crypto.decodepoint(self._fetch_decrypt())
        output_index = self._fetch_u32()
        sub_pub = monero.derive_subaddress_public_key(pub, derivation, output_index)
        self._insert(crypto.encodepoint(sub_pub))
        return SW_OK

    def _idx_parse(self, index):
        major = ustruct.unpack("<L", index)[0]
        minor = ustruct.unpack_from("<L", index, 4)[0]
        return major, minor

    async def get_subaddress(self):
        index = self._fetch(8)
        major, minor = self._idx_parse(index)
        D, C = monero.generate_sub_address_keys(self.a, self.B, major, minor)
        self._insert(crypto.encodepoint(C))
        self._insert(crypto.encodepoint(D))
        return SW_OK

    async def get_subaddress_spend_public_key(self):
        index = self._fetch(8)
        major, minor = self._idx_parse(index)
        D = monero.get_subaddress_spend_public_key(self.a, self.B, major, minor)
        self._insert(crypto.encodepoint(D))
        return SW_OK

    async def get_subaddress_secret_key(self):
        sec = crypto.decodeint(self._fetch_decrypt())
        index = self._fetch(8)
        major, minor = self._idx_parse(index)
        sub_sec = monero.get_subaddress_secret_key(sec, major=major, minor=minor)
        self._insert_encrypt(crypto.encodeint(sub_sec))
        return SW_OK

    async def mlsag_prepare(self):
        Hi = None
        xin = None
        options = 0

        if len(self.c_msg) > 1:
            options = 1
            Hi = crypto.decodepoint(self._fetch())
            if self.options & 0x40:
                xin = crypto.decodeint(self._fetch())
            else:
                xin = crypto.decodeint(self._fetch_decrypt())

        alpha = crypto.random_scalar()
        self._insert_encrypt(crypto.encodeint(alpha))

        # ai.G
        self._insert(crypto.encodepoint(crypto.scalarmult_base(alpha)))

        if options:
            # ai * Hi
            self._insert(crypto.encodepoint(crypto.scalarmult(Hi, alpha)))
            # xin * Hi
            self._insert(crypto.encodepoint(crypto.scalarmult(Hi, xin)))
        return SW_OK

    async def mlsag_hash(self):
        if self.c_p2 == 1:
            self.ctx_h = crypto.get_keccak()
            msg = self.H
        else:
            msg = self._fetch()

        self.ctx_h.update(msg)
        if self.options & 0x80 == 0:
            c = self.ctx_h.digest()
            self.c = crypto.decodeint(c)
            self._insert(crypto.encodeint(self.c))
        return SW_OK

    async def mlsag_sign(self):
        if self.sig_mode == TRANSACTION_CREATE_FAKE:
            xin = crypto.decodeint(self._fetch())
            alpha = crypto.decodeint(self._fetch())
        elif self.sig_mode == TRANSACTION_CREATE_REAL:
            xin = crypto.decodeint(self._fetch_decrypt())
            alpha = crypto.decodeint(self._fetch_decrypt())
        else:
            raise ValueError("Invalid mode")

        ss2 = crypto.sc_mulsub(self.c, xin, alpha)
        self._insert(crypto.encodeint(ss2))
        self._insert_u32(self.sig_mode)
        return SW_OK

    async def open_tx(self):
        self.ctx_amount = sha256()
        account = self._fetch_u32()

        self.r = crypto.random_scalar()
        self.R = crypto.scalarmult_base(self.r)

        self._insert(crypto.encodepoint(self.R))
        self._insert_encrypt(crypto.encodeint(self.r))
        return SW_OK

    async def abort_tx(self):
        self.r = None
        self.R = None
        self.ctx_h = crypto.get_keccak()
        self.ctx_amount = sha256()
        self.ctx_commitment = sha256()
        return SW_OK

    async def set_signature_mode(self):
        self.sig_mode = TRANSACTION_CREATE_FAKE
        sig_mode = self._fetch_u8()
        if sig_mode != TRANSACTION_CREATE_FAKE and sig_mode != TRANSACTION_CREATE_REAL:
            raise ValueError("Wrong data")
        self.sig_mode = sig_mode
        self._insert_u32(sig_mode)
        return SW_OK

    async def mlsag_prehash_init(self):
        if self.c_p2 == 1:
            self.KV = self.ctx_amount.digest()
            self.ctx_amount = sha256()
            self.ctx_commitment = sha256()
            self.ctx_h = crypto.get_keccak()

        self.ctx_h.update(self.c_msg[self.c_offset :])
        if self.sig_mode == TRANSACTION_CREATE_REAL and self.c_p2 == 1:
            self._fetch_u8()
            fee = load_uvarint_b(self._fetch_view())
            # TODO: await layout.require_confirm_fee(self.ctx, fee)

        return SW_OK

    async def mlsag_prehash_update(self):
        is_subaddress = 0
        Aout = None
        Bout = None
        C = None
        v = None
        k = None
        changed = 0

        is_subaddress = bool(self._fetch_u8())
        Aout = crypto.decodepoint(self._fetch())
        Bout = crypto.decodepoint(self._fetch())
        if self.sig_mode == TRANSACTION_CREATE_REAL:
            if crypto.point_eq(Aout, self.A) and crypto.point_eq(Bout, self.B):
                changed = 1

        AKout = self._fetch_decrypt()
        C = self._fetch()
        k = self._fetch()
        v = self._fetch()

        self.ctx_h.update(k)
        self.ctx_h.update(v)

        self.ctx_amount.update(AKout)

        v, k, AKout = self.unblind_int(v, k, AKout)
        self.ctx_amount.update(crypto.encodeint(k))
        self.ctx_amount.update(crypto.encodeint(v))

        vH = crypto.scalarmult_h(v)
        kG = crypto.scalarmult_base(k)
        k = crypto.point_add(kG, vH)

        if not crypto.point_eq(k, crypto.decodepoint(C)):
            raise ValueError(SW_SECURITY_COMMITMENT_CONTROL)

        self.ctx_commitment.update(C)
        if self.options & IN_OPTION_MORE_COMMAND == 0:
            k = self.ctx_amount.digest()
            if not common.ct_equal(k, self.KV):
                raise ValueError(SW_SECURITY_AMOUNT_CHAIN_CONTROL)

            self.C = self.ctx_commitment.digest()
            self.ctx_commitment = sha256()

        if self.sig_mode == TRANSACTION_CREATE_REAL:
            if not changed:
                await self._req_dst(Aout, Bout, v, is_subaddress)

        return SW_OK

    async def _req_dst(self, Aout, Bout, amount, is_sub=False):
        addr = misc.StdObj(view_public_key=Aout, spend_public_key=Bout)
        out = misc.StdObj(addr=addr, amount=amount, is_subaddress=is_sub)
        await self.iface.confirm_out(out, False, self.creds, self.ctx)

    async def mlsag_prehash_finalize(self):
        H = None
        proof = None
        message = None

        if self.options & IN_OPTION_MORE_COMMAND:
            H = self._fetch()
            self.ctx_h.update(H)
            self.ctx_commitment.update(H)
        else:
            H = self.ctx_commitment.digest()
            if not common.ct_equal(H, self.C):
                raise ValueError(SW_SECURITY_COMMITMENT_CHAIN_CONTROL)

            H = self.ctx_h.digest()
            message = self._fetch()
            proof = self._fetch()

            self.ctx_h = crypto.get_keccak()
            self.ctx_h.update(message)
            self.ctx_h.update(H)
            self.ctx_h.update(proof)
            self.H = self.ctx_h.digest()
            self._insert(self.H)
        return SW_OK

    async def stealth(self):
        pub = crypto.decodepoint(self._fetch())
        sec = self._fetch_decrypt_key()
        pay_id = self._fetch(8)

        drv = monero.generate_key_derivation(pub, sec)
        drv += b"\x8d"
        sec = crypto.keccak_hash(drv)
        for i in range(8):
            pay_id[i] ^= sec[i]

        self._insert(pay_id)
        return SW_OK

    async def dispatch(self, ctx, ins, p1, p2, input):
        """
        Main message dispatcher
        :param ctx:
        :param ins:
        :param p1:
        :param p2:
        :param input:
        :return:
        """
        self.c_p1 = p1
        self.c_p2 = p2
        self.c_msg = input
        self.c_offset = 0
        self.r_len = 0

        from apps.monero.controller import iface

        self.ctx = ctx
        self.iface = iface.get_iface(ctx)

        sw = 0x6F01
        try:
            log.debug(__name__, "Ins: %s, %s %s", ins, p1, p2)
            sw = await self._sub_dispatch(ins, p1)
        except Exception as e:
            log.error(__name__, "Exception dispatching: %s", e)
            raise

        gc.collect()
        return sw, self.r_msg[: self.r_len]

    async def _sub_dispatch(self, ins, p1):
        sw = 0x6F01
        self.options = self._fetch_u8()

        if ins == INS_NONE:
            pass
        elif ins == INS_OPEN_TX:
            sw = await self.open_tx()
        elif ins == INS_CLOSE_TX:
            sw = SW_OK
        elif ins == INS_SET_SIGNATURE_MODE:
            sw = await self.set_signature_mode()
        elif ins == INS_STEALTH:
            sw = await self.stealth()

        elif ins == INS_PUT_KEY:
            sw = await self.put_key()
        elif ins == INS_GET_KEY:
            sw = await self.get_key()
        elif ins == INS_MANAGE_SEEDWORDS:
            sw = SW_OK  # TODO:

        elif ins == INS_VERIFY_KEY:
            sw = await self.verify_key()
        elif ins == INS_GET_CHACHA8_PREKEY:
            sw = await self.chacha8_prekey()
        elif ins == INS_SECRET_KEY_TO_PUBLIC_KEY:
            sw = await self.secret_key_to_public_key()
        elif ins == INS_GEN_KEY_DERIVATION:
            sw = await self.generate_key_derivation()
        elif ins == INS_DERIVATION_TO_SCALAR:
            sw = await self.derivation_to_scalar()
        elif ins == INS_DERIVE_PUBLIC_KEY:
            sw = await self.derive_public_key()
        elif ins == INS_DERIVE_SECRET_KEY:
            sw = await self.derive_secret_key()
        elif ins == INS_GEN_KEY_IMAGE:
            sw = await self.generate_key_image()
        elif ins == INS_SECRET_KEY_ADD:
            sw = await self.sc_add()
        elif ins == INS_SECRET_KEY_SUB:
            sw = await self.sc_sub()
        elif ins == INS_GENERATE_KEYPAIR:
            sw = await self.generate_keypair()
        elif ins == INS_SECRET_SCAL_MUL_KEY:
            sw = await self.scal_mul_key()
        elif ins == INS_SECRET_SCAL_MUL_BASE:
            sw = await self.scal_mul_base()

        elif ins == INS_DERIVE_SUBADDRESS_PUBLIC_KEY:
            sw = await self.derive_subaddress_public_key()
        elif ins == INS_GET_SUBADDRESS:
            sw = await self.get_subaddress()
        elif ins == INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY:
            sw = await self.get_subaddress_spend_public_key()
        elif ins == INS_GET_SUBADDRESS_SECRET_KEY:
            sw = await self.get_subaddress_secret_key()

        elif ins == INS_BLIND:
            sw = await self.blind()
        elif ins == INS_UNBLIND:
            sw = await self.unblind()

        elif ins == INS_VALIDATE:
            if p1 == 1:
                sw = await self.mlsag_prehash_init()
            elif p1 == 2:
                sw = await self.mlsag_prehash_update()
            elif p1 == 3:
                sw = await self.mlsag_prehash_finalize()
            else:
                raise ValueError(SW_WRONG_P1P2)

        elif ins == INS_MLSAG:
            if p1 == 1:
                sw = await self.mlsag_prepare()
            elif p1 == 2:
                sw = await self.mlsag_hash()
            elif p1 == 3:
                sw = await self.mlsag_sign()
            else:
                raise ValueError(SW_WRONG_P1P2)
        return sw
