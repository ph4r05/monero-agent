from monero_glue.compat import gc, log, micropython, utils
from monero_glue.compat.micropython import const
from monero_glue.hwtoken import misc
from monero_glue.xmr import common, crypto, monero


class TprefixStub(object):
    __slots__ = ("version", "unlock_time", "vin", "vout", "extra")

    def __init__(self, **kwargs):
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])


class TTransactionBuilder(object):
    """
    Transaction builder
    """

    STEP_INP = const(100)
    STEP_PERM = const(200)
    STEP_VINI = const(300)
    STEP_ALL_IN = const(350)
    STEP_OUT = const(400)
    STEP_ALL_OUT = const(500)
    STEP_MLSAG = const(600)
    STEP_SIGN = const(700)

    def __init__(self, trezor=None, creds=None, state=None, **kwargs):
        self.trezor = trezor
        self.creds = creds
        self.key_master = None
        self.key_hmac = None
        self.key_enc = None

        self.r = None  # txkey
        self.r_pub = None
        self.state = None

        self.multi_sig = False
        self.need_additional_txkeys = False
        self.use_bulletproof = False
        self.use_rct = True
        self.use_simple_rct = False
        self.input_count = 0
        self.output_count = 0
        self.output_change = None
        self.mixin = 0
        self.fee = 0
        self.account_idx = 0

        self.additional_tx_private_keys = []
        self.additional_tx_public_keys = []
        self.inp_idx = -1
        self.out_idx = -1
        self.summary_inputs_money = 0
        self.summary_outs_money = 0
        self.input_secrets = []
        self.input_alphas = []
        self.input_pseudo_outs = []
        self.output_sk = []
        self.output_pk = []
        self.output_amounts = []
        self.output_masks = []
        self.rsig_type = 0
        self.rsig_grp = []
        self.rsig_offload = 0
        self.sumout = crypto.sc_0()
        self.sumpouts_alphas = crypto.sc_0()
        self.subaddresses = {}
        self.tx = None
        self.source_permutation = []  # sorted by key images
        self.tx_prefix_hasher = None
        self.tx_prefix_hash = None
        self.full_message_hasher = None
        self.full_message = None
        self.exp_tx_prefix_hash = None

        if state is None:
            self._init()
        else:
            self.state_load(state)

    def _init(self):
        from monero_glue.xmr.sub.keccak_hasher import KeccakXmrArchive
        from monero_glue.xmr.sub.mlsag_hasher import PreMlsagHasher
        from monero_glue.protocol.tsx_sign_state import TState

        self.state = TState()
        self.tx = TprefixStub(vin=[], vout=[], extra=b"")
        self.tx_prefix_hasher = KeccakXmrArchive()
        self.full_message_hasher = PreMlsagHasher()

    def state_load(self, t):
        from monero_glue.protocol.tsx_sign_state import TState

        self._mem_trace("Restore: %s" % str(t.state), True)

        for attr in t.__dict__:
            if attr.startswith("_"):
                continue

            cval = getattr(t, attr)
            if cval is None:
                setattr(self, attr, cval)
                continue

            if attr == "state":
                self.state = TState()
                self.state.state_load(t.state)
            elif attr == "tx_prefix_hasher":
                from monero_glue.xmr.sub.keccak_hasher import KeccakXmrArchive

                self.tx_prefix_hasher = KeccakXmrArchive(ctx=t.tx_prefix_hasher)
            elif attr == "full_message_hasher":
                from monero_glue.xmr.sub.mlsag_hasher import PreMlsagHasher

                self.full_message_hasher = PreMlsagHasher(state=t.full_message_hasher)
            else:
                setattr(self, attr, cval)
            gc.collect()

    def state_save(self):
        from monero_glue.protocol.tsx_sign_state_holder import TsxSignStateHolder

        t = TsxSignStateHolder()

        for attr in self.__dict__:
            if attr.startswith("_"):
                continue

            cval = getattr(self, attr)
            if cval is None:
                setattr(t, attr, cval)
                continue

            if attr == "state":
                t.state = self.state.state_save()
            elif attr in ["trezor"]:
                continue
            elif attr.startswith("STEP"):
                continue
            elif attr == "tx_prefix_hasher":
                t.tx_prefix_hasher = self.tx_prefix_hasher.ctx()
            elif attr == "full_message_hasher":
                t.full_message_hasher = self.full_message_hasher.state_save()
            else:
                setattr(t, attr, cval)
        return t

    def _mem_trace(self, x=None, collect=False):
        log.debug(
            __name__, "Log trace: %s, ... F: %s A: %s", x, gc.mem_free(), gc.mem_alloc()
        )
        if collect:
            gc.collect()

    def assrt(self, condition, msg=None):
        if condition:
            return
        raise ValueError("Assertion error%s" % (" : %s" % msg if msg else ""))

    def is_terminal(self):
        return self.state.is_terminal()

    def gen_r(self, use_r=None):
        """
        Generates a new transaction key pair.
        """
        self.r = crypto.random_scalar() if use_r is None else use_r
        self.r_pub = crypto.scalarmult_base(self.r)

    def get_primary_change_address(self):
        """
        Computes primary change address for the current account index
        """
        D, C = monero.generate_sub_address_keys(
            self.creds.view_key_private,
            self.creds.spend_key_public,
            self.account_idx,
            0,
        )
        return misc.StdObj(
            view_public_key=crypto.encodepoint(C),
            spend_public_key=crypto.encodepoint(D),
        )

    def check_change(self, outputs):
        """
        Checks if the change address is among tx outputs and it is equal to our address.
        """
        from monero_glue.xmr.sub.addr import addr_eq, get_change_addr_idx

        change_idx = get_change_addr_idx(outputs, self.output_change)

        change_addr = self.change_address()
        if change_addr is None:
            self._mem_trace("No change" if __debug__ else None)
            return

        if change_idx is None and self.output_change.amount == 0 and len(outputs) == 2:
            self._mem_trace("Sweep tsx" if __debug__ else None)
            return  # sweep dummy tsx

        found = False
        for out in outputs:
            if addr_eq(out.addr, change_addr):
                found = True
                break

        if not found:
            raise misc.TrezorChangeAddressError("Change address not found in outputs")

        my_addr = self.get_primary_change_address()
        if not addr_eq(my_addr, change_addr):
            raise misc.TrezorChangeAddressError("Change address differs from ours")

        return True

    def in_memory(self):
        """
        Returns true if the input transaction can be processed whole in-memory
        """
        return False

    def many_inputs(self):
        """
        Returns true if number of inputs > 10 (secret spending key offloaded)
        """
        return self.input_count >= 10

    def many_outputs(self):
        """
        Returns true if number of outputs > 10 (increases number of roundtrips of the protocol)
        """
        return self.output_count >= 10

    def num_inputs(self):
        return self.input_count

    def num_dests(self):
        return self.output_count

    def get_fee(self):
        return self.fee if self.fee > 0 else 0

    def change_address(self):
        return self.output_change.addr if self.output_change else None

    def get_rct_type(self):
        """
        RCTsig type (simple/full x Borromean/Bulletproof)
        :return:
        """
        from monero_serialize.xmrtypes import RctType

        if self.use_simple_rct:
            return RctType.FullBulletproof if self.use_bulletproof else RctType.Simple
        else:
            return RctType.Full

    def init_rct_sig(self):
        """
        Initializes RCTsig structure (fee, tx prefix hash, type)
        """
        rv = misc.StdObj(
            txnFee=self.get_fee(), message=self.tx_prefix_hash, type=self.get_rct_type()
        )
        return rv

    def _build_key(self, secret, discriminator=None, index: int = None) -> bytes:
        """
        Creates an unique-purpose key
        """
        key_buff = bytearray(32 + 12 + 4)  # key + disc + index
        offset = 32
        utils.memcpy(key_buff, 0, secret, 0, len(secret))

        if discriminator is not None:
            utils.memcpy(key_buff, offset, discriminator, 0, len(discriminator))
            offset += len(discriminator)

        if index is not None:
            # dump_uvarint_b_into, saving import
            shifted = True
            while shifted:
                shifted = index >> 7
                key_buff[offset] = (index & 0x7F) | (0x80 if shifted else 0x00)
                offset += 1
                index = shifted

        return crypto.keccak_2hash(key_buff)

    def hmac_key_txin(self, idx: int) -> bytes:
        """
        (TxSourceEntry[i] || tx.vin[i]) hmac key
        """
        return self._build_key(self.key_hmac, b"txin", idx)

    def hmac_key_txin_comm(self, idx: int) -> bytes:
        """
        pseudo_outputs[i] hmac key. Pedersen commitment for inputs.
        """
        return self._build_key(self.key_hmac, b"txin-comm", idx)

    def hmac_key_txdst(self, idx: int) -> bytes:
        """
        TxDestinationEntry[i] hmac key
        """
        return self._build_key(self.key_hmac, b"txdest", idx)

    def hmac_key_txout(self, idx: int) -> bytes:
        """
        (TxDestinationEntry[i] || tx.vout[i]) hmac key
        """
        return self._build_key(self.key_hmac, b"txout", idx)

    def hmac_key_txout_asig(self, idx: int) -> bytes:
        """
        rsig[i] hmac key. Range signature HMAC
        """
        return self._build_key(self.key_hmac, b"txout-asig", idx)

    def enc_key_txin_alpha(self, idx: int) -> bytes:
        """
        Chacha20Poly1305 encryption key for alpha[i] used in Pedersen commitment in pseudo_outs[i]
        """
        return self._build_key(self.key_enc, b"txin-alpha", idx)

    def enc_key_spend(self, idx: int) -> bytes:
        """
        Chacha20Poly1305 encryption key for alpha[i] used in Pedersen commitment in pseudo_outs[i]
        """
        return self._build_key(self.key_enc, b"txin-spend", idx)

    def enc_key_cout(self, idx: int = None) -> bytes:
        """
        Chacha20Poly1305 encryption key for multisig C values from MLASG.
        """
        return self._build_key(self.key_enc, b"cout", idx)

    async def gen_hmac_vini(self, src_entr, vini_bin, idx: int) -> bytes:
        """
        Computes hmac (TxSourceEntry[i] || tx.vin[i])
        """
        from .. import protobuf
        from monero_glue.xmr.sub.keccak_hasher import get_keccak_writer

        kwriter = get_keccak_writer()
        await protobuf.dump_message(kwriter, src_entr)
        await kwriter.awrite(vini_bin)

        hmac_key_vini = self.hmac_key_txin(idx)
        hmac_vini = crypto.compute_hmac(hmac_key_vini, kwriter.get_digest())
        return hmac_vini

    async def gen_hmac_vouti(self, dst_entr, tx_out_bin, idx: int) -> bytes:
        """
        Generates HMAC for (TxDestinationEntry[i] || tx.vout[i])
        """
        from .. import protobuf
        from monero_glue.xmr.sub.keccak_hasher import get_keccak_writer

        kwriter = get_keccak_writer()
        await protobuf.dump_message(kwriter, dst_entr)
        await kwriter.awrite(tx_out_bin)

        hmac_key_vouti = self.hmac_key_txout(idx)
        hmac_vouti = crypto.compute_hmac(hmac_key_vouti, kwriter.get_digest())
        return hmac_vouti

    async def gen_hmac_tsxdest(self, dst_entr, idx: int) -> bytes:
        """
        Generates HMAC for TxDestinationEntry[i]
        """
        from .. import protobuf
        from monero_glue.xmr.sub.keccak_hasher import get_keccak_writer

        kwriter = get_keccak_writer()
        await protobuf.dump_message(kwriter, dst_entr)

        hmac_key = self.hmac_key_txdst(idx)
        hmac_tsxdest = crypto.compute_hmac(hmac_key, kwriter.get_digest())
        return hmac_tsxdest

    async def _tprefix_update(self):
        self.tx_prefix_hasher.keep()
        await self.tx_prefix_hasher.uvarint(self.tx.version)
        await self.tx_prefix_hasher.uvarint(self.tx.unlock_time)
        await self.tx_prefix_hasher.container_size(self.num_inputs())  # ContainerType
        self.tx_prefix_hasher.release()
        self._mem_trace(10, True)

    async def init_transaction(self, tsx_data):
        """
        Initializes a new transaction.
        """
        from monero_glue.xmr.sub.addr import classify_subaddresses

        self.gen_r()
        self.state.init_tsx()
        self._mem_trace(1)

        # Ask for confirmation
        confirmation = await self.trezor.iface.confirm_transaction(tsx_data, self.creds)
        if not confirmation:
            from monero_glue.messages import FailureType
            from monero_glue.messages.Failure import Failure

            return Failure(code=FailureType.ActionCancelled, message="rejected")

        gc.collect()
        self._mem_trace(3)

        # Basic transaction parameters
        self.input_count = tsx_data.num_inputs
        self.output_count = len(tsx_data.outputs)
        self.output_change = misc.dst_entry_to_stdobj(tsx_data.change_dts)
        self.mixin = tsx_data.mixin
        self.fee = tsx_data.fee
        self.account_idx = tsx_data.account
        self.multi_sig = False
        self.state.inp_cnt(self.in_memory())
        self.check_change(tsx_data.outputs)
        self.exp_tx_prefix_hash = None

        # Rsig data
        self.rsig_type = tsx_data.rsig_data.rsig_type
        self.rsig_grp = tsx_data.rsig_data.grouping
        self.rsig_offload = self.rsig_type > 0 and self.output_count > 2
        self.use_bulletproof = self.rsig_type > 0
        self.use_simple_rct = self.input_count > 1 or self.rsig_type != 0

        # Provided tx key, used mostly in multisig.
        if False:  # len(tsx_data.use_tx_keys) > 0:
            for ckey in tsx_data.use_tx_keys:
                crypto.check_sc(crypto.decodeint(ckey))

            self.gen_r(use_r=crypto.decodeint(tsx_data.use_tx_keys[0]))
            self.additional_tx_private_keys = [
                crypto.decodeint(x) for x in tsx_data.use_tx_keys[1:]
            ]

        # Additional keys w.r.t. subaddress destinations
        class_res = classify_subaddresses(tsx_data.outputs, self.change_address())
        num_stdaddresses, num_subaddresses, single_dest_subaddress = class_res

        # if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=r*D
        if num_stdaddresses == 0 and num_subaddresses == 1:
            self.r_pub = crypto.scalarmult(
                crypto.decodepoint(single_dest_subaddress.spend_public_key), self.r
            )

        self.need_additional_txkeys = num_subaddresses > 0 and (
            num_stdaddresses > 0 or num_subaddresses > 1
        )
        self._mem_trace(4, True)

        # Extra processing, payment id
        self.tx.version = 2
        self.tx.unlock_time = tsx_data.unlock_time
        await self.process_payment_id(tsx_data)
        await self.compute_sec_keys(tsx_data)
        gc.collect()

        # Iterative tx_prefix_hash hash computation
        await self._tprefix_update()
        gc.collect()

        # Final message hasher
        self.full_message_hasher.init(self.use_simple_rct)
        await self.full_message_hasher.set_type_fee(self.get_rct_type(), self.get_fee())

        # Sub address precomputation
        if tsx_data.account is not None and tsx_data.minor_indices:
            self.precompute_subaddr(tsx_data.account, tsx_data.minor_indices)
        self._mem_trace(5, True)

        # HMAC outputs - pinning
        hmacs = []
        for idx in range(self.num_dests()):
            c_hmac = await self.gen_hmac_tsxdest(tsx_data.outputs[idx], idx)
            hmacs.append(c_hmac)
            gc.collect()

        self._mem_trace(6)

        from monero_glue.messages.MoneroTransactionInitAck import (
            MoneroTransactionInitAck,
        )
        from monero_glue.messages.MoneroTransactionRsigData import (
            MoneroTransactionRsigData,
        )

        rsig_data = MoneroTransactionRsigData(offload_type=self.rsig_offload)
        return MoneroTransactionInitAck(hmacs=hmacs, rsig_data=rsig_data)

    async def process_payment_id(self, tsx_data):
        """
        Payment id -> extra
        """
        if common.is_empty(tsx_data.payment_id):
            return

        from monero_glue.xmr.sub import tsx_helper

        if len(tsx_data.payment_id) == 8:
            view_key_pub_enc = tsx_helper.get_destination_view_key_pub(
                tsx_data.outputs, self.change_address()
            )
            if view_key_pub_enc == crypto.NULL_KEY_ENC:
                raise ValueError(
                    "Destinations have to have exactly one output to support encrypted payment ids"
                )

            view_key_pub = crypto.decodepoint(view_key_pub_enc)
            payment_id_encr = tsx_helper.encrypt_payment_id(
                tsx_data.payment_id, view_key_pub, self.r
            )

            extra_nonce = payment_id_encr
            extra_prefix = 1

        elif len(tsx_data.payment_id) == 32:
            extra_nonce = tsx_data.payment_id
            extra_prefix = 0

        else:
            raise ValueError("Payment ID size invalid")

        lextra = len(extra_nonce)
        if lextra >= 255:
            raise ValueError("Nonce could be 255 bytes max")

        extra_buff = bytearray(3 + lextra)
        extra_buff[0] = 2
        extra_buff[1] = lextra + 1
        extra_buff[2] = extra_prefix
        utils.memcpy(extra_buff, 3, extra_nonce, 0, lextra)
        self.tx.extra = extra_buff

    async def compute_sec_keys(self, tsx_data):
        """
        Generate master key H(TsxData || r)
        :return:
        """
        from .. import protobuf
        from monero_glue.xmr.sub.keccak_hasher import get_keccak_writer

        writer = get_keccak_writer()
        await protobuf.dump_message(writer, tsx_data)
        await writer.awrite(crypto.encodeint(self.r))

        self.key_master = crypto.keccak_2hash(
            writer.get_digest() + crypto.encodeint(crypto.random_scalar())
        )
        self.key_hmac = crypto.keccak_2hash(b"hmac" + self.key_master)
        self.key_enc = crypto.keccak_2hash(b"enc" + self.key_master)

    def precompute_subaddr(self, account, indices):
        """
        Precomputes subaddresses for account (major) and list of indices (minors)
        Subaddresses have to be stored in encoded form - unique representation.
        Single point can have multiple extended coordinates representation - would not match during subaddress search.
        """
        monero.compute_subaddresses(self.creds, account, indices, self.subaddresses)

    async def set_input(self, src_entr):
        """
        Sets UTXO one by one.
        Computes spending secret key, key image. tx.vin[i] + HMAC, Pedersen commitment on amount.

        If number of inputs is small, in-memory mode is used = alpha, pseudo_outs are kept in the Trezor.
        Otherwise pseudo_outs are offloaded with HMAC, alpha is offloaded encrypted under Chacha20Poly1305()
        with key derived for exactly this purpose.
        """
        from monero_glue.messages.MoneroTransactionSetInputAck import (
            MoneroTransactionSetInputAck,
        )
        from monero_glue.xmr.enc import chacha_poly
        from monero_glue.xmr.sub import tsx_helper
        from monero_serialize.xmrtypes import TxinToKey

        self.state.input()
        self.inp_idx += 1

        await self.trezor.iface.transaction_step(
            self.STEP_INP, self.inp_idx, self.num_inputs()
        )

        if self.inp_idx >= self.num_inputs():
            raise ValueError("Too many inputs")
        if src_entr.real_output >= len(src_entr.outputs):
            raise ValueError(
                "real_output index %s bigger than output_keys.size() %s"
                % (src_entr.real_output, len(src_entr.outputs))
            )
        self.summary_inputs_money += src_entr.amount

        # Secrets derivation
        out_key = crypto.decodepoint(src_entr.outputs[src_entr.real_output].key.dest)
        tx_key = crypto.decodepoint(src_entr.real_out_tx_key)
        additional_keys = [
            crypto.decodepoint(x) for x in src_entr.real_out_additional_tx_keys
        ]

        secs = monero.generate_key_image_helper(
            self.creds,
            self.subaddresses,
            out_key,
            tx_key,
            additional_keys,
            src_entr.real_output_in_tx_index,
        )
        xi, ki, di = secs
        self._mem_trace(1, True)

        # Construct tx.vin
        ki_real = src_entr.multisig_kLRki.ki if self.multi_sig else ki
        vini = TxinToKey(amount=src_entr.amount, k_image=crypto.encodepoint(ki_real))
        vini.key_offsets = tsx_helper.absolute_output_offsets_to_relative(
            [x.idx for x in src_entr.outputs]
        )

        if src_entr.rct:
            vini.amount = 0

        # Serialize with variant code for TxinToKey
        vini_bin = await misc.dump_msg(vini, preallocate=64, prefix=b"\x02")
        self._mem_trace(2, True)

        if self.in_memory():
            self.tx.vin.append(vini)

        # HMAC(T_in,i || vin_i)
        hmac_vini = await self.gen_hmac_vini(src_entr, vini_bin, self.inp_idx)
        self._mem_trace(3, True)

        # PseudoOuts commitment, alphas stored to state
        pseudo_out = None
        pseudo_out_hmac = None
        alpha_enc = None
        spend_enc = None

        if self.use_simple_rct:
            alpha, pseudo_out = self._gen_commitment(src_entr.amount)
            pseudo_out = crypto.encodepoint(pseudo_out)

            # In full version the alpha is encrypted and passed back for storage
            if self.in_memory():
                self.input_alphas.append(alpha)
                self.input_pseudo_outs.append(pseudo_out)
            else:
                pseudo_out_hmac = crypto.compute_hmac(
                    self.hmac_key_txin_comm(self.inp_idx), pseudo_out
                )
                alpha_enc = chacha_poly.encrypt_pack(
                    self.enc_key_txin_alpha(self.inp_idx), crypto.encodeint(alpha)
                )

        if self.many_inputs():
            spend_enc = chacha_poly.encrypt_pack(
                self.enc_key_spend(self.inp_idx), crypto.encodeint(xi)
            )
        else:
            self.input_secrets.append(xi)

        # All inputs done?
        if self.inp_idx + 1 == self.num_inputs():
            await self.tsx_inputs_done()

        return MoneroTransactionSetInputAck(
            vini=vini_bin,
            vini_hmac=hmac_vini,
            pseudo_out=pseudo_out,
            pseudo_out_hmac=pseudo_out_hmac,
            pseudo_out_alpha=alpha_enc,
            spend_key=spend_enc,
        )

    async def tsx_inputs_done(self):
        """
        All inputs set
        """
        self.state.input_done()
        self.subaddresses = None

        if self.inp_idx + 1 != self.num_inputs():
            raise ValueError("Input count mismatch")

        if self.in_memory():
            return await self.tsx_inputs_done_inm()

    async def tsx_inputs_done_inm(self):
        """
        In-memory post processing - tx.vin[i] sorting by key image.
        Used only if number of inputs is small - computable in Trezor without offloading.
        """
        # Sort tx.in by key image
        self.source_permutation = list(range(self.num_inputs()))
        self.source_permutation.sort(key=lambda x: self.tx.vin[x].k_image, reverse=True)
        await self._tsx_inputs_permutation(self.source_permutation)

    async def tsx_inputs_permutation(self, permutation):
        """
        Set permutation on the inputs - sorted by key image on host.
        """
        from monero_glue.messages.MoneroTransactionInputsPermutationAck import (
            MoneroTransactionInputsPermutationAck,
        )

        await self.trezor.iface.transaction_step(self.STEP_PERM)

        if self.in_memory():
            return
        await self._tsx_inputs_permutation(permutation)
        return MoneroTransactionInputsPermutationAck()

    async def _tsx_inputs_permutation(self, permutation):
        """
        Set permutation on the inputs - sorted by key image on host.
        """
        self.state.input_permutation()
        self.source_permutation = permutation

        def swapper(x, y):
            if not self.many_inputs():
                self.input_secrets[x], self.input_secrets[y] = (
                    self.input_secrets[y],
                    self.input_secrets[x],
                )
            if self.in_memory() and self.use_simple_rct:
                self.input_alphas[x], self.input_alphas[y] = (
                    self.input_alphas[y],
                    self.input_alphas[x],
                )
                self.input_pseudo_outs[x], self.input_pseudo_outs[y] = (
                    self.input_pseudo_outs[y],
                    self.input_pseudo_outs[x],
                )
            if self.in_memory():
                self.tx.vin[x], self.tx.vin[y] = self.tx.vin[y], self.tx.vin[x]

        common.apply_permutation(self.source_permutation, swapper)
        self.inp_idx = -1

        # Incremental hashing
        if self.in_memory():
            for idx in range(self.num_inputs()):
                vini_bin = await misc.dump_msg(
                    self.tx.vin[idx], preallocate=65, prefix=b"\x02"
                )
                await self.hash_vini_pseudo_out(vini_bin, idx)
                self._mem_trace("i: %s" % idx if __debug__ else None, True)

    async def input_vini(self, src_entr, vini_bin, hmac, pseudo_out, pseudo_out_hmac):
        """
        Set tx.vin[i] for incremental tx prefix hash computation.
        After sorting by key images on host.
        Hashes pseudo_out to the final_message.

        :param src_entr:
        :param vini_bin: tx.vin[i]
        :param hmac: HMAC of tx.vin[i]
        :param pseudo_out: pseudo_out for the current entry
        :param pseudo_out_hmac: hmac of pseudo_out
        :return:
        """
        from monero_glue.messages.MoneroTransactionInputViniAck import (
            MoneroTransactionInputViniAck,
        )

        await self.trezor.iface.transaction_step(
            self.STEP_VINI, self.inp_idx + 1, self.num_inputs()
        )

        if self.in_memory():
            return
        if self.inp_idx >= self.num_inputs():
            raise ValueError("Too many inputs")

        self.state.input_vins()
        self.inp_idx += 1

        # HMAC(T_in,i || vin_i)
        hmac_vini = await self.gen_hmac_vini(
            src_entr, vini_bin, self.source_permutation[self.inp_idx]
        )
        if not common.ct_equal(hmac_vini, hmac):
            raise ValueError("HMAC is not correct")

        await self.hash_vini_pseudo_out(
            vini_bin, self.inp_idx, pseudo_out, pseudo_out_hmac
        )
        return MoneroTransactionInputViniAck()

    async def hash_vini_pseudo_out(
        self, vini_bin, inp_idx, pseudo_out=None, pseudo_out_hmac=None
    ):
        """
        Incremental hasing of tx.vin[i] and pseudo output
        """
        await self.tx_prefix_hasher.buffer(vini_bin)

        # Pseudo_out incremental hashing - applicable only in simple rct
        if not self.use_simple_rct or self.use_bulletproof:
            return

        if not self.in_memory():
            idx = self.source_permutation[inp_idx]
            pseudo_out_hmac_comp = crypto.compute_hmac(
                self.hmac_key_txin_comm(idx), pseudo_out
            )
            if not common.ct_equal(pseudo_out_hmac, pseudo_out_hmac_comp):
                raise ValueError("HMAC invalid for pseudo outs")
        else:
            pseudo_out = self.input_pseudo_outs[inp_idx]

        await self.full_message_hasher.set_pseudo_out(pseudo_out)

    async def all_in_set(self):
        """
        If in the applicable offloading mode, generate commitment masks.
        """
        self._mem_trace(0)
        self.state.input_all_done()
        await self.trezor.iface.transaction_step(self.STEP_ALL_IN)

        from monero_glue.messages import MoneroTransactionAllInputsSetAck
        from monero_glue.messages import MoneroTransactionRsigData

        rsig_data = MoneroTransactionRsigData()
        resp = MoneroTransactionAllInputsSetAck(rsig_data=rsig_data)

        if not self.rsig_offload:
            return resp

        # Simple offloading - generate random masks that sum to the input mask sum.
        tmp_buff = bytearray(32)
        rsig_data.mask = bytearray(32 * self.num_dests())
        self.sumout = crypto.sc_init(0)
        for i in range(self.num_dests()):
            cur_mask = crypto.new_scalar()
            is_last = i + 1 == self.num_dests()
            if is_last and self.use_simple_rct:
                crypto.sc_sub_into(cur_mask, self.sumpouts_alphas, self.sumout)
            else:
                crypto.random_scalar_into(cur_mask)

            crypto.sc_add_into(self.sumout, self.sumout, cur_mask)
            self.output_masks.append(cur_mask)
            crypto.encodeint_into(tmp_buff, cur_mask)
            utils.memcpy(rsig_data.mask, 32 * i, tmp_buff, 0, 32)

        self.assrt(crypto.sc_eq(self.sumout, self.sumpouts_alphas), "Invalid masks sum")
        self.sumout = crypto.sc_init(0)
        return resp

    def _get_out_mask(self, idx):
        if self.rsig_offload:
            return self.output_masks[idx]
        else:
            is_last = idx + 1 == self.num_dests()
            if is_last:
                return crypto.sc_sub(self.sumpouts_alphas, self.sumout)
            else:
                return crypto.random_scalar()

    def _get_rsig_batch(self, idx):
        """
        Returns index of the current rsig batch
        """
        r = 0
        c = 0
        while c < idx + 1:
            c += self.rsig_grp[r]
            r += 1
        return r - 1

    def _is_last_in_batch(self, idx, bidx=None):
        """
        Returns true if the current output is last in the rsig batch
        """
        bidx = self._get_rsig_batch(idx) if bidx is None else bidx
        batch_size = self.rsig_grp[bidx]
        return (idx - sum(self.rsig_grp[:bidx])) + 1 == batch_size

    def _gen_commitment(self, in_amount):
        """
        Computes Pedersen commitment - pseudo outs
        Here is slight deviation from the original protocol.
        We want that \\sum Alpha = \\sum A_{i,j} where A_{i,j} is a mask from range proof for output i, bit j.

        Previously this was computed in such a way that Alpha_{last} = \\sum A{i,j} - \\sum_{i=0}^{last-1} Alpha
        But we would prefer to compute commitment before range proofs so alphas are generated completely randomly
        and the last A mask is computed in this special way.
        Returns pseudo_out
        """
        alpha = crypto.random_scalar()
        self.sumpouts_alphas = crypto.sc_add(self.sumpouts_alphas, alpha)
        return alpha, crypto.gen_c(alpha, in_amount)

    def _check_out_commitment(self, amount, mask, C):
        self.assrt(
            crypto.point_eq(
                C,
                crypto.point_add(
                    crypto.scalarmult_base(mask), crypto.scalarmult_h(amount)
                ),
            ),
            "OutC fail",
        )

    def _check_bproof(self, batch_size, rsig, masks):
        if len(rsig.V) < batch_size:
            raise misc.TrezorError("Bulletproof to small")

        for i in range(batch_size):
            C = crypto.decodepoint(rsig.V[i])
            crypto.point_mul8_into(C, C)
            self._check_out_commitment(self.output_amounts[i], masks[i], C)

    def _return_rsig_data(self, rsig):
        if rsig is None:
            return None
        from monero_glue.messages import MoneroTransactionRsigData

        if isinstance(rsig, list):
            return MoneroTransactionRsigData(rsig_parts=rsig)
        else:
            return MoneroTransactionRsigData(rsig=rsig)

    async def _range_proof(self, idx, amount, rsig_data=None):
        """
        Computes rangeproof and related information - out_sk, out_pk, ecdh_info.
        In order to optimize incremental transaction build, the mask computation is changed compared
        to the official Monero code. In the official code, the input pedersen commitments are computed
        after range proof in such a way summed masks for commitments (alpha) and rangeproofs (ai) are equal.

        In order to save roundtrips we compute commitments randomly and then for the last rangeproof
        a[63] = (\\sum_{i=0}^{num_inp}alpha_i - \\sum_{i=0}^{num_outs-1} amasks_i) - \\sum_{i=0}^{62}a_i

        The range proof is incrementally hashed to the final_message.
        """
        from monero_glue.xmr import ring_ct

        mask = self._get_out_mask(idx)
        self.output_amounts.append(amount)
        provided_rsig = (
            rsig_data.rsig
            if rsig_data and rsig_data.rsig and len(rsig_data.rsig) > 0
            else None
        )
        if not self.rsig_offload and provided_rsig:
            raise misc.TrezorError("Provided unexpected rsig")
        if not self.rsig_offload:
            self.output_masks.append(mask)

        # Batching
        bidx = self._get_rsig_batch(idx)
        batch_size = self.rsig_grp[bidx]
        last_in_batch = self._is_last_in_batch(idx, bidx)
        if self.rsig_offload and provided_rsig and not last_in_batch:
            raise misc.TrezorError("Provided rsig too early")
        if self.rsig_offload and last_in_batch and not provided_rsig:
            raise misc.TrezorError("Rsig expected, not provided")

        # Batch not finished, skip range sig generation now
        if not last_in_batch:
            return None, mask

        # Rangeproof
        # Pedersen commitment on the value, mask from the commitment, range signature.
        C, rsig = None, None

        self._mem_trace("pre-rproof" if __debug__ else None, collect=True)
        if not self.rsig_offload and self.use_bulletproof:
            rsig = await ring_ct.prove_range_bp_batch(
                self.output_amounts, self.output_masks
            )
            self._mem_trace("post-bp" if __debug__ else None, collect=True)

            # Incremental hashing
            await self.full_message_hasher.rsig_val(rsig, True, raw=False)
            self._mem_trace("post-bp-hash" if __debug__ else None, collect=True)

            rsig = misc.dump_rsig_bp(rsig)
            self._mem_trace(
                "post-bp-ser, size: %s" % len(rsig) if __debug__ else None, collect=True
            )

        elif not self.rsig_offload and not self.use_bulletproof:
            C, mask, rsig = ring_ct.prove_range_chunked(amount, mask)
            del (ring_ct)

            # Incremental hashing
            await self.full_message_hasher.rsig_val(rsig, False, raw=True)
            self._check_out_commitment(amount, mask, C)

        elif self.rsig_offload and self.use_bulletproof:
            from monero_serialize.xmrtypes import Bulletproof

            masks = [
                self._get_out_mask(1 + idx - batch_size + ix)
                for ix in range(batch_size)
            ]

            bp_obj = await misc.parse_msg(rsig_data.rsig, Bulletproof())
            rsig_data.rsig = None

            await self.full_message_hasher.rsig_val(bp_obj, True, raw=False)
            res = await ring_ct.verify_bp(bp_obj, self.output_amounts, masks)
            self.assrt(res, "BP verification fail")
            self._mem_trace("BP verified" if __debug__ else None, collect=True)
            del (bp_obj, ring_ct)

        elif self.rsig_offload and not self.use_bulletproof:
            await self.full_message_hasher.rsig_val(rsig_data.rsig, False, raw=True)
            rsig_data.rsig = None

        else:
            raise misc.TrezorError("Unexpected rsig state")

        self._mem_trace("rproof" if __debug__ else None, collect=True)
        self.output_amounts = []
        if not self.rsig_offload:
            self.output_masks = []
        return rsig, mask

    async def _set_out1_ecdh(self, idx, dest_pub_key, amount, mask, amount_key):
        from monero_glue.xmr import ring_ct

        # Mask sum
        out_pk = misc.StdObj(
            dest=crypto.encodepoint(dest_pub_key),
            mask=crypto.encodepoint(crypto.gen_c(mask, amount)),
        )
        self.sumout = crypto.sc_add(self.sumout, mask)
        self.output_sk.append(misc.StdObj(mask=mask))

        # ECDH masking
        from monero_glue.xmr.sub.recode import recode_ecdh
        from monero_serialize.xmrtypes import EcdhTuple

        ecdh_info = misc.StdObj(mask=mask, amount=crypto.sc_init(amount))
        ring_ct.ecdh_encode_into(
            ecdh_info, ecdh_info, derivation=crypto.encodeint(amount_key)
        )
        recode_ecdh(ecdh_info, encode=True)

        ecdh_info_bin = bytearray(64)
        utils.memcpy(ecdh_info_bin, 0, ecdh_info.mask, 0, 32)
        utils.memcpy(ecdh_info_bin, 32, ecdh_info.amount, 0, 32)
        gc.collect()

        return out_pk, ecdh_info_bin

    async def _set_out1_additional_keys(self, dst_entr):
        additional_txkey = None
        additional_txkey_priv = None
        if self.need_additional_txkeys:
            use_provided = self.num_dests() == len(self.additional_tx_private_keys)
            additional_txkey_priv = (
                self.additional_tx_private_keys[self.out_idx]
                if use_provided
                else crypto.random_scalar()
            )

            if dst_entr.is_subaddress:
                additional_txkey = crypto.scalarmult(
                    crypto.decodepoint(dst_entr.addr.spend_public_key),
                    additional_txkey_priv,
                )
            else:
                additional_txkey = crypto.scalarmult_base(additional_txkey_priv)

            self.additional_tx_public_keys.append(crypto.encodepoint(additional_txkey))
            if not use_provided:
                self.additional_tx_private_keys.append(additional_txkey_priv)
        return additional_txkey_priv

    async def _set_out1_derivation(self, dst_entr, additional_txkey_priv):
        from monero_glue.xmr.sub.addr import addr_eq

        change_addr = self.change_address()
        if change_addr and addr_eq(dst_entr.addr, change_addr):
            # sending change to yourself; derivation = a*R
            derivation = crypto.generate_key_derivation(
                self.r_pub, self.creds.view_key_private
            )

        else:
            # sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
            deriv_priv = (
                additional_txkey_priv
                if dst_entr.is_subaddress and self.need_additional_txkeys
                else self.r
            )
            derivation = crypto.generate_key_derivation(
                crypto.decodepoint(dst_entr.addr.view_public_key), deriv_priv
            )
        return derivation

    async def _set_out1_tx_out(self, dst_entr, tx_out_key):
        # Manual serialization of TxOut(0, TxoutToKey(key))
        tx_out_bin = bytearray(34)
        tx_out_bin[0] = 0  # amount varint
        tx_out_bin[1] = 2  # variant code TxoutToKey
        crypto.encodepoint_into(tx_out_bin, tx_out_key, 2)
        self._mem_trace(8)

        # Tx header prefix hashing
        await self.tx_prefix_hasher.buffer(tx_out_bin)
        self._mem_trace(9, True)

        # Hmac dest_entr.
        hmac_vouti = await self.gen_hmac_vouti(dst_entr, tx_out_bin, self.out_idx)
        self._mem_trace(10, True)
        return tx_out_bin, hmac_vouti

    async def set_out1(self, dst_entr, dst_entr_hmac, rsig_data=None):
        """
        Set destination entry one by one.
        Computes destination stealth address, amount key, range proof + HMAC, out_pk, ecdh_info.
        """
        self._mem_trace(0, True)
        mods = utils.unimport_begin()

        await self.trezor.iface.transaction_step(
            self.STEP_OUT, self.out_idx + 1, self.num_dests()
        )
        self._mem_trace(1)

        if self.state.is_input_vins() and self.inp_idx + 1 != self.num_inputs():
            raise ValueError("Invalid number of inputs")

        self.state.set_output()
        self.out_idx += 1
        self._mem_trace(2, True)

        if dst_entr.amount <= 0 and self.tx.version <= 1:
            raise ValueError("Destination with wrong amount: %s" % dst_entr.amount)

        # HMAC check of the destination
        dst_entr_hmac_computed = await self.gen_hmac_tsxdest(dst_entr, self.out_idx)
        if not common.ct_equal(dst_entr_hmac, dst_entr_hmac_computed):
            raise ValueError("HMAC invalid")
        del (dst_entr_hmac, dst_entr_hmac_computed)
        self._mem_trace(3, True)

        # First output - tx prefix hasher - size of the container
        if self.out_idx == 0:
            await self.tx_prefix_hasher.container_size(self.num_dests())
        self._mem_trace(4, True)

        self.summary_outs_money += dst_entr.amount
        utils.unimport_end(mods)
        self._mem_trace(5, True)

        # Range proof first, memory intensive
        rsig, mask = await self._range_proof(self.out_idx, dst_entr.amount, rsig_data)
        utils.unimport_end(mods)
        self._mem_trace(6, True)

        # Amount key, tx out key
        additional_txkey_priv = await self._set_out1_additional_keys(dst_entr)
        derivation = await self._set_out1_derivation(dst_entr, additional_txkey_priv)
        amount_key = crypto.derivation_to_scalar(derivation, self.out_idx)
        tx_out_key = crypto.derive_public_key(
            derivation, self.out_idx, crypto.decodepoint(dst_entr.addr.spend_public_key)
        )
        del (derivation, additional_txkey_priv)
        self._mem_trace(7, True)

        # Tx header prefix hashing, hmac dst_entr
        tx_out_bin, hmac_vouti = await self._set_out1_tx_out(dst_entr, tx_out_key)
        self._mem_trace(11, True)

        # Out_pk, ecdh_info
        out_pk, ecdh_info_bin = await self._set_out1_ecdh(
            self.out_idx,
            dest_pub_key=tx_out_key,
            amount=dst_entr.amount,
            mask=mask,
            amount_key=amount_key,
        )
        del (dst_entr, mask, amount_key, tx_out_key)
        self._mem_trace(12, True)

        # Incremental hashing of the ECDH info.
        # RctSigBase allows to hash only one of the (ecdh, out_pk) as they are serialized
        # as whole vectors. Hashing ECDH info saves state space.
        await self.full_message_hasher.set_ecdh(ecdh_info_bin)
        self._mem_trace(13, True)

        # Output_pk is stored to the state as it is used during the signature and hashed to the
        # RctSigBase later.
        self.output_pk.append(out_pk)
        self._mem_trace(14, True)

        from monero_glue.messages.MoneroTransactionSetOutputAck import (
            MoneroTransactionSetOutputAck,
        )

        out_pk_bin = bytearray(64)
        utils.memcpy(out_pk_bin, 0, out_pk.dest, 0, 32)
        utils.memcpy(out_pk_bin, 32, out_pk.mask, 0, 32)

        return MoneroTransactionSetOutputAck(
            tx_out=tx_out_bin,
            vouti_hmac=hmac_vouti,
            rsig_data=self._return_rsig_data(rsig),
            out_pk=out_pk_bin,
            ecdh_info=ecdh_info_bin,
        )

    async def all_out1_set_tx_extra(self):
        from monero_glue.xmr.sub import tsx_helper

        self.tx.extra = tsx_helper.add_tx_pub_key_to_extra(self.tx.extra, self.r_pub)

        # Not needed to remove - extra is clean
        # self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraAdditionalPubKeys)
        if self.need_additional_txkeys:
            self.tx.extra = await tsx_helper.add_additional_tx_pub_keys_to_extra(
                self.tx.extra, pub_enc=self.additional_tx_public_keys
            )

    async def all_out1_set_tx_prefix(self):
        from monero_serialize.core.message_types import BlobType

        await self.tx_prefix_hasher.message_field(self.tx, ("extra", BlobType))  # extra

        self.tx_prefix_hash = self.tx_prefix_hasher.get_digest()
        self.tx_prefix_hasher = None

        # Hash message to the final_message
        await self.full_message_hasher.set_message(self.tx_prefix_hash)

    async def all_out1_set(self):
        """
        All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
        transaction prefix hash.
        Adds additional public keys to the tx.extra

        :return: tx.extra, tx_prefix_hash
        """
        self._mem_trace(0)
        self.state.set_output_done()
        await self.trezor.iface.transaction_step(self.STEP_ALL_OUT)
        self._mem_trace(1)

        if self.out_idx + 1 != self.num_dests():
            raise ValueError("Invalid out num")

        # Test if \sum Alpha == \sum A
        if self.use_simple_rct:
            self.assrt(crypto.sc_eq(self.sumout, self.sumpouts_alphas))

        # Fee test
        if self.fee != (self.summary_inputs_money - self.summary_outs_money):
            raise ValueError(
                "Fee invalid %s vs %s, out: %s"
                % (
                    self.fee,
                    self.summary_inputs_money - self.summary_outs_money,
                    self.summary_outs_money,
                )
            )
        self._mem_trace(2)

        # Set public key to the extra
        # Not needed to remove - extra is clean
        await self.all_out1_set_tx_extra()
        self.additional_tx_public_keys = None

        gc.collect()
        self._mem_trace(3)

        if self.summary_outs_money > self.summary_inputs_money:
            raise ValueError(
                "Transaction inputs money (%s) less than outputs money (%s)"
                % (self.summary_inputs_money, self.summary_outs_money)
            )

        # Hashing transaction prefix
        await self.all_out1_set_tx_prefix()
        extra_b = self.tx.extra
        self.tx = None
        gc.collect()
        self._mem_trace(4)

        # Txprefix match check for multisig
        if not common.is_empty(self.exp_tx_prefix_hash) and not common.ct_equal(
            self.exp_tx_prefix_hash, self.tx_prefix_hash
        ):
            self.state.set_fail()
            raise misc.TrezorTxPrefixHashNotMatchingError("Tx prefix invalid")

        gc.collect()
        self._mem_trace(5)

        from monero_glue.messages.MoneroRingCtSig import MoneroRingCtSig
        from monero_glue.messages.MoneroTransactionAllOutSetAck import (
            MoneroTransactionAllOutSetAck,
        )

        rv = self.init_rct_sig()
        rv_pb = MoneroRingCtSig(txn_fee=rv.txnFee, message=rv.message, rv_type=rv.type)

        self.state.set_final_message_done()
        await self.trezor.iface.transaction_step(self.STEP_MLSAG)

        await self.tsx_mlsag_ecdh_info()
        await self.tsx_mlsag_out_pk()
        await self.full_message_hasher.rctsig_base_done()
        self.out_idx = -1
        self.inp_idx = -1

        self.full_message = await self.full_message_hasher.get_digest()
        self.full_message_hasher = None

        return MoneroTransactionAllOutSetAck(
            extra=extra_b,
            tx_prefix_hash=self.tx_prefix_hash,
            rv=rv_pb,
            full_message_hash=self.full_message,
        )

    async def tsx_mlsag_ecdh_info(self):
        """
        Sets ecdh info for the incremental hashing mlsag.
        """
        pass

    async def tsx_mlsag_out_pk(self):
        """
        Sets out_pk for the incremental hashing mlsag.
        """
        if self.num_dests() != len(self.output_pk):
            raise ValueError("Invalid number of ecdh")

        for out in self.output_pk:
            await self.full_message_hasher.set_out_pk(out)

    async def sign_input(
        self,
        src_entr,
        vini_bin,
        hmac_vini,
        pseudo_out,
        pseudo_out_hmac,
        alpha_enc,
        spend_enc,
    ):
        """
        Generates a signature for one input.

        :param src_entr: Source entry
        :param vini_bin: tx.vin[i] for the transaction. Contains key image, offsets, amount (usually zero)
        :param hmac_vini: HMAC for the tx.vin[i] as returned from Trezor
        :param pseudo_out: pedersen commitment for the current input, uses alpha as the mask.
        Only in memory offloaded scenario. Tuple containing HMAC, as returned from the Trezor.
        :param pseudo_out_hmac:
        :param alpha_enc: alpha mask for the current input. Only in memory offloaded scenario,
        tuple as returned from the Trezor
        :param spend_enc:
        :return: Generated signature MGs[i]
        """
        self.state.set_signature()
        await self.trezor.iface.transaction_step(
            self.STEP_SIGN, self.inp_idx + 1, self.num_inputs()
        )

        self.inp_idx += 1
        if self.inp_idx >= self.num_inputs():
            raise ValueError("Invalid ins")
        if self.use_simple_rct and (not self.in_memory() and alpha_enc is None):
            raise ValueError("Inconsistent1")
        if self.use_simple_rct and (not self.in_memory() and pseudo_out is None):
            raise ValueError("Inconsistent2")
        if self.inp_idx >= 1 and not self.use_simple_rct:
            raise ValueError("Inconsistent3")

        inv_idx = self.source_permutation[self.inp_idx]

        # Check HMAC of all inputs
        hmac_vini_comp = await self.gen_hmac_vini(src_entr, vini_bin, inv_idx)
        if not common.ct_equal(hmac_vini_comp, hmac_vini):
            raise ValueError("HMAC is not correct")

        gc.collect()
        self._mem_trace(1)

        if self.use_simple_rct and not self.in_memory():
            pseudo_out_hmac_comp = crypto.compute_hmac(
                self.hmac_key_txin_comm(inv_idx), pseudo_out
            )
            if not common.ct_equal(pseudo_out_hmac_comp, pseudo_out_hmac):
                raise ValueError("HMAC is not correct")

            gc.collect()
            self._mem_trace(2)

            from monero_glue.xmr.enc import chacha_poly

            alpha_c = crypto.decodeint(
                chacha_poly.decrypt_pack(
                    self.enc_key_txin_alpha(inv_idx), bytes(alpha_enc)
                )
            )
            pseudo_out_c = crypto.decodepoint(pseudo_out)

        elif self.use_simple_rct:
            alpha_c = self.input_alphas[self.inp_idx]
            pseudo_out_c = crypto.decodepoint(self.input_pseudo_outs[self.inp_idx])

        else:
            alpha_c = None
            pseudo_out_c = None

        # Spending secret
        if self.many_inputs():
            from monero_glue.xmr.enc import chacha_poly

            input_secret = crypto.decodeint(
                chacha_poly.decrypt_pack(self.enc_key_spend(inv_idx), bytes(spend_enc))
            )
        else:
            input_secret = self.input_secrets[self.inp_idx]

        gc.collect()
        self._mem_trace(3)

        # Basic setup, sanity check
        index = src_entr.real_output
        in_sk = misc.StdObj(dest=input_secret, mask=crypto.decodeint(src_entr.mask))
        kLRki = src_entr.multisig_kLRki if self.multi_sig else None

        # Private key correctness test
        self.assrt(
            crypto.point_eq(
                crypto.decodepoint(src_entr.outputs[src_entr.real_output].key.dest),
                crypto.scalarmult_base(in_sk.dest),
            ),
            "a1",
        )
        self.assrt(
            crypto.point_eq(
                crypto.decodepoint(
                    src_entr.outputs[src_entr.real_output].key.commitment
                ),
                crypto.gen_c(in_sk.mask, src_entr.amount),
            ),
            "a2",
        )

        gc.collect()
        self._mem_trace(4)

        # RCT signature
        gc.collect()
        from monero_glue.xmr import mlsag2

        mg = None
        if self.use_simple_rct:
            # Simple RingCT
            mix_ring = [x.key for x in src_entr.outputs]
            mg, msc = mlsag2.prove_rct_mg_simple(
                self.full_message,
                mix_ring,
                in_sk,
                alpha_c,
                pseudo_out_c,
                kLRki,
                None,
                index,
            )

            if __debug__:
                self.assrt(
                    mlsag2.ver_rct_mg_simple(
                        self.full_message, mg, mix_ring, pseudo_out_c
                    )
                )

        else:
            # Full RingCt, only one input
            txn_fee_key = crypto.scalarmult_h(self.get_fee())
            mix_ring = [[x.key] for x in src_entr.outputs]

            mg, msc = mlsag2.prove_rct_mg(
                self.full_message,
                mix_ring,
                [in_sk],
                self.output_sk,
                self.output_pk,
                kLRki,
                None,
                index,
                txn_fee_key,
            )

            if __debug__:
                self.assrt(
                    mlsag2.ver_rct_mg(
                        mg, mix_ring, self.output_pk, txn_fee_key, self.full_message
                    )
                )

        gc.collect()
        self._mem_trace(5)

        # Encode
        from monero_glue.xmr.sub.recode import recode_msg

        mgs = recode_msg([mg])
        cout = None

        gc.collect()
        self._mem_trace(6)

        # Multisig values returned encrypted, keys returned after finished successfully.
        if self.multi_sig:
            from monero_glue.xmr.enc import chacha_poly

            cout = chacha_poly.encrypt_pack(self.enc_key_cout(), crypto.encodeint(msc))

        # Final state transition
        if self.inp_idx + 1 == self.num_inputs():
            self.state.set_signature_done()
            await self.trezor.iface.transaction_signed()

        gc.collect()
        self._mem_trace()

        from monero_glue.messages.MoneroTransactionSignInputAck import (
            MoneroTransactionSignInputAck,
        )

        return MoneroTransactionSignInputAck(
            signature=await misc.dump_msg_gc(mgs[0], preallocate=488, del_msg=True)
        )

    async def final_msg(self, *args, **kwargs):
        """
        Final step after transaction signing.
        """
        from monero_glue.messages.MoneroTransactionFinalAck import (
            MoneroTransactionFinalAck,
        )
        from monero_glue.xmr.enc import chacha_poly

        self.state.set_final()

        cout_key = self.enc_key_cout() if self.multi_sig else None

        # Encrypted tx keys under transaction specific key, derived from txhash and spend key.
        # Deterministic transaction key, so we can recover it just from transaction and the spend key.
        tx_key, salt, rand_mult = misc.compute_tx_key(
            self.creds.spend_key_private, self.tx_prefix_hash
        )

        key_buff = crypto.encodeint(self.r) + b"".join(
            [crypto.encodeint(x) for x in self.additional_tx_private_keys]
        )
        tx_enc_keys = chacha_poly.encrypt_pack(tx_key, key_buff)

        await self.trezor.iface.transaction_finished()
        gc.collect()

        return MoneroTransactionFinalAck(
            cout_key=cout_key, salt=salt, rand_mult=rand_mult, tx_enc_keys=tx_enc_keys
        )
