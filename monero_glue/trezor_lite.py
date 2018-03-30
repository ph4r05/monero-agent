#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii

from monero_serialize import xmrtypes, xmrserialize
from .monero import TsxData, classify_subaddresses, addr_to_hash
from . import monero, crypto, ring_ct, mlsag2, aesgcm
from . import common as common
from . import trezor


class TrezorLite(object):
    """
    Main Trezor object.
    Provides interface to the host, packages messages.
    """
    def __init__(self):
        self.tsx_ctr = 0
        self.err_ctr = 0
        self.tsx_obj = None  # type: TTransaction
        self.creds = None  # type: trezor.WalletCreds

    def exc_handler(self, e):
        """
        Handles the exception thrown in the Trezor processing
        We could use decorator/wrapper for message calls but not sure how uPython handles them
        so now are entry points wrapped in try-catch

        :param e:
        :return:
        """
        self.err_ctr += 1
        self.tsx_obj = None  # clear transaction object

    async def init_transaction(self, tsx_data: TsxData):
        self.tsx_ctr += 1
        self.tsx_obj = TTransaction(self)
        self.tsx_obj.creds = self.creds
        try:
            return await self.tsx_obj.init_transaction(tsx_data, self.tsx_ctr)
        except Exception as e:
            self.exc_handler(e)
            raise

    async def precompute_subaddr(self, account, indices):
        """
        Precomputes subaddresses for account (major) and list of indices (minors)
        :param account:
        :param indices:
        :return:
        """
        try:
            return self.tsx_obj.precompute_subaddr(account, indices)
        except Exception as e:
            self.exc_handler(e)
            raise

    async def set_tsx_input(self, src_entr):
        """
        :param src_entr
        :type src_entr: xmrtypes.TxSourceEntry
        :return:
        """
        try:
            return await self.tsx_obj.set_input(src_entr)
        except Exception as e:
            self.exc_handler(e)
            raise

    async def tsx_inputs_done(self):
        """
        All inputs set
        :return:
        """
        try:
            return await self.tsx_obj.tsx_inputs_done()
        except Exception as e:
            self.exc_handler(e)
            raise

    async def tsx_inputs_permutation(self, permutation):
        """
        All inputs set
        :return:
        """
        try:
            return await self.tsx_obj.tsx_inputs_permutation(permutation)
        except Exception as e:
            self.exc_handler(e)
            raise

    async def tsx_input_vini(self, *args, **kwargs):
        """
        All inputs set
        :return:
        """
        try:
            return await self.tsx_obj.tsx_input_vini(*args, **kwargs)
        except Exception as e:
            self.exc_handler(e)
            raise

    async def tsx_input_vini_done(self, *args, **kwargs):
        """
        All inputs set
        :return:
        """
        try:
            return await self.tsx_obj.tsx_input_vini_done()
        except Exception as e:
            self.exc_handler(e)
            raise

    async def set_tsx_output1(self, dst_entr, dst_entr_hmac):
        """
        :param dst_entr
        :type dst_entr: xmrtypes.TxDestinationEntry
        :param dst_entr_hmac
        :return:
        """
        try:
            return await self.tsx_obj.set_out1(dst_entr, dst_entr_hmac)
        except Exception as e:
            self.exc_handler(e)
            raise

    async def all_out1_set(self):
        """
        :return:
        """
        try:
            return await self.tsx_obj.all_out1_set()
        except Exception as e:
            self.exc_handler(e)
            raise

    async def tsx_mlsag_pseudo_out(self, out):
        """
        :return:
        """
        try:
            return await self.tsx_obj.tsx_mlsag_pseudo_out(out)
        except Exception as e:
            self.exc_handler(e)
            raise

    async def tsx_gen_rv(self):
        """
        :return:
        """
        try:
            return await self.tsx_obj.tsx_gen_rv()
        except Exception as e:
            self.exc_handler(e)
            raise

    async def tsx_mlsag_rangeproof(self, range_proof):
        """
        :return:
        """
        try:
            return await self.tsx_obj.tsx_mlsag_rangeproof(range_proof)
        except Exception as e:
            self.exc_handler(e)
            raise

    async def tsx_mlsag_done(self):
        """
        :return:
        """
        try:
            return await self.tsx_obj.tsx_mlsag_done()
        except Exception as e:
            self.exc_handler(e)
            raise

    async def sign_input(self, src_entr, vini, hmac_vini, pseudo_out, alpha):
        """
        :return:
        """
        try:
            return await self.tsx_obj.sign_input(src_entr, vini, hmac_vini, pseudo_out, alpha)
        except Exception as e:
            self.exc_handler(e)
            raise


class TState(object):
    """
    Transaction state
    """
    def __init__(self):
        self.s = 0
        self.in_mem = False

    def init_tsx(self):
        if self.s != 0:
            raise ValueError('Illegal state')
        self.s = 1

    def inp_cnt(self, in_mem):
        if self.s != 1:
            raise ValueError('Illegal state')
        self.s = 2
        self.in_mem = in_mem

    def precomp(self):
        if self.s != 2:
            raise ValueError('Illegal state')
        self.s = 3

    def input(self):
        if self.s != 3 and self.s != 4:
            raise ValueError('Illegal state')
        self.s = 4

    def input_done(self):
        if self.s != 4:
            raise ValueError('Illegal state')
        self.s = 5

    def input_permutation(self):
        if self.s != 5:
            raise ValueError('Illegal state')
        self.s = 6

    def input_vins(self):
        if self.s != 6 and self.s != 7:
            raise ValueError('Illegal state')
        self.s = 7

    def input_vins_done(self):
        if self.in_mem or self.s != 7:
            raise ValueError('Illegal state')
        self.s = 8

    def set_output(self):
        if ((not self.in_mem and self.s != 7) or (self.in_mem and self.s != 6)) and self.s != 9:
            raise ValueError('Illegal state')
        self.s = 9

    def set_output_done(self):
        if self.s != 9:
            raise ValueError('Illegal state')
        self.s = 10

    def set_pseudo_out(self):
        if self.s != 10 and self.s != 11:
            raise ValueError('Illegal state')
        self.s = 11

    def set_range_proof(self):
        if self.s != 10 and self.s != 11 and self.s != 12:
            raise ValueError('Illegal state')
        self.s = 12

    def set_final_message_done(self):
        if self.s != 12:
            raise ValueError('Illegal state')
        self.s = 13

    def set_signature(self):
        if self.s != 13 and self.s != 14:
            raise ValueError('Illegal state')
        self.s = 14


class TTransaction(object):
    """
    Transaction builder
    """
    def __init__(self, trezor=None):
        self.trezor = trezor  # type: TrezorLite
        self.creds = None  # type: trezor.WalletCreds
        self.key_master = None
        self.key_hmac = None
        self.key_enc = None

        self.r = None  # txkey
        self.r_pub = None
        self.state = TState()

        self.multi_sig = False
        self.need_additional_txkeys = False
        self.use_bulletproof = False
        self.use_rct = True
        self.use_simple_rct = False
        self.input_count = 0
        self.output_count = 0
        self.output_change = None
        self.mixin = 0

        self.additional_tx_keys = []
        self.additional_tx_public_keys = []
        self.inp_idx = -1
        self.out_idx = -1
        self.summary_inputs_money = 0
        self.summary_outs_money = 0
        self.input_secrets = []
        self.input_alphas = []
        self.input_pseudo_outs = []
        self.output_secrets = []
        self.output_amounts = []
        self.output_sk = []
        self.output_pk = []
        self.output_ecdh = []
        self.sumout = 0
        self.sumpouts_alphas = 0
        self.subaddresses = {}
        self.tx = xmrtypes.Transaction(vin=[], vout=[], extra=b'')
        self.source_permutation = []  # sorted by key images
        self.tx_prefix_hasher = common.KeccakArchive()
        self.tx_prefix_hash = None
        self.full_message_hasher = monero.PreMlsagHasher()
        self.full_message = None

    def assrt(self, condition, msg=None):
        """
        Asserts condition
        :param condition:
        :param msg:
        :return:
        """
        if condition:
            return
        raise ValueError('Assertion error')

    def gen_r(self):
        """
        Generates a new transaction key pair.
        :return:
        """
        self.r = crypto.random_scalar()
        self.r_pub = crypto.scalarmult_base(self.r)

    async def init_transaction(self, tsx_data, tsx_ctr):
        """
        Initializes a new transaction.
        :param tsx_data:
        :param tsx_ctr:
        :return:
        """
        self.gen_r()
        self.state.init_tsx()

        # Basic transaction parameters
        self.input_count = tsx_data.num_inputs
        self.output_count = len(tsx_data.outputs)
        self.output_change = tsx_data.change_dts
        self.mixin = tsx_data.mixin
        self.use_simple_rct = self.input_count > 1
        self.state.inp_cnt(self.in_memory())
        self.check_change(tsx_data.outputs)

        # Additional keys w.r.t. subaddress destinations
        class_res = classify_subaddresses(tsx_data.outputs, self.change_address())
        num_stdaddresses, num_subaddresses, single_dest_subaddress = class_res

        # if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
        if num_stdaddresses == 0 and num_subaddresses == 1:
            self.r_pub = crypto.ge_scalarmult(self.r, crypto.decodepoint(single_dest_subaddress.m_spend_public_key))

        self.need_additional_txkeys = num_subaddresses > 0 and (num_stdaddresses > 0 or num_subaddresses > 1)
        if self.need_additional_txkeys:
            for _ in range(self.num_dests()):
                self.additional_tx_keys.append(crypto.random_scalar())

        # Extra processing, payment id
        self.tx.version = 2
        self.tx.unlock_time = tsx_data.unlock_time
        await self.process_payment_id(tsx_data)
        await self.compute_sec_keys(tsx_data, tsx_ctr)

        # HMAC outputs - pinning
        hmacs = []
        for idx in range(self.num_dests()):
            c_hmac = await self.gen_hmac_tsxdest(tsx_data.outputs[idx], idx)
            hmacs.append(c_hmac)

        return self.in_memory(), hmacs

    async def process_payment_id(self, tsx_data):
        """
        Payment id -> extra
        :return:
        """
        if tsx_data.payment_id is None or len(tsx_data.payment_id) == 0:
            return

        view_key_pub_enc = monero.get_destination_view_key_pub(tsx_data.outputs, self.change_address())
        if view_key_pub_enc == crypto.NULL_KEY_ENC:
            raise ValueError('Destinations have to have exactly one output to support encrypted payment ids')

        view_key_pub = crypto.decodepoint(view_key_pub_enc)
        payment_id_encr = monero.encrypt_payment_id(tsx_data.payment_id, view_key_pub, self.r)

        extra_nonce = monero.set_encrypted_payment_id_to_tx_extra_nonce(payment_id_encr)
        self.tx.extra = monero.add_extra_nonce_to_tx_extra(b'', extra_nonce)

    async def compute_sec_keys(self, tsx_data, tsx_ctr):
        """
        Generate master key H(TsxData || r || c_tsx)
        :return:
        """
        writer = common.get_keccak_writer()
        ar1 = xmrserialize.Archive(writer, True)
        await ar1.message(tsx_data)
        await xmrserialize.dump_uvarint(writer, self.r)
        await xmrserialize.dump_uvarint(writer, tsx_ctr)
        self.key_master = writer.get_digest()
        self.key_hmac = common.keccak_2hash(b'hmac' + self.key_master)
        self.key_enc = common.keccak_2hash(b'enc' + self.key_master)

    def precompute_subaddr(self, account, indices):
        """
        Precomputes subaddresses for account (major) and list of indices (minors)
        Subaddresses have to be stored in encoded form - unique representation.
        Single point can have multiple extended coordinates representation - would not match during subaddress search.
        :param account:
        :param indices:
        :return:
        """
        self.state.precomp()
        for idx in indices:
            if account == 0 and idx == 0:
                self.subaddresses[crypto.encodepoint(self.trezor.creds.spend_key_public)] = (0, 0)
                continue

            pub = monero.get_subaddress_spend_public_key(self.trezor.creds.view_key_private,
                                                         self.trezor.creds.spend_key_public,
                                                         major=account, minor=idx)
            pub = crypto.encodepoint(pub)
            self.subaddresses[pub] = (account, idx)

    def check_change(self, outputs):
        """
        Checks if the change address is among tx outputs.
        :param outputs:
        :return:
        """
        change_addr = self.change_address()
        if change_addr is None:
            return

        for out in outputs:
            if out.addr == change_addr:
                return True

        raise ValueError('Change address not found in outputs')

    def in_memory(self):
        """
        Returns true if the input transaction can be processed whole in-memory
        :return:
        """
        return self.input_count <= 1

    def num_inputs(self):
        """
        Number of inputs
        :return:
        """
        return self.input_count

    def num_dests(self):
        """
        Number of destinations
        :return:
        """
        return self.output_count

    def get_fee(self):
        """
        Txn fee
        :return:
        """
        fee = self.summary_inputs_money - self.summary_outs_money
        return fee if fee > 0 else 0

    def change_address(self):
        """
        Returns change address if change dst is set
        :return:
        """
        return self.output_change.addr if self.output_change else None

    def get_rct_type(self):
        """
        RCTsig type (simple/full x Borromean/Bulletproof)
        :return:
        """
        if self.use_simple_rct:
            return xmrtypes.RctType.SimpleBulletproof if self.use_bulletproof else xmrtypes.RctType.Simple
        else:
            return xmrtypes.RctType.FullBulletproof if self.use_bulletproof else xmrtypes.RctType.Full

    def init_rct_sig(self):
        """
        Initializes RCTsig structure (fee, tx prefix hash, type)
        :return:
        """
        rv = xmrtypes.RctSig()
        rv.p = xmrtypes.RctSigPrunable()
        rv.txnFee = self.get_fee()
        rv.message = self.tx_prefix_hash
        rv.type = self.get_rct_type()
        return rv

    def hmac_key_txin(self, idx):
        """
        (TxSourceEntry[i] || tx.vin[i]) hmac key
        :param idx:
        :return:
        """
        return common.keccak_2hash(self.key_hmac + b'txin' + xmrserialize.dump_uvarint_b(idx))

    def hmac_key_txin_comm(self, idx):
        """
        pseudo_outputs[i] hmac key. Pedersen commitment for inputs.
        :param idx:
        :return:
        """
        return common.keccak_2hash(self.key_hmac + b'txin-comm' + xmrserialize.dump_uvarint_b(idx))

    def hmac_key_txdst(self, idx):
        """
        TxDestinationEntry[i] hmac key
        :param idx:
        :return:
        """
        return common.keccak_2hash(self.key_hmac + b'txdest' + xmrserialize.dump_uvarint_b(idx))

    def hmac_key_txout(self, idx):
        """
        (TxDestinationEntry[i] || tx.vout[i]) hmac key
        :param idx:
        :return:
        """
        return common.keccak_2hash(self.key_hmac + b'txout' + xmrserialize.dump_uvarint_b(idx))

    def hmac_key_txout_asig(self, idx):
        """
        rsig[i] hmac key. Range signature HMAC
        :param idx:
        :return:
        """
        return common.keccak_2hash(self.key_hmac + b'txout-asig' + xmrserialize.dump_uvarint_b(idx))

    def enc_key_txin_alpha(self, idx):
        """
        AES-GCM encryption key for alpha[i] used in Pedersen commitment in pseudo_outs[i]
        :param idx:
        :return:
        """
        return common.keccak_2hash(self.key_enc + b'txin-alpha' + xmrserialize.dump_uvarint_b(idx))

    async def gen_hmac_vini(self, src_entr, vini, idx):
        """
        Computes hmac (TxSourceEntry[i] || tx.vin[i])
        :param src_entr:
        :param vini:
        :param idx:
        :return:
        """
        kwriter = common.get_keccak_writer()
        ar = xmrserialize.Archive(kwriter, True)
        await ar.message(src_entr, xmrtypes.TxSourceEntry)
        await ar.message(vini, xmrtypes.TxinToKey)

        hmac_key_vini = self.hmac_key_txin(idx)
        hmac_vini = common.compute_hmac(hmac_key_vini, kwriter.get_digest())
        return hmac_vini

    async def gen_hmac_vouti(self, dst_entr, tx_out, idx):
        """
        Generates HMAC for (TxDestinationEntry[i] || tx.vout[i])
        :param dst_entr:
        :param tx_out:
        :param idx:
        :return:
        """
        kwriter = common.get_keccak_writer()
        ar = xmrserialize.Archive(kwriter, True)
        await ar.message(dst_entr, xmrtypes.TxDestinationEntry)
        await ar.message(tx_out, xmrtypes.TxOut)

        hmac_key_vouti = self.hmac_key_txout(idx)
        hmac_vouti = common.compute_hmac(hmac_key_vouti, kwriter.get_digest())
        return hmac_vouti

    async def gen_hmac_tsxdest(self, dst_entr, idx):
        """
        Generates HMAC for TxDestinationEntry[i]
        :param dst_entr:
        :param idx:
        :return:
        """
        kwriter = common.get_keccak_writer()
        ar = xmrserialize.Archive(kwriter, True)
        await ar.message(dst_entr, xmrtypes.TxDestinationEntry)

        hmac_key = self.hmac_key_txdst(idx)
        hmac_tsxdest = common.compute_hmac(hmac_key, kwriter.get_digest())
        return hmac_tsxdest

    async def set_input(self, src_entr):
        """
        Sets UTXO one by one.
        Computes spending secret key, key image. tx.vin[i] + HMAC, Pedersen commitment on amount.

        If number of inputs is small, in-memory mode is used = alpha, pseudo_outs are kept in the Trezor.
        Otherwise pseudo_outs are offloaded with HMAC, alpha is offloaded encrypted under AES-GCM() with
        key derived for exactly this purpose.

        :param src_entr:
        :type src_entr: xmrtypes.TxSourceEntry
        :return:
        """
        self.state.input()
        self.inp_idx += 1
        if self.inp_idx >= self.num_inputs():
            raise ValueError('Too many inputs')
        if src_entr.real_output >= len(src_entr.outputs):
            raise ValueError('real_output index %s bigger than output_keys.size()' % (src_entr.real_output, len(src_entr.outputs)))
        self.summary_inputs_money += src_entr.amount

        # Secrets derivation
        out_key = crypto.decodepoint(src_entr.outputs[src_entr.real_output][1].dest)
        tx_key = crypto.decodepoint(src_entr.real_out_tx_key)
        additional_keys = [crypto.decodepoint(x) for x in src_entr.real_out_additional_tx_keys]

        secs = monero.generate_key_image_helper(self.trezor.creds, self.subaddresses, out_key,
                                                tx_key,
                                                additional_keys,
                                                src_entr.real_output_in_tx_index)
        xi, ki, di = secs
        self.input_secrets.append(xi)

        # Construct tx.vin
        ki_real = src_entr.multisig_kLRki.ki if self.multi_sig else ki
        vini = xmrtypes.TxinToKey(amount=src_entr.amount, k_image=crypto.encodepoint(ki_real))
        vini.key_offsets = [x[0] for x in src_entr.outputs]
        vini.key_offsets = monero.absolute_output_offsets_to_relative(vini.key_offsets)

        if src_entr.rct:
            vini.amount = 0

        if self.in_memory():
            self.tx.vin.append(vini)

        # HMAC(T_in,i || vin_i)
        hmac_vini = await self.gen_hmac_vini(src_entr, vini, self.inp_idx)

        # PseudoOuts commitment, alphas stored to state
        pseudo_out = None
        pseudo_out_hmac = None
        alpha_enc = None
        if self.use_simple_rct:
            alpha, pseudo_out = await self.commitment(src_entr.amount)
            pseudo_out = crypto.encodepoint(pseudo_out)

            # In full version the alpha is encrypted and passed back for storage
            if self.in_memory():
                self.input_alphas.append(alpha)
                self.input_pseudo_outs.append(pseudo_out)
            else:
                pseudo_out_hmac = common.compute_hmac(self.hmac_key_txin_comm(self.inp_idx), pseudo_out)
                alpha_enc = aesgcm.encrypt(self.enc_key_txin_alpha(self.inp_idx), crypto.encodeint(alpha))

        return vini, hmac_vini, (pseudo_out, pseudo_out_hmac), alpha_enc

    async def tsx_inputs_done_inm(self):
        """
        In-memory post processing - tx.vin[i] sorting by key image.
        Used only if number of inputs is small - computable in Trezor without offloading.

        :return:
        """
        # Sort tx.in by key image
        self.source_permutation = list(range(self.num_inputs()))
        self.source_permutation.sort(key=lambda x: self.tx.vin[x].k_image)
        await self._tsx_inputs_permutation(self.source_permutation)

    async def tsx_inputs_done(self):
        """
        All inputs set
        :return:
        """
        self.state.input_done()
        if self.inp_idx + 1 != self.num_inputs():
            raise ValueError('Input count mismatch')
        if self.in_memory():
            return await self.tsx_inputs_done_inm()

        # Iterative message hash computation
        await self.tx_prefix_hasher.ar.message_field(self.tx, xmrtypes.TransactionPrefix.FIELDS[0])
        await self.tx_prefix_hasher.ar.message_field(self.tx, xmrtypes.TransactionPrefix.FIELDS[1])

        # vins size
        await self.tx_prefix_hasher.ar.container_size(self.num_inputs(), xmrtypes.TransactionPrefix.FIELDS[2][1])
        return self.r_pub

    async def tsx_inputs_permutation(self, permutation):
        """
        Set permutation on the inputs - sorted by key image on host.

        :param permutation:
        :return:
        """
        if self.in_memory():
            return
        return await self._tsx_inputs_permutation(permutation)

    async def _tsx_inputs_permutation(self, permutation):
        """
        Set permutation on the inputs - sorted by key image on host.

        :param permutation:
        :return:
        """
        self.state.input_permutation()
        self.source_permutation = permutation

        def swapper(x, y):
            self.input_secrets[x], self.input_secrets[y] = self.input_secrets[y], self.input_secrets[x]
            if self.in_memory() and self.use_simple_rct:
                self.input_alphas[x], self.input_alphas[y] = self.input_alphas[y], self.input_alphas[x]
                self.input_pseudo_outs[x], self.input_pseudo_outs[y] = self.input_pseudo_outs[y], self.input_pseudo_outs[x]
            if self.in_memory():
                self.tx.vin[x], self.tx.vin[y] = self.tx.vin[y], self.tx.vin[x]

        common.apply_permutation(self.source_permutation, swapper)
        self.inp_idx = -1

    async def tsx_input_vini(self, src_entr, vini, hmac):
        """
        Set tx.vin[i] for incremental tx prefix hash computation.
        After sorting by key images on host.

        :param src_entr:
        :param vini: tx.vin[i]
        :param hmac: HMAC of tx.vin[i]
        :return:
        """
        if self.in_memory():
            return

        self.state.input_vins()
        self.inp_idx += 1

        # HMAC(T_in,i || vin_i)
        hmac_vini = await self.gen_hmac_vini(src_entr, vini, self.source_permutation[self.inp_idx])
        if not common.ct_equal(hmac_vini, hmac):
            raise ValueError('HMAC is not correct')

        # Serialize particular input type
        await self.tx_prefix_hasher.ar.field(vini, xmrtypes.TxInV)

    async def tsx_input_vini_done(self):
        """
        All inputs were set from the Agent.
        Shifts state machine to a next state (if everything is set correctly).
        Currently we return nothing from this message.
        :return:
        """
        self.state.input_vins_done()
        if self.inp_idx + 1 != self.num_inputs():
            raise ValueError('Invalid number of inputs')

    async def commitment(self, in_amount):
        """
        Computes Pedersen commitment - pseudo outs
        Here is slight deviation from the original protocol.
        We want that \sum Alpha = \sum A_{i,j} where A_{i,j} is a mask from range proof for output i, bit j.

        Previously this was computed in such a way that Alpha_{last} = \sum A{i,j} - \sum_{i=0}^{last-1} Alpha
        But we would prefer to compute commitment before range proofs so alphas are generated completely randomly
        and the last A mask is computed in this special way.
        Returns pseudo_out
        :return:
        """
        alpha = crypto.random_scalar()
        self.sumpouts_alphas = crypto.sc_add(self.sumpouts_alphas, alpha)
        return alpha, crypto.gen_c(alpha, in_amount)

    async def range_proof(self, idx):
        """
        Computes rangeproof and related information - out_sk, out_pk, ecdh_info.
        In order to optimize incremental transaction build, the mask computation is changed compared
        to the official Monero code. In the official code, the input pedersen commitments are computed
        after range proof in such a way summed masks for commitments (alpha) and rangeproofs (ai) are equal.

        In order to save roundtrips we compute commitments randomly and then for the last rangeproof
        a[63] = (\sum_{i=0}^{num_inp}alpha_i - \sum_{i=0}^{num_outs-1} amasks_i) - \sum_{i=0}^{62}a_i

        :param idx:
        :return:
        """
        out_pk = xmrtypes.CtKey(dest=self.tx.vout[idx].target.key)
        is_last = idx + 1 == self.num_dests()
        last_mask = None if not is_last or not self.use_simple_rct else crypto.sc_sub(self.sumpouts_alphas, self.sumout)

        C, mask, rsig = None, 0, None

        # Rangeproof
        if self.use_bulletproof:
            raise ValueError('Bulletproof not yet supported')

        else:
            C, mask, rsig = ring_ct.prove_range(self.output_amounts[idx], last_mask)

            if __debug__:
                self.assrt(ring_ct.ver_range(C, rsig))
                self.assrt(crypto.point_eq(C, crypto.point_add(
                    crypto.scalarmult_base(mask),
                    crypto.scalarmult_h(self.output_amounts[idx]))))

            # Recoding to structure
            monero.recode_rangesig(rsig, encode=True)

        # Mask sum
        out_pk.mask = crypto.encodepoint(C)
        self.sumout = crypto.sc_add(self.sumout, mask)
        self.output_sk.append(xmrtypes.CtKey(mask=mask))

        # ECDH masking
        amount_key = crypto.encodeint(self.output_secrets[idx])
        ecdh_info = xmrtypes.EcdhTuple(mask=mask, amount=self.output_amounts[idx])
        ecdh_info = ring_ct.ecdh_encode(ecdh_info, derivation=amount_key)
        monero.recode_ecdh(ecdh_info, encode=True)
        return rsig, out_pk, ecdh_info

    async def set_out1(self, dst_entr, dst_entr_hmac):
        """
        Set destination entry one by one.
        Computes destination stealth address, amount key, range proof + HMAC, out_pk, ecdh_info.

        :param dst_entr
        :type dst_entr: xmrtypes.TxDestinationEntry
        :param dst_entr_hmac
        :return:
        """
        self.state.set_output()
        self.out_idx += 1
        change_addr = self.change_address()

        if dst_entr.amount <= 0 and self.tx.version <= 1:
            raise ValueError('Destination with wrong amount: %s' % dst_entr.amount)

        # HMAC check of the destination
        dst_entr_hmac_computed = await self.gen_hmac_tsxdest(dst_entr, self.out_idx)
        if not common.ct_equal(dst_entr_hmac, dst_entr_hmac_computed):
            raise ValueError('HMAC invalid')

        if self.need_additional_txkeys:
            if dst_entr.is_subaddress:
                additional_txkey = crypto.ge_scalarmult(self.additional_tx_keys[self.out_idx],
                                                        crypto.decodepoint(dst_entr.addr.m_spend_public_key))
            else:
                additional_txkey = crypto.ge_scalarmult_base(self.additional_tx_keys[self.out_idx])

            self.additional_tx_public_keys.append(additional_txkey)

        if change_addr and dst_entr.addr == change_addr:
            # sending change to yourself; derivation = a*R
            derivation = monero.generate_key_derivation(self.r_pub, self.creds.view_key_private)

        else:
            # sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
            deriv_priv = self.additional_tx_keys[self.out_idx] if dst_entr.is_subaddress and self.need_additional_txkeys else self.r
            derivation = monero.generate_key_derivation(crypto.decodepoint(dst_entr.addr.m_view_public_key), deriv_priv)

        amount_key = crypto.derivation_to_scalar(derivation, self.out_idx)
        tx_out_key = crypto.derive_public_key(derivation, self.out_idx, crypto.decodepoint(dst_entr.addr.m_spend_public_key))
        tk = xmrtypes.TxoutToKey(key=crypto.encodepoint(tx_out_key))
        tx_out = xmrtypes.TxOut(amount=0, target=tk)
        self.tx.vout.append(tx_out)
        self.summary_outs_money += dst_entr.amount

        self.output_secrets.append(amount_key)
        self.output_amounts.append(dst_entr.amount)

        # Hmac dest_entr.
        hmac_vouti = await self.gen_hmac_vouti(dst_entr, tx_out, self.out_idx)

        # Range proof, out_pk, ecdh_info
        rsig, out_pk, ecdh_info = await self.range_proof(self.out_idx)
        kwriter = common.get_keccak_writer()
        ar = xmrserialize.Archive(kwriter, True)
        await ar.message(rsig)

        hmac_key_rsig = self.hmac_key_txout_asig(self.out_idx)
        hmac_rsig = common.compute_hmac(hmac_key_rsig, kwriter.get_digest())
        self.output_pk.append(out_pk)
        self.output_ecdh.append(ecdh_info)

        return tx_out, hmac_vouti, (rsig, hmac_rsig), out_pk, ecdh_info

    async def all_out1_set(self):
        """
        All outputs were set in this phase. Computes additional public keys (if needed), tx.extra and
        transaction prefix hash.
        Adds additional public keys to the tx.extra
        :return: tx.extra, tx_prefix_hash
        """
        self.state.set_output_done()
        if self.out_idx + 1 != self.num_dests():
            raise ValueError('Invalid out num')

        # Test if \sum Alpha == \sum A
        if self.use_simple_rct:
            self.assrt(crypto.sc_eq(self.sumout, self.sumpouts_alphas))

        # Set public key to the extra
        # Not needed to remove - extra is clean
        # self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraPubKey)
        self.tx.extra = monero.add_tx_pub_key_to_extra(self.tx.extra, self.r_pub)

        # Not needed to remove - extra is clean
        # self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraAdditionalPubKeys)
        if self.need_additional_txkeys:
            self.tx.extra = await monero.add_additional_tx_pub_keys_to_extra(self.tx.extra, self.additional_tx_public_keys)

        if self.summary_outs_money > self.summary_inputs_money:
            raise ValueError('Transaction inputs money (%s) less than outputs money (%s)'
                             % (self.summary_inputs_money, self.summary_outs_money))

        # Hashing transaction prefix
        if self.in_memory():
            await self.tx_prefix_hasher.ar.message_field(self.tx, xmrtypes.TransactionPrefix.FIELDS[0])  # version
            await self.tx_prefix_hasher.ar.message_field(self.tx, xmrtypes.TransactionPrefix.FIELDS[1])  # unlock_time
            await self.tx_prefix_hasher.ar.message_field(self.tx, xmrtypes.TransactionPrefix.FIELDS[2])  # vins
        await self.tx_prefix_hasher.ar.message_field(self.tx, xmrtypes.TransactionPrefix.FIELDS[3])  # vouts
        await self.tx_prefix_hasher.ar.message_field(self.tx, xmrtypes.TransactionPrefixExtraBlob.FIELDS[4])  # extra

        self.tx_prefix_hash = self.tx_prefix_hasher.kwriter.get_digest()
        del self.tx_prefix_hasher

        # Init full_message hasher
        # Hash message, type, fee, pseudoOuts number of elements
        self.full_message_hasher.init(self.use_simple_rct, self.tx_prefix_hash)
        await self.full_message_hasher.set_type_fee(self.get_rct_type(), self.get_fee())

        if self.in_memory():
            for idx in range(len(self.input_pseudo_outs)):
                await self.full_message_hasher.set_pseudo_out(self.input_pseudo_outs[idx])
        else:
            self.inp_idx = -1

        return self.tx.extra, self.tx_prefix_hash

    async def tsx_mlsag_pseudo_out(self, out):
        """
        Sets Pseudo outputs (Pedersen commitments) for the final_message incremental hashing.
        :return:
        """
        self.state.set_pseudo_out()
        self.inp_idx += 1
        if self.inp_idx >= self.num_inputs():
            raise ValueError('Too many pseudo inputs')

        if not self.in_memory():
            idx = self.source_permutation[self.inp_idx]
            pseudo_out, pseudo_out_hmac_provided = out
            pseudo_out_hmac = common.compute_hmac(self.hmac_key_txin_comm(idx), pseudo_out)
            if not common.ct_equal(pseudo_out_hmac, pseudo_out_hmac_provided):
                raise ValueError('HMAC invalid for pseudo outs')

            await self.full_message_hasher.set_pseudo_out(pseudo_out)

        # Next state transition
        if self.inp_idx + 1 == self.num_inputs():
            await self.tsx_mlsag_ecdh_info()
            await self.tsx_mlsag_out_pk()
            await self.full_message_hasher.rctsig_base_done()
            self.out_idx = -1

    async def tsx_mlsag_ecdh_info(self):
        """
        Sets ecdh info for the incremental hashing mlsag.
        :return:
        """
        if self.num_dests() != len(self.output_ecdh):
            raise ValueError('Invalid number of ecdh')

        for ecdh in self.output_ecdh:
            await self.full_message_hasher.set_ecdh(ecdh)

    async def tsx_mlsag_out_pk(self):
        """
        Sets out_pk for the incremental hashing mlsag.
        :return:
        """
        if self.num_dests() != len(self.output_pk):
            raise ValueError('Invalid number of ecdh')

        for out in self.output_pk:
            await self.full_message_hasher.set_out_pk(out)

    async def tsx_gen_rv(self):
        """
        Generates initial RctSig
        :return:
        """
        return self.init_rct_sig()

    async def tsx_mlsag_rangeproof(self, range_proof):
        """
        Sets previously computed range proof, offloaded to host. Used for incremental hashing for mlsag struct.
        :param range_proof: (range proof, range proof hmac)
        :return:
        """
        self.state.set_range_proof()
        self.out_idx += 1

        if self.inp_idx + 1 != self.num_inputs():
            raise ValueError('Invalid ins')
        if self.out_idx + 1 > self.num_dests():
            raise ValueError('Invalid outs')

        rsig, hmac_rsig = range_proof

        kwriter = common.get_keccak_writer()
        ar = xmrserialize.Archive(kwriter, True)
        await ar.message(rsig)

        hmac_key_rsig = self.hmac_key_txout_asig(self.out_idx)
        hmac_rsig_comp = common.compute_hmac(hmac_key_rsig, kwriter.get_digest())
        if not common.ct_equal(hmac_rsig, hmac_rsig_comp):
            raise ValueError('HMAC invalid for rsig')

        await self.full_message_hasher.rsig_val(rsig, bulletproof=self.use_bulletproof)

        # Next state transition
        if self.out_idx + 1 == self.num_dests():
            self.full_message = await self.full_message_hasher.get_digest()
            del self.full_message_hasher

            self.state.set_final_message_done()
            self.inp_idx = -1

    async def tsx_mlsag_done(self):
        """
        MLSAG message computed
        :return:
        """
        return self.full_message

    async def sign_input(self, src_entr, vini, hmac_vini, pseudo_out, alpha):
        """
        Generates a signature for one input
        :param src_entr: Source entry
        :type src_entr: xmrtypes.TxSourceEntry
        :param vini: tx.vin[i] for the transaction. Contains key image, offsets, amount (usually zero)
        :param hmac_vini: HMAC for the tx.vin[i] as returned from Trezor
        :param pseudo_out: pedersen commitment for the current input, uses alpha as the mask.
        Only in memory offloaded scenario. Tuple containing HMAC, as returned from the Trezor.
        :param alpha: alpha mask for the current input. Only in memory offloaded scenario,
        tuple as returned from the Trezor
        :return: Generated signature MGs[i]
        """
        self.state.set_signature()
        self.inp_idx += 1
        if self.inp_idx >= self.num_inputs():
            raise ValueError('Invalid ins')
        if not self.in_memory() and alpha is None:
            raise ValueError('Inconsistent')
        if not self.in_memory() and pseudo_out[0] is None:
            raise ValueError('Inconsistent')
        if self.inp_idx >= 1 and not self.use_simple_rct:
            raise ValueError('Inconsistent')

        inv_idx = self.source_permutation[self.inp_idx]

        # Check HMAC of all inputs
        hmac_vini_comp = await self.gen_hmac_vini(src_entr, vini, inv_idx)
        if not common.ct_equal(hmac_vini_comp, hmac_vini):
            raise ValueError('HMAC is not correct')

        if not self.in_memory():
            pseudo_out_hmac = common.compute_hmac(self.hmac_key_txin_comm(inv_idx), pseudo_out[0])
            if not common.ct_equal(pseudo_out_hmac, pseudo_out[1]):
                raise ValueError('HMAC is not correct')

            alpha_c = aesgcm.decrypt(self.enc_key_txin_alpha(inv_idx), alpha[0], alpha[1], alpha[2])
            alpha_c = crypto.decodeint(alpha_c)
            pseudo_out_c = crypto.decodepoint(pseudo_out[0])

        elif self.use_simple_rct:
            alpha_c = self.input_alphas[self.inp_idx]
            pseudo_out_c = crypto.decodepoint(self.input_pseudo_outs[self.inp_idx])

        # Basic setup, sanity check
        index = src_entr.real_output
        in_sk = xmrtypes.CtKey(dest=self.input_secrets[self.inp_idx], mask=crypto.decodeint(src_entr.mask))
        kLRki = None
        # TODO: kLRki

        # Private key correctness test
        self.assrt(crypto.point_eq(crypto.decodepoint(src_entr.outputs[src_entr.real_output][1].dest),
                                   crypto.scalarmult_base(in_sk.dest)))
        self.assrt(crypto.point_eq(crypto.decodepoint(src_entr.outputs[src_entr.real_output][1].mask),
                                   crypto.gen_c(in_sk.mask, src_entr.amount)))

        # RCT signature
        mg = None
        if self.use_simple_rct:
            # Simple RingCT
            mix_ring = []
            for idx2, out in enumerate(src_entr.outputs):
                mix_ring.append(out[1])

            mg = mlsag2.prove_rct_mg_simple(self.full_message, mix_ring,
                                            in_sk, alpha_c, pseudo_out_c, kLRki, None, index)

            if __debug__:
                self.assrt(mlsag2.ver_rct_mg_simple(self.full_message, mg, mix_ring, pseudo_out_c))

        else:
            # Full RingCt, only one input
            txn_fee_key = crypto.scalarmult_h(self.get_fee())
            n_total_outs = len(src_entr.outputs)
            mix_ring = [None] * n_total_outs
            for idx in range(n_total_outs):
                mix_ring[idx] = [src_entr.outputs[idx][1]]

            mg = mlsag2.prove_rct_mg(self.full_message, mix_ring,
                                     [in_sk], self.output_sk, self.output_pk, kLRki, None, index, txn_fee_key)

            if __debug__:
                self.assrt(mlsag2.ver_rct_mg(mg, mix_ring, self.output_pk, txn_fee_key, self.full_message))

        # Encode
        mgs = monero.recode_msg([mg])
        return mgs[0]

