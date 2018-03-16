#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii

from monero_serialize import xmrtypes, xmrserialize
from .monero import TsxData, classify_subaddresses, addr_to_hash
from . import monero, crypto, ring_ct, mlsag2
from . import common as common


class WalletCreds(object):
    """
    Stores wallet private keys
    """
    def __init__(self, view_key_private=None, spend_key_private=None, view_key_public=None, spend_key_public=None, address=None):
        self.view_key_private = view_key_private
        self.view_key_public = view_key_public
        self.spend_key_private = spend_key_private
        self.spend_key_public = spend_key_public
        self.address = address

    @classmethod
    def new_wallet(cls, priv_view_key, priv_spend_key):
        pub_view_key = crypto.scalarmult_base(priv_view_key)
        pub_spend_key = crypto.scalarmult_base(priv_spend_key)
        addr = monero.encode_addr(monero.net_version(),
                                  crypto.encodepoint(pub_spend_key),
                                  crypto.encodepoint(pub_view_key))
        return cls(view_key_private=priv_view_key, spend_key_private=priv_spend_key,
                   view_key_public=pub_view_key, spend_key_public=pub_spend_key,
                   address=addr)


class Trezor(object):
    """
    Main Trezor object
    """
    def __init__(self):
        self.tsx_ctr = 0
        self.tsx_obj = None  # type: TTransaction
        self.creds = None  # type: WalletCreds

    async def init_transaction(self, tsx_data: TsxData):
        self.tsx_ctr += 1
        self.tsx_obj = TTransaction(self)
        self.tsx_obj.creds = self.creds
        await self.tsx_obj.init_transaction(tsx_data, self.tsx_ctr)

    async def precompute_subaddr(self, account, indices):
        """
        Precomputes subaddresses for account (major) and list of indices (minors)
        :param account:
        :param indices:
        :return:
        """
        self.tsx_obj.precompute_subaddr(account, indices)

    async def set_tsx_input(self, src_entr):
        """
        :param src_entr
        :type src_entr: xmrtypes.TxSourceEntry
        :return:
        """
        await self.tsx_obj.set_input(src_entr)

    async def tsx_inputs_done(self):
        """
        All inputs set
        :return:
        """
        await self.tsx_obj.tsx_inputs_done()

    async def set_tsx_output1(self, dst_entr):
        """
        :param src_entr
        :type src_entr: xmrtypes.TxDestinationEntry
        :return:
        """
        await self.tsx_obj.set_out1(dst_entr)


class TTransaction(object):
    """
    Transaction builder
    """
    def __init__(self, trezor=None):
        self.trezor = trezor  # type: Trezor
        self.creds = None  # type: WalletCreds
        self.key_master = None
        self.key_hmac = None

        self.r = None  # txkey
        self.r_pub = None

        self.tsx_data = None  # type: monero.TsxData
        self.need_additional_txkeys = False
        self.use_bulletproof = False
        self.use_rct = True
        self.use_simple_rct = False
        self.additional_tx_keys = []
        self.additional_tx_public_keys = []
        self.inp_idx = -1
        self.out_idx = -1
        self.summary_inputs_money = 0
        self.summary_outs_money = 0
        self.input_rcts = []
        self.input_secrets = []
        self.output_secrets = []
        self.subaddresses = {}
        self.tx = xmrtypes.Transaction(vin=[], vout=[], extra=[])
        self.source_permutation = []  # sorted by key images
        self.tx_prefix_hash = None

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
        self.tsx_data = tsx_data
        self.gen_r()

        # Additional keys
        class_res = classify_subaddresses(tsx_data.outputs, tsx_data.change_dts.addr if tsx_data.change_dts else None)
        num_stdaddresses, num_subaddresses, single_dest_subaddress = class_res

        # if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
        if num_stdaddresses == 0 and num_subaddresses == 1:
            self.r_pub = crypto.ge_scalarmult(self.r, crypto.decodepoint(single_dest_subaddress.m_spend_public_key))

        self.need_additional_txkeys = num_subaddresses > 0 and (num_stdaddresses > 0 or num_subaddresses > 1)
        if self.need_additional_txkeys:
            for _ in range(len(tsx_data.outputs)):
                self.additional_tx_keys.append(crypto.random_scalar())

        # Extra processing, payment id
        self.tx.version = 2
        self.tx.unlock_time = tsx_data.unlock_time
        await self.process_payment_id()
        await self.compute_hmac_keys(tsx_ctr)

    async def process_payment_id(self):
        """
        Payment id -> extra
        :return:
        """
        if self.tsx_data.payment_id is None or len(self.tsx_data.payment_id) == 0:
            return

        change_addr = self.tsx_data.change_dts.addr if self.tsx_data.change_dts else None
        view_key_pub_enc = monero.get_destination_view_key_pub(self.tsx_data.outputs, change_addr)
        if view_key_pub_enc == crypto.NULL_KEY_ENC:
            raise ValueError('Destinations have to have exactly one output to support encrypted payment ids')

        view_key_pub = crypto.decodepoint(view_key_pub_enc)
        payment_id_encr = monero.encrypt_payment_id(self.tsx_data.payment_id, view_key_pub, self.r)

        extra_nonce = monero.set_encrypted_payment_id_to_tx_extra_nonce(payment_id_encr)
        self.tx.extra = monero.add_extra_nonce_to_tx_extra([], extra_nonce)

    async def compute_hmac_keys(self, tsx_ctr):
        """
        Generate master key H(TsxData || r || c_tsx)
        :return:
        """
        writer = common.get_keccak_writer()
        ar1 = xmrserialize.Archive(writer, True)
        await ar1.message(self.tsx_data)
        await xmrserialize.dump_uvarint(writer, self.r)
        await xmrserialize.dump_uvarint(writer, tsx_ctr)
        self.key_master = writer.get_digest()
        self.key_hmac = common.keccak_hash(b'hmac' + self.key_master)

    def precompute_subaddr(self, account, indices):
        """
        Precomputes subaddresses for account (major) and list of indices (minors)
        Subaddresses have to be stored in encoded form - unique representation.
        Single point can have multiple extended coordinates representation - would not match during subaddress search.
        :param account:
        :param indices:
        :return:
        """
        for idx in indices:
            if account == 0 and idx == 0:
                self.subaddresses[crypto.encodepoint(self.trezor.creds.spend_key_public)] = (0,0)
                continue

            m = monero.get_subaddress_secret_key(self.trezor.creds.view_key_private, major=account, minor=idx)
            pub = crypto.encodepoint(crypto.scalarmult_base(m))
            self.subaddresses[pub] = (account, indices)

    async def set_input(self, src_entr):
        """
        :param src_entr:
        :type src_entr: xmrtypes.TxSourceEntry
        :return:
        """
        self.inp_idx += 1
        if src_entr.real_output >= len(src_entr.outputs):
            raise ValueError('real_output index %s bigger than output_keys.size()' % (src_entr.real_output, len(src_entr.outputs)))
        self.summary_inputs_money += src_entr.amount

        out_key = crypto.decodepoint(src_entr.outputs[src_entr.real_output][1].dest)
        tx_key = crypto.decodepoint(src_entr.real_out_tx_key)
        additional_keys = [crypto.decodepoint(x) for x in src_entr.real_out_additional_tx_keys]

        secs = monero.generate_key_image_helper(self.trezor.creds, self.subaddresses, out_key,
                                                tx_key,
                                                additional_keys,
                                                src_entr.real_output_in_tx_index)
        xi, ki, di = secs
        self.input_secrets.append((xi, ))
        self.input_rcts.append(src_entr.rct)

        # Construct tx.vin
        vini = xmrtypes.TxinToKey(amount=src_entr.amount, k_image=crypto.encodepoint(ki))
        vini.key_offsets = [x[0] for x in src_entr.outputs]
        vini.key_offsets = monero.absolute_output_offsets_to_relative(vini.key_offsets)
        self.tx.vin.append(vini)

        hmac_vini = common.keccak_hash(self.key_hmac + b'txin' + xmrserialize.dump_uvarint_b(self.inp_idx))
        # TODO: HMAC(T_in,i || vin_i)

        return vini

    async def tsx_inputs_done(self):
        """
        All inputs set
        :return:
        """

        # Sort tx.in by key image
        self.source_permutation = list(range(self.inp_idx+1))
        self.source_permutation.sort(key=lambda x: self.tx.vin[x].k_image)

        def swapper(x, y):
            self.tx.vin[x], self.tx.vin[y] = self.tx.vin[y], self.tx.vin[x]
            self.input_secrets[x], self.input_secrets[y] = self.input_secrets[y], self.input_secrets[x]
            self.input_rcts[x], self.input_rcts[y] = self.input_rcts[y], self.input_rcts[x]

        common.apply_permutation(self.source_permutation, swapper)

        # Set public key to the extra
        self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraPubKey)
        monero.add_tx_pub_key_to_extra(self.tx.extra, self.r_pub)

        self.use_simple_rct = self.inp_idx > 0

    async def set_out1(self, dst_entr):
        """
        Set destination entry
        :param src_entr
        :type src_entr: xmrtypes.TxDestinationEntry
        :return:
        """
        self.out_idx += 1
        change_addr = self.tsx_data.change_dts.addr if self.tsx_data.change_dts else None

        if dst_entr.amount <= 0 and self.tx.version <= 1:
            raise ValueError('Destination with wrong amount: %s' % dst_entr.amount)

        additional_txkey = None
        if self.need_additional_txkeys:
            if dst_entr.is_subaddress:
                additional_txkey = crypto.ge_scalarmult(self.additional_tx_keys[self.out_idx],
                                                        crypto.decodepoint(dst_entr.addr.m_spend_public_key))
            else:
                additional_txkey = crypto.ge_scalarmult_base(self.additional_tx_keys[self.out_idx])

        if self.need_additional_txkeys:
            self.additional_tx_public_keys.append(additional_txkey)

        if change_addr and dst_entr.addr == change_addr:
            # sending change to yourself; derivation = a*R
            derivation = monero.generate_key_derivation(self.r_pub, self.creds.view_key_private)

        else:
            # sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
            deriv_priv = self.additional_tx_keys[self.out_idx] if dst_entr.is_subaddress and self.need_additional_txkeys else self.r
            derivation = monero.generate_key_derivation(self.creds.view_key_public, deriv_priv)

        amount_key = crypto.derivation_to_scalar(derivation, self.out_idx)
        tx_out_key = crypto.derive_public_key(derivation, self.out_idx, crypto.decodepoint(dst_entr.addr.m_spend_public_key))
        tk = xmrtypes.TxoutToKey(key=crypto.encodepoint(tx_out_key))
        tx_out = xmrtypes.TxOut(amount=dst_entr.amount, target=tk)
        self.tx.vout.append(tx_out)
        self.summary_outs_money += dst_entr.amount

        self.output_secrets.append((amount_key, ))

        # Last output?
        if self.out_idx + 1 == len(self.tsx_data.outputs):
            await self.all_out1_set()

    async def all_out1_set(self):
        """
        All out1 set phase
        Adds additional public keys to the tx.extra
        :return:
        """
        self.tx.extra = await monero.remove_field_from_tx_extra(self.tx.extra, xmrtypes.TxExtraAdditionalPubKeys)
        if self.need_additional_txkeys:
            await monero.add_additional_tx_pub_keys_to_extra(self.tx.extra, self.additional_tx_public_keys)

        if self.summary_outs_money > self.summary_inputs_money:
            raise ValueError('Transaction inputs money (%s) less than outputs money (%s)'
                             % (self.summary_inputs_money, self.summary_outs_money))

    async def signature(self, tx):
        """
        Computes the signature
        TODO: implement according to the protocol

        :param tx: const data
        :type tx: xmrtypes.TxConstructionData
        :return:
        """
        amount_in = 0
        inamounts = [None] * len(self.source_permutation)
        index = [None] * len(self.source_permutation)
        in_sk = [None] * len(self.source_permutation)  # type: list[xmrtypes.CtKey]

        # TODO: iterative?
        for i in range(len(self.source_permutation)):
            idx = self.source_permutation[i]
            src = tx.sources[idx]
            amount_in += src.amount
            inamounts[i] = src.amount
            index[i] = src.real_output
            in_sk[i] = xmrtypes.CtKey(dest=self.input_secrets[i][0], mask=crypto.decodeint(src.mask))
            # TODO: kLRki

            # private key correctness test
            if __debug__:
                assert crypto.point_eq(crypto.decodepoint(src.outputs[src.real_output][1].dest),
                                       crypto.scalarmult_base(in_sk[i].dest))
                assert crypto.point_eq(crypto.decodepoint(src.outputs[src.real_output][1].mask),
                                       crypto.gen_c(in_sk[i].mask, inamounts[i]))

        # TODO: iterative?
        destinations = []
        outamounts = []
        amount_out = 0
        for idx, dst in enumerate(tx.dests):
            destinations.append(crypto.decodepoint(self.tx.vout[idx].target.key))
            outamounts.append(self.tx.vout[idx].amount)
            amount_out += self.tx.vout[idx].amount

        if self.use_simple_rct:
            mix_ring = [None] * (self.inp_idx + 1)
            for i in range(len(self.source_permutation)):
                src = tx.sources[self.source_permutation[i]]
                mix_ring[i] = []
                for idx2, out in enumerate(src.outputs):
                    mix_ring[i].append(out[1])

        else:
            n_total_outs = len(tx.sources[0].outputs)
            mix_ring = [None] * n_total_outs
            for idx in range(n_total_outs):
                mix_ring[idx] = []
                for i in range(len(self.source_permutation)):
                    src = tx.sources[self.source_permutation[i]]
                    mix_ring[idx].append(src.outputs[idx][1])

        if not self.use_simple_rct and amount_in > amount_out:
            outamounts.append(amount_in - amount_out)

        # Hide amounts
        self.zero_out_amounts()

        # Tx prefix hash
        await self.compute_tx_prefix_hash()

        # Signature
        if self.use_simple_rct:
            rv = await self.gen_rct_simple(in_sk, destinations, inamounts, outamounts, amount_in - amount_out, mix_ring, None, None, index)
        else:
            rv = await self.gen_rct(in_sk, destinations, outamounts, mix_ring, None, None, tx.sources[0].real_output)

        # Recode for serialization
        rv = await self.rct_recode(rv)
        self.tx.signatures = []
        self.tx.rct_signatures = rv
        del rv

        # Serialize response
        writer = xmrserialize.MemoryReaderWriter()
        ar1 = xmrserialize.Archive(writer, True)
        await ar1.message(self.tx, msg_type=xmrtypes.Transaction)

        return writer.buffer

    def zero_out_amounts(self):
        """
        Zero out all amounts to mask rct outputs, real amounts are now encrypted
        :return:
        """
        for idx, inx in enumerate(self.tx.vin):
            if self.input_rcts[idx]:
                inx.amount = 0

        for out in self.tx.vout:
            out.amount = 0

    async def compute_tx_prefix_hash(self):
        """
        Computes tx prefix hash
        :return:
        """
        return await monero.get_transaction_prefix_hash(self.tx)

    async def gen_rct_header(self, destinations, outamounts):
        """
        Initializes RV RctSig structure, processes outputs, computes range proofs, ecdh info masking.
        Common to gen_rct and gen_rct_simple.

        :param destinations:
        :param outamounts:
        :return:
        """
        rv = xmrtypes.RctSig()
        rv.p = xmrtypes.RctSigPrunable()

        rv.message = self.tx_prefix_hash
        rv.outPk = [None] * len(destinations)

        if self.use_bulletproof:
            rv.p.bulletproofs = [None] * len(destinations)
        else:
            rv.p.rangeSigs = [None] * len(destinations)
        rv.ecdhInfo = [None] * len(destinations)

        # Output processing
        sumout = 0
        out_sk = [None] * len(destinations)
        for idx in range(len(destinations)):
            rv.outPk[idx] = xmrtypes.CtKey(dest=crypto.encodepoint(destinations[idx]))
            C, mask, rsig = None, 0, None

            # Rangeproof
            if self.use_bulletproof:
                raise ValueError('Bulletproof not yet supported')

            else:
                C, mask, rsig = ring_ct.prove_range(outamounts[idx])
                rv.p.rangeSigs[idx] = rsig
                if __debug__:
                    assert ring_ct.ver_range(C, rsig)
                    assert crypto.point_eq(C, crypto.point_add(
                        crypto.scalarmult_base(mask),
                        crypto.scalarmult_h(outamounts[idx])))

                # Recoding to structure
                for i in range(len(rsig.Ci)):
                    rsig.Ci[i] = crypto.encodepoint(rsig.Ci[i])
                for i in range(len(rsig.asig.s0)):
                    rsig.asig.s0[i] = crypto.encodepoint(rsig.asig.s0[i])
                for i in range(len(rsig.asig.s1)):
                    rsig.asig.s1[i] = crypto.encodeint(rsig.asig.s1[i])
                rsig.asig.ee = crypto.encodeint(rsig.asig.ee)

            # Mask sum
            rv.outPk[idx].mask = crypto.encodepoint(C)
            sumout = crypto.sc_add(sumout, mask)
            out_sk[idx] = xmrtypes.CtKey(mask=mask)

            # ECDH masking
            amount_key = crypto.encodeint(self.output_secrets[idx][0])
            rv.ecdhInfo[idx] = xmrtypes.EcdhTuple(mask=mask, amount=outamounts[idx])
            rv.ecdhInfo[idx] = ring_ct.ecdh_encode(rv.ecdhInfo[idx], derivation=amount_key)
            rv.ecdhInfo[idx].mask = crypto.encodeint(rv.ecdhInfo[idx].mask)
            rv.ecdhInfo[idx].amount = crypto.encodeint(rv.ecdhInfo[idx].amount)
        return rv, sumout, out_sk

    async def gen_rct(self, in_sk, destinations, amounts, mix_ring, kLRki, msout, index):
        """
        Full ring CT signature.
        Used when there is only one input transaction to spend.

        :param in_sk:
        :param destinations:
        :param amounts:
        :param mix_ring:
        :param kLRki:
        :param msout:
        :param index:
        :param out_sk:
        :return:
        """
        if len(amounts) != len(destinations) and len(amounts) != len(destinations) + 1:
            raise ValueError('Different number of amounts/destinations')
        if len(self.output_secrets) != len(destinations):
            raise ValueError('Different number of amount_keys/destinations')
        if index >= len(mix_ring):
            raise ValueError('Bad index into mix ring')
        for n in range(len(mix_ring)):
            if len(mix_ring[n]) != len(in_sk):
                raise ValueError('Bad mixring size')
        if (not kLRki or not msout) and (kLRki or msout):
            raise ValueError('Only one of kLRki/mscout is present')

        rv, sumout, out_sk = await self.gen_rct_header(destinations, amounts)
        rv.type = xmrtypes.RctType.FullBulletproof if self.use_bulletproof else xmrtypes.RctType.Full

        if len(amounts) > len(destinations):
            rv.txnFee = amounts[len(destinations)]
        else:
            rv.txnFee = 0

        txn_fee_key = crypto.scalarmult_h(rv.txnFee)
        rv.mixRing = mix_ring
        # TODO: msout multisig

        full_message = await monero.get_pre_mlsag_hash(rv)
        rv.p.MGs = [
            mlsag2.prove_rct_mg(full_message,
                                rv.mixRing,
                                in_sk, out_sk, rv.outPk, kLRki, None, index, txn_fee_key)
        ]

        if __debug__:
            assert mlsag2.ver_rct_mg(rv.p.MGs[0], rv.mixRing, rv.outPk, txn_fee_key, full_message)
        return rv

    async def gen_rct_simple(self, in_sk, destinations, inamounts, outamounts, txn_fee, mix_ring, kLRki, msout, index):
        """
        Generate simple RCT signature.

        :param in_sk:
        :param destinations:
        :param inamounts:
        :param outamounts:
        :param txn_fee:
        :param mix_ring:
        :param kLRki:
        :param msout:
        :param index:
        :param out_sk:
        :return:
        """
        if len(inamounts) == 0:
            raise ValueError("Empty inamounts")
        if len(inamounts) != len(in_sk):
            raise ValueError("Different number of inamounts/inSk")
        if len(outamounts) != len(destinations):
            raise ValueError("Different number of amounts/destinations")
        if len(self.output_secrets) != len(destinations):
            raise ValueError("Different number of amount_keys/destinations")
        if len(index) != len(in_sk):
            raise ValueError("Different number of index/inSk")
        if len(mix_ring) != len(in_sk):
            raise ValueError("Different number of mixRing/inSk")
        for idx in range(len(mix_ring)):
            if index[idx] >= len(mix_ring[idx]):
                raise ValueError('Bad index into mixRing')

        rv, sumout, out_sk = await self.gen_rct_header(destinations, outamounts)
        rv.type = xmrtypes.RctType.SimpleBulletproof if self.use_bulletproof else xmrtypes.RctType.Simple
        rv.txnFee = txn_fee
        rv.mixRing = mix_ring

        # Pseudooutputs
        pseudo_outs = [None] * len(inamounts)
        rv.p.MGs = [None] * len(inamounts)
        sumpouts = 0
        a = []
        for idx in range(len(inamounts)-1):
            a.append(crypto.random_scalar())
            sumpouts = crypto.sc_add(sumpouts, a[idx])
            pseudo_outs[idx] = crypto.gen_c(a[idx], inamounts[idx])

        a.append(crypto.sc_sub(sumout, sumpouts))
        pseudo_outs[-1] = crypto.gen_c(a[-1], inamounts[-1])

        if self.use_bulletproof:
            rv.p.pseudoOuts = [crypto.encodepoint(x) for x in pseudo_outs]
        else:
            rv.pseudoOuts = [crypto.encodepoint(x) for x in pseudo_outs]

        full_message = await monero.get_pre_mlsag_hash(rv)

        # TODO: msout multisig
        for i in range(len(inamounts)):
            rv.p.MGs[i] = mlsag2.prove_rct_mg_simple(
                full_message,
                rv.mixRing[i],
                in_sk[i], a[i],
                pseudo_outs[i],
                kLRki[i] if kLRki else None, None, index[i])

            if __debug__:
                assert mlsag2.ver_rct_mg_simple(full_message, rv.p.MGs[i], rv.mixRing[i], pseudo_outs[i])

        return rv

    async def rct_recode(self, rv):
        """
        Recodes RCT MGs signatures from raw forms to bytearrays so it works with serialization
        :param rv:
        :return:
        """
        mgs = rv.p.MGs
        for idx in range(len(mgs)):
            mgs[idx].cc = crypto.encodeint(mgs[idx].cc)

            for i in range(len(mgs[idx].ss)):
                for j in range(len(mgs[idx].ss[i])):
                    mgs[idx].ss[i][j] = crypto.encodeint(mgs[idx].ss[i][j])
        return rv


