#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from monero_serialize import xmrserialize, xmrtypes
from monero_glue.hwtoken import misc as tmisc
from monero_glue.agent import agent_misc
from monero_glue.protocol.base import TError
from monero_glue.xmr import monero, common, key_image
from monero_glue.xmr.enc import chacha_poly
from monero_glue.old import trezor
from monero_glue.messages import MoneroRespError, MoneroTsxSign, \
    MoneroTsxInit, MoneroTsxInitResp, \
    MoneroTsxSetInput, MoneroTsxSetInputResp, \
    MoneroTsxInputsPermutation, MoneroTsxInputVini, MoneroTsxSetOutput, MoneroTsxSetOutputResp, \
    MoneroTsxAllOutSet, MoneroTsxAllOutSetResp, \
    MoneroTsxMlsagDone, MoneroTsxMlsagDoneResp, \
    MoneroTsxSignInput, MoneroTsxSignInputResp, \
    MoneroTsxFinal, MoneroTsxFinalResp, \
    MoneroKeyImageSync, \
    MoneroKeyImageSyncStep, MoneroKeyImageSyncFinal


class TData(object):
    """
    Agent transaction-scoped data
    """
    def __init__(self):
        self.tsx_data = None  # type: monero.TsxData
        self.tx = xmrtypes.Transaction(version=2, vin=[], vout=[], extra=[])
        self.tx_in_hmacs = []
        self.tx_out_entr_hmacs = []
        self.tx_out_hmacs = []
        self.tx_out_rsigs = []
        self.tx_out_pk = []
        self.tx_out_ecdh = []
        self.source_permutation = []
        self.alphas = []
        self.pseudo_outs = []
        self.couts = []
        self.tx_prefix_hash = None
        self.enc_salt1 = None
        self.enc_salt2 = None
        self.enc_keys = None  # encrypted tx keys


class Agent(object):
    """
    Glue agent, running on host
    """
    def __init__(self, trezor, address_n=None, network_type=None, **kwargs):
        self.trezor = trezor
        self.ct = None  # type: TData
        self.address_n = address_n
        self.network_type = network_type

    def is_simple(self, rv):
        """
        True if simpe
        :param rv:
        :return:
        """
        return rv.type in [xmrtypes.RctType.Simple, xmrtypes.RctType.SimpleBulletproof]

    def is_bulletproof(self, rv):
        """
        True if bulletproof
        :param rv:
        :return:
        """
        return rv.type in [xmrtypes.RctType.FullBulletproof, xmrtypes.RctType.SimpleBulletproof]

    def is_error(self, response):
        """
        True if trezor returned an error
        :param response:
        :return:
        """
        return isinstance(response, TError) or isinstance(response, MoneroRespError)

    def handle_error(self, response):
        """
        Raises an error if Trezor returned an error.
        :param response:
        :return:
        """
        if not self.is_error(response):
            return
        raise agent_misc.TrezorReturnedError(response)

    async def sign_unsigned_tx(self, unsig):
        """
        Processes unsigned transaction set, returns serialized signed transactions.
        :param unsig:
        :return:
        """
        txes = []
        for tx in unsig.txes:
            await self.sign_transaction_data(tx)
            txes.append(await self.serialized_tx())

        return txes

    async def sign_tx(self, construction_data):
        """
        Transfers transaction, serializes response

        :param construction_data:
        :return:
        """
        if not isinstance(construction_data, list):
            construction_data = [construction_data]

        txes = []
        for tdata in construction_data:
            await self.sign_transaction_data(tdata)
            txes.append(await self.serialized_tx())

        return txes

    async def serialized_tx(self):
        """
        Returns the last signed transaction as blob
        :return:
        """
        return await self.serialize_tx(self.ct.tx)

    async def serialize_tx(self, tx):
        """
        Serializes transaction
        :param tx:
        :return:
        """
        writer = xmrserialize.MemoryReaderWriter()
        ar1 = xmrserialize.Archive(writer, True)
        await ar1.message(tx, msg_type=xmrtypes.Transaction)
        return bytes(writer.buffer)

    async def sign_transaction_data(self, tx, multisig=False, exp_tx_prefix_hash=None, use_tx_keys=None):
        """
        Uses Trezor to sign the transaction
        :param tx:
        :type tx: xmrtypes.TxConstructionData
        :param multisig:
        :param exp_tx_prefix_hash:
        :param use_tx_keys:
        :return:
        """
        self.ct = TData()

        payment_id = []
        extras = await monero.parse_extra_fields(tx.extra)
        extra_nonce = monero.find_tx_extra_field_by_type(extras, xmrtypes.TxExtraNonce)
        if extra_nonce and monero.has_encrypted_payment_id(extra_nonce.nonce):
            payment_id = monero.get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce)

        # Init transaction
        tsx_data = trezor.TsxData()
        tsx_data.version = 1
        tsx_data.payment_id = payment_id
        tsx_data.unlock_time = tx.unlock_time
        tsx_data.outputs = tx.splitted_dsts
        tsx_data.change_dts = tx.change_dts
        tsx_data.num_inputs = len(tx.sources)
        tsx_data.mixin = len(tx.sources[0].outputs)
        tsx_data.fee = sum([x.amount for x in tx.sources]) - sum([x.amount for x in tx.splitted_dsts])
        tsx_data.account = tx.subaddr_account
        tsx_data.minor_indices = tx.subaddr_indices
        tsx_data.is_multisig = multisig
        tsx_data.exp_tx_prefix_hash = common.defval(exp_tx_prefix_hash, b'')
        tsx_data.use_tx_keys = common.defval(use_tx_keys, [])
        self.ct.tx.unlock_time = tx.unlock_time

        self.ct.tsx_data = tsx_data
        tsx_data_pb = await tmisc.translate_tsx_data_pb(tsx_data)
        init_msg = MoneroTsxInit(version=0, address_n=self.address_n, network_type=self.network_type, tsx_data=tsx_data_pb)

        t_res = await self.trezor.tsx_sign(MoneroTsxSign(init=init_msg))  # type: MoneroTsxInitResp
        self.handle_error(t_res)

        in_memory = t_res.in_memory
        self.ct.tx_out_entr_hmacs = t_res.hmacs

        # Set transaction inputs
        for idx, src in enumerate(tx.sources):
            src_bin = await tmisc.dump_msg(src)
            msg = MoneroTsxSetInput(src_entr=src_bin)

            t_res = await self.trezor.tsx_sign(MoneroTsxSign(set_input=msg))  # type: MoneroTsxSetInputResp
            self.handle_error(t_res)

            vini = await tmisc.parse_msg(t_res.vini, xmrtypes.TxinToKey())
            self.ct.tx.vin.append(vini)
            self.ct.tx_in_hmacs.append(t_res.vini_hmac)
            self.ct.pseudo_outs.append((t_res.pseudo_out, t_res.pseudo_out_hmac))
            self.ct.alphas.append(t_res.alpha_enc)

        # Sort key image
        self.ct.source_permutation = list(range(len(tx.sources)))
        self.ct.source_permutation.sort(key=lambda x: self.ct.tx.vin[x].k_image, reverse=True)

        def swapper(x, y):
            self.ct.tx.vin[x], self.ct.tx.vin[y] = self.ct.tx.vin[y], self.ct.tx.vin[x]
            self.ct.tx_in_hmacs[x], self.ct.tx_in_hmacs[y] = self.ct.tx_in_hmacs[y], self.ct.tx_in_hmacs[x]
            self.ct.pseudo_outs[x], self.ct.pseudo_outs[y] = self.ct.pseudo_outs[y], self.ct.pseudo_outs[x]
            self.ct.alphas[x], self.ct.alphas[y] = self.ct.alphas[y], self.ct.alphas[x]
            tx.sources[x], tx.sources[y] = tx.sources[y], tx.sources[x]

        common.apply_permutation(self.ct.source_permutation, swapper)

        if not in_memory:
            msg = MoneroTsxInputsPermutation(perm=self.ct.source_permutation)
            t_res = await self.trezor.tsx_sign(MoneroTsxSign(input_permutation=msg))
            self.handle_error(t_res)

        # Set vin_i back - tx prefix hashing
        # Done only if not in-memory.
        if not in_memory:
            for idx in range(len(self.ct.tx.vin)):
                msg = MoneroTsxInputVini(src_entr=await tmisc.dump_msg(tx.sources[idx]),
                                         vini=await tmisc.dump_msg(self.ct.tx.vin[idx]),
                                         vini_hmac=self.ct.tx_in_hmacs[idx],
                                         pseudo_out=self.ct.pseudo_outs[idx][0] if not in_memory else None,
                                         pseudo_out_hmac=self.ct.pseudo_outs[idx][1] if not in_memory else None, )
                t_res = await self.trezor.tsx_sign(MoneroTsxSign(input_vini=msg))
                self.handle_error(t_res)

        # Set transaction outputs
        for idx, dst in enumerate(tx.splitted_dsts):
            msg = MoneroTsxSetOutput(dst_entr=await tmisc.dump_msg(dst),
                                     dst_entr_hmac=self.ct.tx_out_entr_hmacs[idx])
            t_res = await self.trezor.tsx_sign(MoneroTsxSign(set_output=msg))  # type: MoneroTsxSetOutputResp
            self.handle_error(t_res)

            self.ct.tx.vout.append(await tmisc.parse_msg(t_res.tx_out, xmrtypes.TxOut()))
            self.ct.tx_out_hmacs.append(t_res.vouti_hmac)
            self.ct.tx_out_rsigs.append(await tmisc.parse_msg(t_res.rsig, xmrtypes.RangeSig()))
            self.ct.tx_out_pk.append(await tmisc.parse_msg(t_res.out_pk, xmrtypes.CtKey()))
            self.ct.tx_out_ecdh.append(await tmisc.parse_msg(t_res.ecdh_info, xmrtypes.EcdhTuple()))

        t_res = await self.trezor.tsx_sign(MoneroTsxSign(all_out_set=MoneroTsxAllOutSet()))  # type: MoneroTsxAllOutSetResp
        self.handle_error(t_res)

        rv = xmrtypes.RctSig()
        rv.p = xmrtypes.RctSigPrunable()
        rv.txnFee = t_res.rv.txn_fee
        rv.message = t_res.rv.message
        rv.type = t_res.rv.rv_type
        self.ct.tx.extra = list(bytearray(t_res.extra))

        # Verify transaction prefix hash correctness, tx hash in one pass
        self.ct.tx_prefix_hash = await monero.get_transaction_prefix_hash(self.ct.tx)
        if not common.ct_equal(t_res.tx_prefix_hash, self.ct.tx_prefix_hash):
            raise ValueError('Transaction prefix has does not match')

        # RctSig
        if self.is_simple(rv):
            if self.is_bulletproof(rv):
                rv.p.pseudoOuts = [x[0] for x in self.ct.pseudo_outs]
            else:
                rv.pseudoOuts = [x[0] for x in self.ct.pseudo_outs]

        # Range proof
        rv.p.rangeSigs = []
        rv.outPk = []
        rv.ecdhInfo = []
        for idx in range(len(self.ct.tx_out_rsigs)):
            rv.p.rangeSigs.append(self.ct.tx_out_rsigs[idx])
            rv.outPk.append(self.ct.tx_out_pk[idx])
            rv.ecdhInfo.append(self.ct.tx_out_ecdh[idx])

        # MLSAG message check
        t_res = await self.trezor.tsx_sign(MoneroTsxSign(mlsag_done=MoneroTsxMlsagDone()))  # type: MoneroTsxMlsagDoneResp
        self.handle_error(t_res)

        mlsag_hash = t_res.full_message_hash
        mlsag_hash_computed = await monero.get_pre_mlsag_hash(rv)
        if not common.ct_equal(mlsag_hash, mlsag_hash_computed):
            raise ValueError('Pre MLSAG hash has does not match')

        # Sign each input
        couts = []
        rv.p.MGs = []
        for idx, src in enumerate(tx.sources):
            msg = MoneroTsxSignInput(await tmisc.dump_msg(src),
                                     await tmisc.dump_msg(self.ct.tx.vin[idx]),
                                     self.ct.tx_in_hmacs[idx],
                                     self.ct.pseudo_outs[idx][0] if not in_memory else None,
                                     self.ct.pseudo_outs[idx][1] if not in_memory else None,
                                     self.ct.alphas[idx])
            t_res = await self.trezor.tsx_sign(MoneroTsxSign(sign_input=msg))  # type: MoneroTsxSignInputResp
            self.handle_error(t_res)

            mg = await tmisc.parse_msg(t_res.signature, xmrtypes.MgSig())
            rv.p.MGs.append(mg)
            couts.append(t_res.cout)

        self.ct.tx.signatures = []
        self.ct.tx.rct_signatures = rv

        t_res = await self.trezor.tsx_sign(MoneroTsxSign(final_msg=MoneroTsxFinal()))  # type: MoneroTsxFinalResp
        self.handle_error(t_res)

        if multisig:
            cout_key = t_res.cout_key
            for ccout in couts:
                self.ct.couts.append(chacha_poly.decrypt(cout_key, ccout[0], ccout[1], ccout[2]))

        self.ct.enc_salt1, self.ct.enc_salt2 = t_res.salt, t_res.rand_mult
        self.ct.enc_keys = t_res.tx_enc_keys
        return self.ct.tx

    def last_transaction_data(self):
        """
        Returns last transaction data
        :return:
        """
        return self.ct

    async def import_outputs(self, outputs):
        """
        Key images sync. Required for hot wallet be able to construct transactions.
        If the signed transaction is not relayed with the hot wallet it gets out of sync with
        key images. Thus importing is needed.

        Wallet2::import_outputs()

        :param outputs:
        :return:
        """
        ki_export_init = await key_image.generate_commitment(outputs)
        t_res = await self.trezor.key_image_sync(MoneroKeyImageSync(init=ki_export_init))
        self.handle_error(t_res)

        sub_res = []
        iter = await key_image.yield_key_image_data(outputs)
        batches = common.chunk(iter, 10)
        for rr in batches:  # type: list[key_image.MoneroTransferDetails]
            t_res = await self.trezor.key_image_sync(MoneroKeyImageSync(step=MoneroKeyImageSyncStep(tdis=rr)))
            self.handle_error(t_res)

            sub_res += t_res.kis

        t_res = await self.trezor.key_image_sync(MoneroKeyImageSync(final_msg=MoneroKeyImageSyncFinal()))
        self.handle_error(t_res)

        # Decrypting phase
        enc_key = bytes(t_res.enc_key)
        final_res = []
        for sub in sub_res:  # type: key_image.MoneroExportedKeyImage
            plain = chacha_poly.decrypt(enc_key, bytes(sub.iv), bytes(sub.blob), bytes(sub.tag))
            ki_bin = plain[:32]

            # ki = crypto.decodepoint(ki_bin)
            # sig = [crypto.decodeint(plain[32:64]), crypto.decodeint(plain[64:])]

            final_res.append((ki_bin, (plain[32:64], plain[64:])))

        return final_res

