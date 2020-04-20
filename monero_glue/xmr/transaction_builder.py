#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: https://github.com/monero-project/mininero
# Author: Dusan Klinec, ph4r05, 2020

import logging
import binascii
import io
import logging
import os
import random
import re
import sys
import time
from typing import List, Optional

from monero_serialize.core.readwriter import MemoryReaderWriter

from monero_glue.compat import gc
from monero_glue.compat.utils import memcpy
from monero_glue.xmr import bulletproof, crypto, mlsag2, monero
from monero_serialize import xmrtypes, xmrserialize

from monero_glue.hwtoken import misc
from monero_glue.xmr import crypto, monero, wallet, common
from monero_glue.xmr.monero import (
    XmrNoSuchAddressException,
    generate_key_image_helper_precomp,
)
from monero_glue.xmr.sub import addr
from monero_glue.xmr.sub.creds import AccountCreds
from monero_serialize.helpers import ArchiveException
from monero_serialize.xmrtypes import (
    AccountPublicAddress,
    TxDestinationEntry,
    TxExtraAdditionalPubKeys,
    TxExtraNonce,
    TxExtraPubKey,
    OutputEntry,
    CtKey,
    TxSourceEntry,
    ECPublicKey,
    TransferDetails,
    TransactionPrefix,
    TxinToKey,
    TxOut,
    TxoutToKey,
    TxExtraField,
    TxExtraFields,
    UnsignedTxSet,
    TxConstructionData,
    RCTConfig,
    MultisigKLRki,
    SubaddressIndex,
)

from monero_glue.xmr.sub.xmr_net import NetworkTypes

logger = logging.getLogger(__name__)


def generate_key_image_ex(
    creds,
    subaddresses,
    out_key,
    tx_public_key,
    additional_tx_public_keys,
    real_output_index,
):
    recv_derivation = crypto.generate_key_derivation(
        tx_public_key, creds.view_key_private
    )

    additional_recv_derivations = []
    for add_pub_key in additional_tx_public_keys:
        additional_recv_derivations.append(
            crypto.generate_key_derivation(add_pub_key, creds.view_key_private)
        )

    subaddr_recv_info = monero.is_out_to_acc_precomp(
        subaddresses,
        out_key,
        recv_derivation,
        additional_recv_derivations,
        real_output_index,
    )
    if subaddr_recv_info is None:
        raise XmrNoSuchAddressException()

    xi, ki = generate_key_image_helper_precomp(
        creds, out_key, subaddr_recv_info[1], real_output_index, subaddr_recv_info[0]
    )
    return xi, ki, recv_derivation, subaddr_recv_info


class DestInfo:
    def __init__(self, creds, major=0, minor=0, payment_id=None):
        self.creds = creds
        self.major = major
        self.minor = minor
        self.payment_id = payment_id


class TransactionBuilder(object):
    def __init__(self):
        self.seed = b"0000"
        self.dest_keys = None  # type: Optional[List[AccountCreds]]
        self.src_keys = None  # type: Optional[AccountCreds]
        self.cur_keys = None  # type: Optional[List[AccountCreds]]
        self.prng = random.Random(self.seed)

        self.ring_size = 11
        self.nettype = NetworkTypes.TESTNET
        self.fee = 1000
        self.account_idx = 0

        self.payment_id = None
        self.transfers = []  # type: List[TransferDetails]
        self.selected_transfers = []  # type: List[int]
        self.sources = []  # type: List[TxSourceEntry]
        self.sources_creds = []  # type: List[AccountCreds]
        self.outputs = []  # type: List[TxDestinationEntry]
        self.outputs_extra = []  # type: List[DestInfo]
        self.change_idx = None
        self.extra = []
        self.unsigned_tx = None

    def random_scalar(self):
        x = self.prng.getrandbits(64 * 8) % crypto.l
        return crypto.decodeint(x.to_bytes(32, 'big'))

    def random_pub(self):
        return crypto.scalarmult_base(self.random_scalar())

    def random_bytes(self, n):
        CHUNK = 32
        left = n % CHUNK
        bchunks = [self.prng.getrandbits(CHUNK * 8).to_bytes(CHUNK, 'big') for _ in range(n//32)]
        rems = self.prng.getrandbits(left * 8).to_bytes(left, 'big') if left > 0 else b""
        return bytearray(b"".join(bchunks) + rems)

    def random_glob_idx(self):
        return self.prng.randint(0, 0xFFFFFF)

    def gen_tx_prefix(self, inputs=2, outputs=2) -> TransactionPrefix:
        pref = TransactionPrefix()
        pref.version = 2
        pref.unlock_time = 0
        pref.vin = []
        pref.vout = []
        pref.extra = []

        for i in range(inputs):
            inp = TxinToKey(
                amount=0,
                key_offsets=[self.random_glob_idx() for _ in range(self.ring_size)],
                k_image=crypto.encodepoint(self.random_pub()),
            )
            pref.vin.append(inp)

        for i in range(outputs):
            out = TxOut(
                amount=0,
                target=TxoutToKey(key=crypto.encodepoint(self.random_pub()))
            )
            pref.vout.append(out)
        return pref

    async def dump_extra_fields(self, extras):
        writer = xmrserialize.MemoryReaderWriter(preallocate=None)
        ar = xmrserialize.Archive(writer, True)
        await ar.container(extras, container_type=TxExtraFields)
        return writer.get_buffer()

    async def gen_input(self, value=1, sub_major=None, sub_minor=0, additionals=False):
        creds = self.src_keys
        r = self.random_scalar()
        R = crypto.scalarmult_base(r)
        additional_keys = []
        Additional = None
        sub_major = sub_major if sub_major is not None else self.account_idx
        is_sub = sub_major != 0 or sub_minor != 0

        if sub_major != self.account_idx:
            logger.warning("Generating input with different major subindex, cannot be spent in the resulting "
                           "transaction")

        kssec = monero.get_subaddress_secret_key(creds.view_key_private, major=sub_major, minor=sub_minor)
        kssub = crypto.sc_add(kssec, creds.spend_key_private) if is_sub else creds.spend_key_private
        kvsub = crypto.sc_mul(creds.view_key_private, kssub) if is_sub else creds.view_key_private
        KSSUB, KVSUB = monero.generate_sub_address_keys(
            creds.view_key_private,
            creds.spend_key_public,
            sub_major,
            sub_minor)

        if not crypto.point_eq(KSSUB, crypto.scalarmult_base(kssub)):
            raise ValueError("Invariant error")

        oidx = self.prng.randint(0, 12)
        additionals_cnt = self.prng.randint(oidx + 1, 2 * oidx + 1)
        deriv = crypto.generate_key_derivation(KVSUB, r)
        kout = crypto.derive_secret_key(deriv, oidx, kssub)
        KOUT = crypto.derive_public_key(deriv, oidx, KSSUB)
        if not crypto.point_eq(KOUT, crypto.scalarmult_base(kout)):
            raise ValueError("Invariant error")

        if additionals:
            if is_sub:
                Additional = crypto.scalarmult(KSSUB, r)
            else:
                Additional = crypto.scalarmult_base(r)
        else:
            if is_sub:
                R = crypto.scalarmult(KSSUB, r)

        amnt = crypto.sc_init(value)
        msk = self.random_scalar()  # commitment mask
        C = crypto.add_keys2(msk, amnt, crypto.xmr_H())

        ring = []
        for i in range(self.ring_size - 1):
            tk = CtKey(
                dest=crypto.encodepoint(self.random_pub()),
                mask=crypto.encodepoint(self.random_pub()),
            )
            ring.append(tk)

        index = self.prng.randint(0, len(ring))
        ring.insert(index, CtKey(dest=crypto.encodepoint(KOUT), mask=crypto.encodepoint(C)))
        if additionals:
            additional_keys = [self.random_pub() for _ in range(additionals_cnt)]
            additional_keys[oidx] = Additional

        src = TxSourceEntry()
        src.outputs = [(self.random_glob_idx(), x) for x in ring]
        src.real_output = index
        src.real_out_tx_key = crypto.encodepoint(R)
        src.real_out_additional_tx_keys = [crypto.encodepoint(x) for x in additional_keys]
        src.real_output_in_tx_index = oidx
        src.amount = value
        src.rct = True
        src.mask = crypto.encodeint(msk)
        src.multisig_kLRki = MultisigKLRki(K=crypto.ZERO, L=crypto.ZERO, R=crypto.ZERO, ki=crypto.ZERO)

        td = TransferDetails()
        td.m_internal_output_index = oidx
        td.m_global_output_index = src.outputs[index][0]
        td.m_mask = src.mask
        td.m_amount = value
        td.m_subaddr_index = SubaddressIndex(major=sub_major, minor=sub_minor)
        td.m_rct = True
        td.m_txid = self.random_bytes(32)
        td.m_block_height = self.prng.randint(0, 0xFFFF)
        td.m_spent = False
        td.m_spent_height = 0
        td.m_key_image_known = True
        td.m_key_image_requested = False
        td.m_key_image_partial = False
        td.m_multisig_k = []
        td.m_multisig_info = []
        td.m_uses = []
        td.m_pk_index = 0
        td.m_tx = self.gen_tx_prefix(self.prng.randint(1, 10), additionals_cnt)
        td.m_tx.vout[oidx].target.key = crypto.encodepoint(KOUT)

        extras = []
        extras.append(TxExtraNonce(nonce=self.random_bytes(8)))
        extras.append(TxExtraPubKey(pub_key=src.real_out_tx_key))
        if src.real_out_additional_tx_keys:
            extras.append(TxExtraAdditionalPubKeys(data=src.real_out_additional_tx_keys))
        td.m_tx.extra = await self.dump_extra_fields(extras)

        tmpsubs = {}
        monero.compute_subaddresses(creds, sub_major, [sub_minor], tmpsubs)
        xi, ki, rderiv = self.check_input(src, creds, tmpsubs)
        if not crypto.sc_eq(xi, kout):
            raise ValueError("Invariant error")

        td.m_key_image = crypto.encodepoint(ki)

        self.sources.append(src)
        self.selected_transfers.append(len(self.transfers))
        self.transfers.append(td)
        self.sources_creds.append(creds)

        if not crypto.point_eq(
                crypto.decodepoint(src.outputs[src.real_output][1].dest),
                crypto.scalarmult_base(kout)):
            raise ValueError("Invariant error")

        return self

    async def gen_output(self, value=1, dest=None, sub_major=0, sub_minor=0, payment_id=None):
        dest = dest if dest is not None else (self.prng.choice(self.dest_keys) if isinstance(self.dest_keys, list) else self.dest_keys)
        is_sub = sub_major != 0 or sub_minor != 0
        if is_sub and payment_id is not None:
            raise ValueError("Integrated cannot be subaddress")

        KS, KV = monero.generate_sub_address_keys(dest.view_key_private, dest.spend_key_public, sub_major, sub_minor)
        pubaddr = AccountPublicAddress(
                m_spend_public_key=crypto.encodepoint(KS),
                m_view_public_key=crypto.encodepoint(KV),
        )

        pub2 = addr.PubAddress(
            pubaddr.m_spend_public_key,
            pubaddr.m_view_public_key,
        )

        tde = TxDestinationEntry(
            amount=value,
            addr=pubaddr,
            is_subaddress=is_sub,
            original=addr.public_addr_encode(pub2, is_sub, self.nettype, payment_id),
            is_integrated=payment_id is not None,
        )

        tdextra = DestInfo(dest, sub_major, sub_minor, payment_id)
        self.outputs.append(tde)
        self.outputs_extra.append(tdextra)
        return self

    async def gen_change(self, value=None):
        inc_total = sum(x.amount for x in self.sources)
        out_total = sum(x.amount for x in self.outputs)
        to_change = value if value is not None else (inc_total - out_total - self.fee)
        if to_change < 0:
            raise ValueError("Change is negative")

        await self.gen_output(to_change, self.src_keys, self.account_idx, 0)
        self.change_idx = len(self.outputs) - 1
        return self
    
    async def shuffle_outputs(self):
        tmparr = zip(self.outputs, self.outputs_extra, range(len(self.outputs)))
        self.prng.shuffle(tmparr)
        self.outputs = [x[0] for x in tmparr]
        self.outputs_extra = [x[1] for x in tmparr]
        self.change_idx = [i for i, x in enumerate(tmparr) if x[2] == self.change_idx][0]

    async def set_payment_id(self, payment_id):
        self.payment_id = payment_id
        extras = [
            TxExtraNonce(nonce=self.payment_id),
        ]
        self.extra = await self.dump_extra_fields(extras)

    async def analyze_input(self, keys, subs, inp):
        subs = subs if subs else {}
        real_out_key = inp.outputs[inp.real_output][1]
        out_key = crypto.decodepoint(real_out_key.dest)
        tx_key = crypto.decodepoint(inp.real_out_tx_key)
        additional_keys = [
            crypto.decodepoint(x) for x in inp.real_out_additional_tx_keys
        ]

        res = generate_key_image_ex(
            keys, subs, out_key, tx_key, additional_keys, inp.real_output_in_tx_index
        )

        xi, ki, recv_derivation, subaddr_recv_info = res
        sub_idx = subaddr_recv_info[0]
        return sub_idx

    async def reformat_out(self, out):
        res = misc.StdObj(
            amount=out.amount,
            addr=addr.build_address(
                out.addr.m_spend_public_key, out.addr.m_view_public_key
            ),
            is_subaddress=out.is_subaddress,
        )
        return res

    async def reformat_outs(self, dsts):
        out_txs2 = []
        for o in dsts:
            out_txs2.append(await self.reformat_out(o))
        return out_txs2

    async def build(self):
        sset = UnsignedTxSet(txes=[], transfers=self.transfers)

        dests = list(self.outputs)
        if self.change_idx is not None:
            dests.pop(self.change_idx)

        tdata = TxConstructionData(
            sources=self.sources,
            change_dts=self.outputs[self.change_idx] if self.change_idx is not None else None,
            splitted_dsts=self.outputs,
            selected_transfers=self.selected_transfers,
            extra=self.extra,
            unlock_time=0,
            use_rct=True,
            use_bulletproofs=True,
            rct_config=RCTConfig(range_proof_type=4, bp_version=2),
            dests=dests,
            subaddr_account=self.account_idx,
            subaddr_indices=list(set(x.m_subaddr_index.major for x in self.transfers)),
        )

        sset.txes.append(tdata)
        self.unsigned_tx = sset
        return sset

    async def serialize_unsigned(self):
        return await misc.dump_msg(self.unsigned_tx)

    async def describe(self, unsigned_txs, keys, key_subs=None):
        inp = unsigned_txs.txes[0].sources
        if key_subs is None:
            key_subs = {}
            for tx in enumerate(unsigned_txs.txes):
                monero.compute_subaddresses(keys, tx.subaddr_account, list(tx.subaddr_indices), key_subs)

        print("\nInp: %s, #txs: %s, #transfers: %s" % (inp, len(unsigned_txs.txes), len(unsigned_txs.transfers)))
        for txid, tx in enumerate(unsigned_txs.txes):
            srcs = tx.sources
            dsts = tx.splitted_dsts
            extra = tx.extra
            change = tx.change_dts
            account = tx.subaddr_account
            subs = tx.subaddr_indices
            mixin = len(srcs[0].outputs) - 1
            amnt_in = sum([x.amount for x in srcs])
            amnt_out = sum([x.amount for x in dsts])
            fee = amnt_in - amnt_out
            n_inp_additional = sum(
                [1 for x in srcs if len(x.real_out_additional_tx_keys) > 0]
            )

            change_addr = (
                addr.build_address(
                    change.addr.m_spend_public_key, change.addr.m_view_public_key
                )
                if change
                else None
            )
            out_txs2 = await self.reformat_outs(dsts)

            num_stdaddresses, num_subaddresses, single_dest_subaddress = addr.classify_subaddresses(
                out_txs2, change_addr
            )

            print(
                "  tx: %s, #inp: %2d, #inp_add: %2d, #out: %2d, mixin: %2d, acc: %s, subs: %s, "
                "xmr_in: %10.6f, xmr_out: %10.6f, fee: %10.6f, change: %10.6f, out_clean: %10.6f"
                % (
                    txid,
                    len(srcs),
                    n_inp_additional,
                    len(dsts),
                    mixin,
                    account,
                    subs,
                    wallet.conv_disp_amount(amnt_in),
                    wallet.conv_disp_amount(amnt_out),
                    wallet.conv_disp_amount(fee),
                    wallet.conv_disp_amount(change.amount) if change else 0,
                    wallet.conv_disp_amount(
                        (amnt_out - change.amount) if change else amnt_out
                    ),
                )
            )
            print(
                "  Out: num_std: %2d, num_sub: %2d, single_dest_sub: %s, total: %s"
                % (
                    num_stdaddresses,
                    num_subaddresses,
                    1 if single_dest_subaddress else 0,
                    len(dsts),
                )
            )

            accounts = set()
            subs = set()
            for inp in srcs:
                res = await self.analyze_input(keys, key_subs, inp)
                accounts.add(res[0])
                if res != (0, 0):
                    subs.add(res)

            print("  Ins: accounts: %s, subs: %s" % (accounts, len(subs)))

            extras = await monero.parse_extra_fields(extra)
            extras_val = []
            for c in extras:
                if isinstance(c, TxExtraPubKey):
                    extras_val.append("TxKey")
                elif isinstance(c, TxExtraNonce):
                    extras_val.append(
                        "Nonce: %s" % binascii.hexlify(c.nonce).decode("ascii")
                    )
                elif isinstance(c, TxExtraAdditionalPubKeys):
                    extras_val.append("AdditionalTxKeys: %s" % len(c.data))
                else:
                    extras_val.append(str(c))
            print("  Extras: %s" % ", ".join(extras_val))

            # Final verification
            for idx, inp in enumerate(tx.sources):
                self.check_input(inp, keys, key_subs)
                if not crypto.point_eq(
                        crypto.decodepoint(inp.outputs[inp.real_output][1].mask),
                        crypto.gen_c(crypto.decodeint(inp.mask), inp.amount),
                ): raise ValueError("Real source entry's mask does not equal spend key's. Inp: %d" % idx)

    async def primary_change_address(self, key: AccountCreds, account: int):
        D, C = monero.generate_sub_address_keys(
            key.view_key_private,
            crypto.scalarmult_base(key.spend_key_private),
            account,
            0,
        )
        return AccountPublicAddress(
            view_public_key=crypto.encodepoint(C),
            spend_public_key=crypto.encodepoint(D),
        )

    async def find_change_idx(self, tx, change_idx=None):
        if change_idx is not None:
            return change_idx

        out_txs2 = await self.reformat_outs(tx.splitted_dsts)
        change_dts = await self.reformat_out(tx.change_dts) if tx.change_dts else None
        change_idx = addr.get_change_addr_idx(out_txs2, change_dts)
        return change_idx

    def check_input(self, inp: TxSourceEntry, new_keys, new_subs):
        real_out_key = inp.outputs[inp.real_output][1]
        tx_key = crypto.decodepoint(inp.real_out_tx_key)
        additional_keys = [
            crypto.decodepoint(x) for x in inp.real_out_additional_tx_keys
        ]

        return monero.generate_key_image_helper(
            new_keys,
            new_subs,
            crypto.decodepoint(real_out_key.dest),
            tx_key,
            additional_keys,
            inp.real_output_in_tx_index,
        )

    def precompute_subaddr(self, keys, subs, major_cnt=10, minor_cnt=200):
        if keys is None:
            return None
        for i in range(major_cnt):
            monero.compute_subaddresses(keys, i, list(range(0, minor_cnt)), subs)
