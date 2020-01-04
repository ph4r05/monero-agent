import argparse
import asyncio
import binascii
import io
import logging
import os
import random
import re
import sys
import time

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
    CtKey, TxSourceEntry)

import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.DEBUG, use_chroot=False)


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


class TestGen(object):
    def __init__(self):
        self.args = None
        self.dest_keys = None  # type: AccountCreds
        self.cur_keys = None  # type: AccountCreds
        self.cur_subs = {}
        self.dest_subs = {}

        self.add_additionals = False
        self.dest_sub_major = 0

    async def process(self, idx, inp):
        is_stdin = False
        if inp == b"-":
            file = getattr(sys.stdin, "buffer", sys.stdin)
            is_stdin = True
        else:
            file = open(inp, "rb")

        try:
            logger.debug("Processing: %s" % inp)
            data = file.read()
            unsigned_tx = await wallet.load_unsigned_tx(
                self.cur_keys.view_key_private, data
            )

            if self.args.desc:
                await self.describe(inp, unsigned_tx, self.cur_keys, self.cur_subs)

            if self.dest_keys is None:
                return

            new_unsigned = await self.rekey_unsigned(unsigned_tx)

            new_bin = await wallet.dump_unsigned_tx(
                self.dest_keys.view_key_private, new_unsigned
            )

            if self.args.output:
                nbase = "output.bin" if is_stdin else os.path.basename(inp)
                nbase_fname, nbase_ext = os.path.splitext(nbase)
                if self.args.suffix:
                    nbase_fname += self.args.suffix

                nbase = nbase_fname + nbase_ext
                ndest = os.path.join(self.args.output, nbase)

                if self.args.desc:
                    await self.describe(
                        ndest, new_unsigned, self.dest_keys, self.dest_subs
                    )

                with open(ndest, "wb") as fh:
                    fh.write(new_bin)
                logger.info("Result written to: %s" % ndest)

            else:
                sys.stdout.buffer.write(new_bin)

        except ArchiveException as ae:
            logger.error(ae)
            logger.error(ae.tracker)

        finally:
            if not is_stdin:
                file.close()

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

    async def describe(self, inp, unsigned_txs, keys, key_subs):
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

    async def primary_change_address(self, key, account):
        D, C = monero.generate_sub_address_keys(
            key.view_key_private,
            crypto.scalarmult_base(key.spend_key_private),
            account,
            0,
        )
        return misc.StdObj(
            view_public_key=crypto.encodepoint(C),
            spend_public_key=crypto.encodepoint(D),
        )

    async def adjust_change(self, tx):
        logger.debug("Change addr adjust")
        out_txs2 = await self.reformat_outs(tx.splitted_dsts)
        change_dts = await self.reformat_out(tx.change_dts) if tx.change_dts else None
        change_idx = addr.get_change_addr_idx(out_txs2, change_dts)

        if change_idx is None:
            logger.warning('Change address not found in outputs, dts: %s' % (change_dts, ))
            for ii in out_txs2:
                logger.warning('Out: %s' % ii)

            # Find addr that matches and adapt value in change dst
            for idx, ii in enumerate(out_txs2):
                if addr.addr_eq(change_dts.addr, ii.addr):
                    logger.info('Found surrogate change addr: [%s] %s' % (idx, ii))
                    change_dts.amount = ii.amount
                    change_idx = idx
                    break

        if self.args.outs_subs:
            for ix, o in enumerate(tx.splitted_dsts):
                if change_idx is None or ix != change_idx:
                    o.is_subaddress = True

        if change_idx is None:
            logger.warning('Could not fix change addr')
            return

        change_addr = await self.primary_change_address(
            self.dest_keys, self.dest_sub_major
        )
        tx.change_dts.amount = change_dts.amount
        tx.change_dts.addr.m_spend_public_key = change_addr.spend_public_key
        tx.change_dts.addr.m_view_public_key = change_addr.view_public_key
        logger.debug("Change addr adjust @idx: %s, spend key: %s"
                     % (change_idx, binascii.hexlify(change_addr.spend_public_key)))

        tx.splitted_dsts[
            change_idx
        ].addr.m_spend_public_key = change_addr.spend_public_key
        tx.splitted_dsts[
            change_idx
        ].addr.m_view_public_key = change_addr.view_public_key

        return change_idx

    async def amplify_inputs(self, tx, new_keys=None, new_subs=None):
        lst = tx.sources[-1]
        orig_amount = lst.amount
        partial = orig_amount // (self.args.inputs + 1)

        amnt_sum = partial
        lst.amount = partial
        commitment = crypto.encodepoint(crypto.gen_c(crypto.decodeint(lst.mask), partial))
        lst.outputs[lst.real_output][1].mask = commitment

        for i in range(1, self.args.inputs + 1):
            is_lst = i >= self.args.inputs
            new_amnt = orig_amount - amnt_sum if is_lst else partial
            amnt_sum += partial

            commitment = crypto.encodepoint(crypto.gen_c(crypto.decodeint(lst.mask), new_amnt))
            new_inp = TxSourceEntry(outputs=list(lst.outputs),
                                    real_output=lst.real_output,
                                    real_out_tx_key=lst.real_out_tx_key,
                                    real_out_additional_tx_keys=lst.real_out_additional_tx_keys,
                                    real_output_in_tx_index=lst.real_output_in_tx_index,
                                    amount=new_amnt,
                                    rct=lst.rct,
                                    mask=lst.mask,
                                    multisig_kLRki=lst.multisig_kLRki)

            # Amount changed -> update the commitment
            orig_key = new_inp.outputs[new_inp.real_output][1]
            new_inp.outputs[new_inp.real_output] = (0, CtKey(dest=orig_key.dest, mask=commitment))

            # Randomize mixin values
            for i in range(new_inp.real_output + 1, len(new_inp.outputs)):
                new_inp.outputs[i] = (0, CtKey(
                    mask=crypto.encodepoint(self.random_pub()),
                    dest=crypto.encodepoint(self.random_pub())))

                if new_inp.real_out_additional_tx_keys:
                    new_inp.real_out_additional_tx_keys[i] = crypto.encodepoint(self.random_pub())

            self.check_input(new_inp, new_keys, new_subs)

            if not crypto.point_eq(
                    crypto.decodepoint(new_inp.outputs[new_inp.real_output][1].mask),
                    crypto.gen_c(crypto.decodeint(new_inp.mask), new_inp.amount),
                ): raise ValueError("Real source entry's mask does not equal spend key's")

            tx.sources.append(new_inp)

    async def find_change_idx(self, tx, change_idx=None):
        if change_idx is not None:
            return change_idx

        out_txs2 = await self.reformat_outs(tx.splitted_dsts)
        change_dts = await self.reformat_out(tx.change_dts) if tx.change_dts else None
        change_idx = addr.get_change_addr_idx(out_txs2, change_dts)
        return change_idx

    async def shuffle_outs(self, tx, change_idx=None):
        change_idx = await self.find_change_idx(tx, change_idx)
        permutation = list(range(len(tx.splitted_dsts)))
        random.shuffle(permutation)

        def swapper(x, y):
            tx.splitted_dsts[x], tx.splitted_dsts[y] = tx.splitted_dsts[y], tx.splitted_dsts[x]

        common.apply_permutation(permutation, swapper)
        new_change = permutation.index(change_idx) if change_idx is not None else None
        logger.debug('Outputs shuffled, change tsx idx: %d' % new_change)
        return new_change

    async def reduce_outs(self, tx, change_idx=None):
        tgtn = self.args.outs
        if tgtn >= len(tx.splitted_dsts):
            return change_idx

        change_idx = await self.find_change_idx(tx, change_idx)

        # change first, if some
        if change_idx is not None:
            chg = tx.splitted_dsts[change_idx]
            del tx.splitted_dsts[change_idx]
            tx.splitted_dsts.insert(0, chg)

        # amount adjust
        leftover = sum([x.amount for x in tx.splitted_dsts[tgtn:]])
        tx.splitted_dsts[tgtn-1].amount += leftover
        tx.splitted_dsts = tx.splitted_dsts[:tgtn]

        if tgtn == 1 and tx.change_dts:
            tx.change_dts.amount = tx.splitted_dsts[0].amount

        return await self.shuffle_outs(tx, change_idx)

    async def amplify_outs(self, tx, change_idx=None):
        if self.args.outs <= len(tx.splitted_dsts):
            return change_idx

        change_idx = await self.find_change_idx(tx, change_idx)
        lstidx = len(tx.splitted_dsts) - 1
        lst = tx.splitted_dsts[lstidx]
        orig_amount = lst.amount
        toadd = self.args.outs - len(tx.splitted_dsts)
        partial = orig_amount // (toadd + 1)
        amnt_sum = partial
        lst.amount = partial

        for i in range(toadd):
            is_lst = i >= toadd - 1
            new_amnt = orig_amount - amnt_sum if is_lst else partial
            amnt_sum += partial
            naddr = AccountPublicAddress(
                m_spend_public_key=bytes(lst.addr.m_spend_public_key),
                m_view_public_key=bytes(lst.addr.m_view_public_key),
            )
            new_tx = TxDestinationEntry(
                amount=new_amnt, is_subaddress=lst.is_subaddress, addr=naddr
            )
            tx.splitted_dsts.append(new_tx)

        if tx.change_dts and change_idx is not None and change_idx == lstidx:
            tx.change_dts.amount = tx.splitted_dsts[0].amount

        return await self.shuffle_outs(tx, change_idx)

    async def subadress_outs(self, tx, change_idx=None):
        change_idx = await self.find_change_idx(tx, change_idx)

        for ix, ox in enumerate(tx.splitted_dsts):
            if change_idx is not None and ix == change_idx:
                continue
            # if ox.is_subaddress:
            #     continue

            spkey = bytes(ox.addr.m_spend_public_key)
            orig_keys = self.dest_keys
            orig_idx = self.dest_sub_major, 0

            if spkey in self.cur_subs:
                orig_keys = self.cur_keys
                orig_idx = self.cur_subs[spkey]
                logger.debug('Out %d, in cur subs, idx: %s' % (ix, orig_idx))

            elif spkey in self.dest_subs:
                orig_idx = self.dest_subs[spkey]
                logger.debug('Out %d, in dst subs, idx: %s' % (ix, orig_idx))

            naddr = monero.generate_sub_address_keys(orig_keys.view_key_private, orig_keys.spend_key_public,
                                                     orig_idx[0], ix+1)

            ox.addr.m_spend_public_key = crypto.encodepoint(naddr[0])
            ox.addr.m_view_public_key = crypto.encodepoint(naddr[1])
            ox.is_subaddress = True

        return change_idx

    async def add_nonce(self, tx):
        # TX_EXTRA_NONCE = 2 | extralen+1 | TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID = 1 | nonce
        c_extra = [2, 8+1, 1] + list(binascii.unhexlify(self.args.add_nonce))
        if len(c_extra) != 3+8:
            raise ValueError("Invalid length")
        tx.extra = tx.extra + c_extra if tx.extra else c_extra

    async def add_long_nonce(self, tx):
        # TX_EXTRA_NONCE = 2 | extralen+1 | TX_EXTRA_NONCE_PAYMENT_ID = 0 | nonce
        c_extra = [2, 32+1, 0] + list(binascii.unhexlify(self.args.add_long_nonce))
        if len(c_extra) != 3+32:
            raise ValueError("Invalid length")
        tx.extra = tx.extra + c_extra if tx.extra else c_extra

    async def rekey_unsigned(self, unsigned_txs):
        for tx in unsigned_txs.txes:
            tx.use_bulletproofs = False
            logger.debug(
                "Transaction with %s inputs, %s outputs, %s mix ring"
                % (len(tx.sources), len(tx.splitted_dsts), len(tx.sources[0].outputs))
            )

            if self.args.inputs:
                await self.amplify_inputs(tx, self.dest_keys, self.dest_subs)

            for inp in tx.sources:
                self.rekey_input(
                    inp, self.cur_keys, self.cur_subs, self.dest_keys, self.dest_subs, self.args.mixin
                )

            change_idx = None
            if tx.change_dts and (tx.subaddr_account != self.dest_sub_major) \
                    or (self.dest_keys != self.cur_keys) or self.args.outs_subs:
                change_idx = await self.adjust_change(tx)

            tx.subaddr_account = self.dest_sub_major
            tx.subaddr_indices = self.args.minors

            if self.args.outs is not None:
                change_idx = await self.reduce_outs(tx, change_idx)
                change_idx = await self.amplify_outs(tx, change_idx)

            if self.args.outs_subs:
                change_idx = await self.subadress_outs(tx, change_idx)

            if self.args.add_nonce is not None:
                await self.add_nonce(tx)

            if self.args.add_long_nonce is not None:
                await self.add_long_nonce(tx)

        return unsigned_txs

    def rekey_input(self, inp, keys, subs=None, new_keys=None, new_subs=None, mixin_change=None):
        subs = subs if subs else {}
        real_out_key = inp.outputs[inp.real_output][1]
        out_key = crypto.decodepoint(real_out_key.dest)
        tx_key = crypto.decodepoint(inp.real_out_tx_key)
        additional_keys = [
            crypto.decodepoint(x) for x in inp.real_out_additional_tx_keys
        ]

        logger.debug("Current out key: %s" % binascii.hexlify(real_out_key.dest))
        secs = monero.generate_key_image_helper(
            keys, subs, out_key, tx_key, additional_keys, inp.real_output_in_tx_index
        )
        xi, ki, di = secs

        need_additional = additional_keys is not None and len(additional_keys) > 0
        is_dst_sub = self.dest_sub_major != 0 and (
            self.args.minors[0] != 0 or len(self.args.minors) > 1
        )
        logger.debug(
            "Is dst sub: %s, need additional: %s" % (is_dst_sub, need_additional)
        )

        if is_dst_sub and self.add_additionals:
            need_additional = True

        if is_dst_sub:
            rand_minor = random.choice(self.args.minors)
            m = monero.get_subaddress_secret_key(
                new_keys.view_key_private, major=self.dest_sub_major, minor=rand_minor
            )
            M = crypto.scalarmult_base(m)
            d = crypto.sc_add(m, new_keys.spend_key_private)
            D = crypto.point_add(new_keys.spend_key_public, M)
            C = crypto.scalarmult(D, new_keys.view_key_private)

        if not need_additional and not is_dst_sub:
            # real_out_key.dst = Hs(R*new_a || idx)G + newB
            r = crypto.random_scalar()
            tx_key = crypto.scalarmult_base(r)
            new_deriv = crypto.generate_key_derivation(new_keys.view_key_public, r)
            new_out_pr = crypto.derive_secret_key(
                new_deriv, inp.real_output_in_tx_index, new_keys.spend_key_private
            )
            new_out = crypto.scalarmult_base(new_out_pr)
            real_out_key.dest = crypto.encodepoint(new_out)

        elif not need_additional and is_dst_sub:
            # real_out_key.dst = Hs(r*C || idx)G + newB, R=rD
            r = crypto.random_scalar()
            tx_key = crypto.scalarmult(D, r)
            new_deriv = crypto.generate_key_derivation(C, r)
            new_out_pr = crypto.derive_secret_key(
                new_deriv, inp.real_output_in_tx_index, d
            )
            new_out = crypto.scalarmult_base(new_out_pr)
            real_out_key.dest = crypto.encodepoint(new_out)

        else:
            r = crypto.random_scalar()
            tx_key = crypto.scalarmult_base(r)

            gen_additionals = min(2, inp.real_output_in_tx_index + 1)
            if additional_keys is None or len(additional_keys) < gen_additionals:
                additional_keys = [
                    crypto.scalarmult_base(crypto.random_scalar())
                    for _ in range(gen_additionals)
                ]

            ri = crypto.random_scalar()
            if is_dst_sub:
                add_tx = crypto.scalarmult(D, ri)
                new_deriv = crypto.generate_key_derivation(C, ri)
                new_out_pr = crypto.derive_secret_key(
                    new_deriv, inp.real_output_in_tx_index, d
                )
                new_out = crypto.scalarmult_base(new_out_pr)
                if not crypto.point_eq(
                    new_out,
                    crypto.derive_public_key(new_deriv, inp.real_output_in_tx_index, D),
                ):
                    raise ValueError("Invalid txout computation")

            else:
                add_tx = crypto.scalarmult_base(ri)
                new_deriv = crypto.generate_key_derivation(new_keys.view_key_public, r)
                new_out_pr = crypto.derive_secret_key(
                    new_deriv, inp.real_output_in_tx_index, new_keys.spend_key_private
                )
                new_out = crypto.scalarmult_base(new_out_pr)

            additional_keys[inp.real_output_in_tx_index] = add_tx
            real_out_key.dest = crypto.encodepoint(new_out)

        # Increasing the size of the mixin
        if mixin_change and len(inp.outputs) < mixin_change:
            for i in range(mixin_change - len(inp.outputs)):
                inp.outputs.append((0, CtKey(
                    mask=crypto.encodepoint(self.random_pub()),
                    dest=crypto.encodepoint(self.random_pub()))))
                if additional_keys:
                    additional_keys.append(self.random_pub())

        inp.real_out_tx_key = crypto.encodepoint(tx_key)
        inp.real_out_additional_tx_keys = [
            crypto.encodepoint(x) for x in additional_keys
        ]

        logger.debug("New pub: %s" % binascii.hexlify(real_out_key.dest))

        # Self-check
        self.check_input(inp, new_keys, new_subs)
        return inp

    def check_input(self, inp, new_keys, new_subs):
        real_out_key = inp.outputs[inp.real_output][1]
        tx_key = crypto.decodepoint(inp.real_out_tx_key)
        additional_keys = [
            crypto.decodepoint(x) for x in inp.real_out_additional_tx_keys
        ]

        _ = monero.generate_key_image_helper(
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

    def parse_keys(self, keyvar, ktype="current"):
        if keyvar is None:
            return None
        if len(keyvar) != 2 * 2 * 32:
            raise ValueError(
                "Keys for the %s destination length invalid. Format: SpendKey || ViewKey hexcoded"
                % ktype
            )
        keys_bin = binascii.unhexlify(keyvar)
        spend_key = crypto.decodeint(keys_bin[:32])
        view_key = crypto.decodeint(keys_bin[32:64])

        return AccountCreds.new_wallet(view_key, spend_key)

    def random_pub(self):
        return crypto.scalarmult_base(crypto.random_scalar())

    async def work(self):
        self.cur_keys = self.parse_keys(self.args.current)
        self.dest_keys = self.parse_keys(self.args.dest, "destination")
        self.dest_sub_major = self.args.major
        self.add_additionals = self.args.add_extra
        self.precompute_subaddr(self.cur_keys, self.cur_subs)
        self.precompute_subaddr(self.dest_keys, self.dest_subs)

        files = self.args.files if self.args.files and len(self.args.files) else [b"-"]
        for idx, line in enumerate(files):
            await self.process(idx, line)

    async def main(self):
        parser = argparse.ArgumentParser(
            description="Test generator - changing unsigned transactions"
        )
        parser.add_argument(
            "--dest",
            default=None,
            required=False,
            help="Destination address to transform to",
        )

        parser.add_argument(
            "--current", default=None, required=True, help="Current destination address"
        )

        parser.add_argument(
            "--output", default=None, help="Output directory to write results to"
        )

        parser.add_argument(
            "--major", default=0, type=int, help="Destination major address index"
        )

        parser.add_argument(
            "--minors",
            default=[0],
            type=int,
            nargs="*",
            help="Destination minor address index",
        )

        parser.add_argument(
            "--desc",
            dest="desc",
            default=False,
            action="store_const",
            const=True,
            help="Generate test file descriptors",
        )

        parser.add_argument(
            "--suffix", dest="suffix", default="", help="Generated tsx files suffix"
        )

        parser.add_argument(
            "--outs",
            dest="outs",
            default=None,
            type=int,
            help="Change number of transaction outputs",
        )

        parser.add_argument(
            "--outs-subs",
            dest="outs_subs",
            default=False,
            action="store_const",
            const=True,
            help="Make all outputs go to a subaddr.",
        )

        parser.add_argument(
            "--inputs",
            dest="inputs",
            default=None,
            type=int,
            help="Amplify the last input to more inputs - increases tx inputs",
        )

        parser.add_argument(
            "--mixin",
            dest="mixin",
            default=None,
            type=int,
            help="Increases the mixin level to the given value. Does not work for decreasing the mixin",
        )

        parser.add_argument(
            "--add-extra",
            dest="add_extra",
            action="store_const",
            const=True,
            default=False,
            help="Adds additional tx keys",
        )

        parser.add_argument(
            "--add-nonce",
            dest="add_nonce",
            default=None,
            help="Adds encrypted nonce",
        )

        parser.add_argument(
            "--add-long-nonce",
            dest="add_long_nonce",
            default=None,
            help="Adds long nonce",
        )

        parser.add_argument(
            "files",
            metavar="FILE",
            nargs="*",
            help="files to read, if empty, stdin is used",
        )
        self.args = parser.parse_args()
        return await self.work()


async def amain():
    tgen = TestGen()
    res = await tgen.main()
    sys.exit(res)


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain())
    loop.close()


if __name__ == "__main__":
    main()
