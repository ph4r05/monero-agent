#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

import binascii
import struct

from monero_glue.misc import b58_mnr
from monero_glue.xmr import common, crypto, mlsag2, ring_ct
from monero_serialize import protobuf as xproto
from monero_serialize import xmrserialize, xmrtypes
from .sub.addr import *
from .sub.creds import *
from .sub.keccak_hasher import *
from .sub.mlsag_hasher import *
from .sub.recode import *
from .sub.recode_ext import *
from .sub.tsx_helper import *
from .sub.xmr_net import *


DISPLAY_DECIMAL_POINT = 12


class XmrNoSuchAddressException(common.XmrException):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TxScanInfo(object):
    """
    struct tx_scan_info_t
    """

    __slots__ = [
        "in_ephemeral",
        "ki",
        "mask",
        "amount",
        "money_transfered",
        "error",
        "received",
    ]


def get_subaddress_secret_key(secret_key, index=None, major=None, minor=None):
    """
    Builds subaddress secret key from the subaddress index
    Hs(SubAddr || a || index_major || index_minor)

    :param secret_key:
    :param index:
    :param major:
    :param minor:
    :return:
    """
    if index:
        major = index.major
        minor = index.minor

    if major == 0 and minor == 0:
        return secret_key

    return crypto.get_subaddress_secret_key(secret_key, major, minor)


def get_subaddress_spend_public_key(view_private, spend_public, major, minor):
    """
    Generates subaddress spend public key D_{major, minor}
    :param view_private:
    :param spend_public:
    :param major:
    :param minor:
    :return:
    """
    if major == 0 and minor == 0:
        return spend_public

    m = get_subaddress_secret_key(view_private, major=major, minor=minor)
    M = crypto.scalarmult_base(m)
    D = crypto.point_add(spend_public, M)
    return D


def generate_key_derivation(pub_key, priv_key):
    """
    Generates derivation priv_key * pub_key.
    Simple ECDH.
    :param pub_key:
    :param priv_key:
    :return:
    """
    return crypto.generate_key_derivation(pub_key, priv_key)


def derive_subaddress_public_key(out_key, derivation, output_index):
    """
    out_key - H_s(derivation || varint(output_index))G
    :param out_key:
    :param derivation:
    :param output_index:
    :return:
    """
    crypto.check_ed25519point(out_key)
    scalar = crypto.derivation_to_scalar(derivation, output_index)
    point2 = crypto.scalarmult_base(scalar)
    point4 = crypto.point_sub(out_key, point2)
    return point4


def generate_key_image(public_key, secret_key):
    """
    Key image: secret_key * H_p(pub_key)
    :param public_key: encoded point
    :param secret_key:
    :return:
    """
    point = crypto.hash_to_ec(public_key)
    point2 = crypto.scalarmult(point, secret_key)
    return point2


def is_out_to_acc_precomp(
    subaddresses, out_key, derivation, additional_derivations, output_index
):
    """
    Searches subaddresses for the computed subaddress_spendkey.
    If found, returns (major, minor), derivation.

    :param subaddresses:
    :param out_key:
    :param derivation:
    :param additional_derivations:
    :param output_index:
    :return:
    """
    subaddress_spendkey = crypto.encodepoint(
        derive_subaddress_public_key(out_key, derivation, output_index)
    )
    if subaddress_spendkey in subaddresses:
        return subaddresses[subaddress_spendkey], derivation

    if additional_derivations and len(additional_derivations) > 0:
        if output_index >= len(additional_derivations):
            raise ValueError("Wrong number of additional derivations")

        subaddress_spendkey = derive_subaddress_public_key(
            out_key, additional_derivations[output_index], output_index
        )
        subaddress_spendkey = crypto.encodepoint(subaddress_spendkey)
        if subaddress_spendkey in subaddresses:
            return (
                subaddresses[subaddress_spendkey],
                additional_derivations[output_index],
            )

    return None


def generate_key_image_helper_precomp(
    ack, out_key, recv_derivation, real_output_index, received_index
):
    """
    Generates UTXO spending key and key image.

    :param ack: sender credentials
    :type ack: AccountCreds
    :param out_key: real output (from input RCT) destination key
    :param recv_derivation:
    :param real_output_index:
    :param received_index: subaddress index this payment was received to
    :return:
    """
    if ack.spend_key_private == 0:
        raise ValueError("Watch-only wallet not supported")

    # derive secret key with subaddress - step 1: original CN derivation
    scalar_step1 = crypto.derive_secret_key(
        recv_derivation, real_output_index, ack.spend_key_private
    )

    # step 2: add Hs(SubAddr || a || index_major || index_minor)
    subaddr_sk = None
    scalar_step2 = None
    if received_index == (0, 0):
        scalar_step2 = scalar_step1
    else:
        subaddr_sk = get_subaddress_secret_key(
            ack.view_key_private, major=received_index[0], minor=received_index[1]
        )
        scalar_step2 = crypto.sc_add(scalar_step1, subaddr_sk)

    # when not in multisig, we know the full spend secret key, so the output pubkey can be obtained by scalarmultBase
    if len(ack.multisig_keys) == 0:
        pub_ver = crypto.scalarmult_base(scalar_step2)

    else:
        # When in multisig, we only know the partial spend secret key. But we do know the full spend public key,
        # so the output pubkey can be obtained by using the standard CN key derivation.
        pub_ver = crypto.derive_public_key(
            recv_derivation, real_output_index, ack.spend_key_public
        )

        # Add the contribution from the subaddress part
        if received_index != (0, 0):
            subaddr_pk = crypto.scalarmult_base(subaddr_sk)
            pub_ver = crypto.point_add(pub_ver, subaddr_pk)

    if not crypto.point_eq(pub_ver, out_key):
        raise ValueError(
            "key image helper precomp: given output pubkey doesn't match the derived one"
        )

    ki = generate_key_image(crypto.encodepoint(pub_ver), scalar_step2)
    return scalar_step2, ki


def generate_key_image_helper(
    creds,
    subaddresses,
    out_key,
    tx_public_key,
    additional_tx_public_keys,
    real_output_index,
):
    """
    Generates UTXO spending key and key image.
    Supports subaddresses.

    :param creds:
    :param subaddresses:
    :param out_key: real output (from input RCT) destination key
    :param tx_public_key: real output (from input RCT) public key
    :param additional_tx_public_keys:
    :param real_output_index: index of the real output in the RCT
    :return:
    """
    recv_derivation = generate_key_derivation(tx_public_key, creds.view_key_private)

    additional_recv_derivations = []
    for add_pub_key in additional_tx_public_keys:
        additional_recv_derivations.append(
            generate_key_derivation(add_pub_key, creds.view_key_private)
        )

    subaddr_recv_info = is_out_to_acc_precomp(
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
    return xi, ki, recv_derivation


def check_acc_out_precomp(tx_out, subaddresses, derivation, additional_derivations, i):
    """
    wallet2::check_acc_out_precomp
    Detects whether the tx output belongs to the subaddresses. If yes, computes the derivation.
    Returns TxScanInfo

    :param tx_out:
    :param derivation:
    :param additional_derivations:
    :param i:
    :return:
    """
    tx_scan_info = TxScanInfo()
    tx_scan_info.error = True

    if not isinstance(tx_out.target, xmrtypes.TxoutToKey):
        return tx_scan_info

    tx_scan_info.received = is_out_to_acc_precomp(
        subaddresses,
        crypto.decodepoint(tx_out.target.key),
        derivation,
        additional_derivations,
        i,
    )
    if tx_scan_info.received:
        tx_scan_info.money_transfered = tx_out.amount
    else:
        tx_scan_info.money_transfered = 0
    tx_scan_info.error = False
    return tx_scan_info


def scan_output(creds, tx, i, tx_scan_info, tx_money_got_in_outs, outs, multisig):
    """
    Wallet2::scan_output()
    Computes spending key, key image, decodes ECDH info, amount, checks masks.

    :param creds:
    :param tx:
    :param i:
    :param tx_scan_info:
    :param tx_money_got_in_outs:
    :param outs:
    :param multisig:
    :return:
    """
    if multisig:
        tx_scan_info.in_ephemeral = 0
        tx_scan_info.ki = crypto.identity()

    else:
        out_dec = crypto.decodepoint(tx.vout[i].target.key)
        res = generate_key_image_helper_precomp(
            creds, out_dec, tx_scan_info.received[1], i, tx_scan_info.received[0]
        )
        tx_scan_info.in_ephemeral, tx_scan_info.ki = res
        if not tx_scan_info.ki:
            raise ValueError("Key error generation failed")

    outs.append(i)
    if tx_scan_info.money_transfered == 0:
        res2 = ecdh_decode_rv(tx.rct_signatures, tx_scan_info.received[1], i)
        tx_scan_info.money_transfered, tx_scan_info.mask = res2
        tx_scan_info.money_transfered = crypto.sc_get64(tx_scan_info.money_transfered)

    tx_money_got_in_outs[tx_scan_info.received[0]] += tx_scan_info.money_transfered
    tx_scan_info.amount = tx_scan_info.money_transfered
    return tx_scan_info


def ecdh_decode_rv(rv, derivation, i):
    """
    Decodes ECDH info from transaction.

    :param rv:
    :param derivation:
    :param i:
    :return:
    """
    scalar = crypto.derivation_to_scalar(derivation, i)
    if rv.type in [xmrtypes.RctType.Simple, xmrtypes.RctType.SimpleBulletproof]:
        return ecdh_decode_simple(rv, scalar, i)

    elif rv.type in [xmrtypes.RctType.Full, xmrtypes.RctType.FullBulletproof]:
        return ecdh_decode_simple(rv, scalar, i)

    else:
        raise ValueError("Unknown rv type")


def ecdh_decode_simple(rv, sk, i):
    """
    Decodes ECDH from the transaction, checks mask (decoding validity).

    :param rv:
    :param sk:
    :param i:
    :return:
    """
    if i >= len(rv.ecdhInfo):
        raise ValueError("Bad index")
    if len(rv.outPk) != len(rv.ecdhInfo):
        raise ValueError("outPk vs ecdhInfo mismatch")

    ecdh_info = rv.ecdhInfo[i]
    ecdh_info = recode_ecdh(ecdh_info, False)
    ecdh_info = ring_ct.ecdh_decode(ecdh_info, derivation=crypto.encodeint(sk))
    c_tmp = crypto.add_keys2(ecdh_info.mask, ecdh_info.amount, crypto.gen_H())
    if not crypto.point_eq(c_tmp, crypto.decodepoint(rv.outPk[i].mask)):
        raise ValueError("Amount decoded incorrectly")

    return ecdh_info.amount, ecdh_info.mask


async def get_transaction_prefix_hash(tx):
    """
    Computes transaction prefix in one step
    :param tx:
    :return:
    """
    writer = get_keccak_writer()
    ar1 = xmrserialize.Archive(writer, True)
    await ar1.message(tx, msg_type=xmrtypes.TransactionPrefixExtraBlob)
    return writer.get_digest()


def expand_transaction(tx):
    """
    Expands transaction - recomputes fields not serialized.
    Recomputes only II, does not have access to the blockchain to get public keys for inputs
    for mix ring reconstruction.

    :param tx:
    :return:
    """
    rv = tx.rct_signatures
    if rv.type in [xmrtypes.RctType.Full, xmrtypes.RctType.FullBulletproof]:
        rv.p.MGs[0].II = [None] * len(tx.vin)
        for n in range(len(tx.vin)):
            rv.p.MGs[0].II[n] = tx.vin[n].k_image

    elif rv.type in [xmrtypes.RctType.Simple, xmrtypes.RctType.SimpleBulletproof]:
        if len(rv.p.MGs) != len(tx.vin):
            raise ValueError("Bad MGs size")
        for n in range(len(tx.vin)):
            rv.p.MGs[n].II = [tx.vin[n].k_image]

    else:
        raise ValueError("Unsupported rct tx type %s" % rv.type)

    return tx


def compute_subaddresses(creds, account, indices, subaddresses=None):
    """
    Computes subaddress public spend key for receiving transactions.

    :param creds: credentials
    :param account: major index
    :param indices: array of minor indices
    :param subaddresses: subaddress dict. optional.
    :return:
    """
    if subaddresses is None:
        subaddresses = {}

    for idx in indices:
        if account == 0 and idx == 0:
            subaddresses[crypto.encodepoint(creds.spend_key_public)] = (0, 0)
            continue

        pub = get_subaddress_spend_public_key(
            creds.view_key_private, creds.spend_key_public, major=account, minor=idx
        )
        pub = crypto.encodepoint(pub)
        subaddresses[pub] = (account, idx)
    return subaddresses


async def get_tx_pub_key_from_received_outs(td):
    """
    Extracts tx pub key from extras.
    Handles previous bug in Monero.

    :param td:
    :type td: xmrtypes.TransferDetails
    :return:
    """
    extras = await parse_extra_fields(list(td.m_tx.extra))
    tx_pub = find_tx_extra_field_by_type(extras, xmrtypes.TxExtraPubKey, 0)

    # Due to a previous bug, there might be more than one tx pubkey in extra, one being
    # the result of a previously discarded signature.
    # For speed, since scanning for outputs is a slow process, we check whether extra
    # contains more than one pubkey. If not, the first one is returned. If yes, they're
    # checked for whether they yield at least one output
    second_pub = find_tx_extra_field_by_type(extras, xmrtypes.TxExtraPubKey, 1)
    if second_pub is None:
        return tx_pub.pub_key

    # Workaround: resend all your funds to the wallet in a different transaction.
    # Proper handling would require derivation -> need trezor roundtrips.
    raise ValueError("Input transaction is buggy, contains two tx keys")


def generate_keys(recovery_key):
    """
    Wallet gen.
    :param recovery_key:
    :return:
    """
    sec = crypto.sc_reduce32(recovery_key)
    pub = crypto.scalarmult_base(sec)
    return sec, pub


def generate_monero_keys(seed):
    """
    Generates spend key / view key from the seed in the same manner as Monero code does.

    account.cpp:
    crypto::secret_key account_base::generate(const crypto::secret_key& recovery_key, bool recover, bool two_random).
    :param seed:
    :return:
    """
    spend_sec, spend_pub = generate_keys(crypto.decodeint(seed))
    hash = crypto.cn_fast_hash(crypto.encodeint(spend_sec))
    view_sec, view_pub = generate_keys(crypto.decodeint(hash))
    return spend_sec, spend_pub, view_sec, view_pub


def generate_sub_address_keys(view_sec, spend_pub, major, minor):
    """
    Computes generic public sub-address
    :param view_sec:
    :param spend_pub:
    :param major:
    :param minor:
    :return: spend public, view public
    """
    if major == 0 and minor == 0:  # special case, Monero-defined
        return spend_pub, crypto.scalarmult_base(view_sec)

    m = get_subaddress_secret_key(view_sec, major=major, minor=minor)
    M = crypto.scalarmult_base(m)
    D = crypto.point_add(spend_pub, M)
    C = crypto.scalarmult(D, view_sec)
    return D, C
