#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from monero_serialize import protobuf as xproto
from monero_serialize import xmrtypes, xmrserialize
from monero_glue.xmr import mlsag2, ring_ct, crypto, common
from monero_glue.xmr.core.tsx_helper import *
from monero_glue.misc import b58_mnr
import binascii
import struct


DISPLAY_DECIMAL_POINT = 12


class XmrNoSuchAddressException(common.XmrException):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class NetworkTypes(object):
    MAINNET = 0
    TESTNET = 1
    STAGENET = 2
    FAKECHAIN = 3


class MainNet(object):
    PUBLIC_ADDRESS_BASE58_PREFIX = 18
    PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 19
    PUBLIC_SUBADDRESS_BASE58_PREFIX = 42


class TestNet(object):
    PUBLIC_ADDRESS_BASE58_PREFIX = 53
    PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 54
    PUBLIC_SUBADDRESS_BASE58_PREFIX = 63


class StageNet(object):
    PUBLIC_ADDRESS_BASE58_PREFIX = 24
    PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 25
    PUBLIC_SUBADDRESS_BASE58_PREFIX = 36


class TsxData(xmrserialize.MessageType):
    """
    TsxData, initial input to the transaction processing.
    Serialization structure for easy hashing.
    """
    __slots__ = ['version', 'payment_id', 'unlock_time', 'outputs', 'change_dts', 'num_inputs', 'mixin', 'fee',
                 'account', 'minor_indices', 'is_multisig', 'exp_tx_prefix_hash', 'use_tx_keys']
    FIELDS = [
        ('version', xmrserialize.UVarintType),
        ('payment_id', xmrserialize.BlobType),
        ('unlock_time', xmrserialize.UVarintType),
        ('outputs', xmrserialize.ContainerType, xmrtypes.TxDestinationEntry),
        ('change_dts', xmrtypes.TxDestinationEntry),
        ('num_inputs', xmrserialize.UVarintType),
        ('mixin', xmrserialize.UVarintType),
        ('fee', xmrserialize.UVarintType),
        ('account', xmrserialize.UVarintType),
        ('minor_indices', xmrserialize.ContainerType, xmrserialize.UVarintType),
        ('is_multisig', xmrserialize.BoolType),
        ('exp_tx_prefix_hash', xmrserialize.BlobType),                    # expected prefix hash, bail on error
        ('use_tx_keys', xmrserialize.ContainerType, xmrtypes.SecretKey),  # use this secret key, multisig
    ]

    def __init__(self, payment_id=None, outputs=None, change_dts=None, **kwargs):
        super().__init__(**kwargs)

        self.payment_id = payment_id
        self.change_dts = change_dts
        self.fee = 0
        self.account = 0
        self.minor_indices = [0]
        self.outputs = outputs if outputs else []  # type: list[xmrtypes.TxDestinationEntry]
        self.is_multisig = False
        self.exp_tx_prefix_hash = b''
        self.use_tx_keys = []


class AccountCreds(object):
    """
    Stores account private keys
    """
    def __init__(self, view_key_private=None, spend_key_private=None, view_key_public=None, spend_key_public=None, address=None):
        self.view_key_private = view_key_private
        self.view_key_public = view_key_public
        self.spend_key_private = spend_key_private
        self.spend_key_public = spend_key_public
        self.address = address
        self.multisig_keys = []

    @classmethod
    def new_wallet(cls, priv_view_key, priv_spend_key, network_type=NetworkTypes.MAINNET):
        pub_view_key = crypto.scalarmult_base(priv_view_key)
        pub_spend_key = crypto.scalarmult_base(priv_spend_key)
        addr = encode_addr(net_version(network_type),
                           crypto.encodepoint(pub_spend_key),
                           crypto.encodepoint(pub_view_key))
        return cls(view_key_private=priv_view_key, spend_key_private=priv_spend_key,
                   view_key_public=pub_view_key, spend_key_public=pub_spend_key,
                   address=addr)


class TxScanInfo(object):
    """
    struct tx_scan_info_t
    """
    __slots__ = ['in_ephemeral', 'ki', 'mask', 'amount', 'money_transfered', 'error', 'received']


class KeccakArchive(object):
    def __init__(self):
        self.kwriter = get_keccak_writer()
        self.ar = xmrserialize.Archive(self.kwriter, True)


def get_keccak_writer(sub_writer=None):
    """
    Creates new fresh async Keccak writer
    :param sub_writer:
    :return:
    """
    return xproto.AHashWriter(common.HashWrapper(crypto.get_keccak()), sub_writer=sub_writer)


def net_version(network_type=NetworkTypes.MAINNET, is_subaddr=False):
    """
    Network version bytes used for address construction
    :return:
    """
    c_net = None
    if network_type == NetworkTypes.MAINNET:
        c_net = MainNet
    elif network_type == NetworkTypes.TESTNET:
        c_net = TestNet
    elif network_type == NetworkTypes.STAGENET:
        c_net = StageNet
    else:
        raise ValueError()

    prefix = c_net.PUBLIC_ADDRESS_BASE58_PREFIX if not is_subaddr else c_net.PUBLIC_SUBADDRESS_BASE58_PREFIX
    return bytes([prefix])


def addr_to_hash(addr: xmrtypes.AccountPublicAddress):
    """
    Creates hashable address representation
    :param addr:
    :return:
    """
    return bytes(addr.m_spend_public_key + addr.m_view_public_key)


def encode_addr(version, spend_pub, view_pub):
    """
    Encodes public keys as versions
    :param version:
    :param spendP:
    :param viewP:
    :return:
    """
    buf = version + spend_pub + view_pub
    h = crypto.cn_fast_hash(buf)
    buf = binascii.hexlify(buf + h[0:4])
    return b58_mnr.b58encode(buf)


def decode_addr(addr):
    """
    Given address, get version and public spend and view keys.

    :param addr:
    :return:
    """
    d = b58_mnr.b58decode(data_bin=addr)

    addr_checksum = d[-4:]
    calc_checksum = crypto.cn_fast_hash(d[:-4])[:4]
    if addr_checksum == calc_checksum:
        version = ord(d[:1])
        pub_spend_key = d[1:33]
        pub_view_key = d[33:65]
        return version, pub_spend_key, pub_view_key

    else:
        raise ValueError('Invalid address checksum')


def public_addr_encode(pub_addr, is_sub=False, net=NetworkTypes.MAINNET):
    """
    Encodes public address to Monero address
    :param pub_addr:
    :type pub_addr: xmrtypes.AccountPublicAddress
    :param is_sub:
    :param net:
    :return:
    """
    net_ver = net_version(net, is_sub)
    return encode_addr(net_ver, pub_addr.m_spend_public_key, pub_addr.m_view_public_key)


def classify_subaddresses(tx_dests, change_addr : xmrtypes.AccountPublicAddress):
    """
    Classify destination subaddresses
    void classify_addresses()
    :param tx_dests:
    :type tx_dests: list[xmrtypes.TxDestinationEntry]
    :param change_addr:
    :return:
    """
    num_stdaddresses = 0
    num_subaddresses = 0
    single_dest_subaddress = None
    addr_set = set()
    for tx in tx_dests:
        if change_addr and change_addr == tx.addr:
            continue
        addr_hashed = addr_to_hash(tx.addr)
        if addr_hashed in addr_set:
            continue
        addr_set.add(addr_hashed)
        if tx.is_subaddress:
            num_subaddresses += 1
            single_dest_subaddress = tx.addr
        else:
            num_stdaddresses += 1
    return num_stdaddresses, num_subaddresses, single_dest_subaddress


def get_subaddress_secret_key(secret_key, index=None, major=None, minor=None, little_endian=True):
    """
    Builds subaddress secret key from the subaddress index
    Hs(SubAddr || a || index_major || index_minor)

    UPDATE: Monero team fixed this problem. Always use little endian.
    Note: need to handle endianity in the index
    C-code simply does: memcpy(data + sizeof(prefix) + sizeof(crypto::secret_key), &index, sizeof(subaddress_index));
    Where the index has the following form:

    struct subaddress_index {
        uint32_t major;
        uint32_t minor;
    }

    https://docs.python.org/3/library/struct.html#byte-order-size-and-alignment
    :param secret_key:
    :param index:
    :param major:
    :param minor:
    :param little_endian:
    :return:
    """
    if index:
        major = index.major
        minor = index.minor
    endianity = '<' if little_endian else '>'
    prefix = b'SubAddr'
    buffer = bytearray(len(prefix) + 1 + 32 + 4 + 4)
    struct.pack_into('%s7sb32sLL' % endianity, buffer, 0, prefix, 0, crypto.encodeint(secret_key), major, minor)
    return crypto.hash_to_scalar(buffer)


def get_subaddress_spend_public_key(view_private, spend_public, major, minor):
    """
    Generates subaddress spend public key D_{major, minor}
    :param view_private:
    :param spend_public:
    :param major:
    :param minor:
    :return:
    """
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
    point2 = crypto.ge_scalarmult(secret_key, point)
    return point2


def is_out_to_acc_precomp(subaddresses, out_key, derivation, additional_derivations, output_index):
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
    subaddress_spendkey = crypto.encodepoint(derive_subaddress_public_key(out_key, derivation, output_index))
    if subaddress_spendkey in subaddresses:
        return subaddresses[subaddress_spendkey], derivation

    if additional_derivations and len(additional_derivations) > 0:
        if output_index >= len(additional_derivations):
            raise ValueError('Wrong number of additional derivations')

        subaddress_spendkey = derive_subaddress_public_key(out_key, additional_derivations[output_index], output_index)
        subaddress_spendkey = crypto.encodepoint(subaddress_spendkey)
        if subaddress_spendkey in subaddresses:
            return subaddresses[subaddress_spendkey], additional_derivations[output_index]

    return None


def generate_key_image_helper_precomp(ack, out_key, recv_derivation, real_output_index, received_index):
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
        raise ValueError('Watch-only wallet not supported')

    # derive secret key with subaddress - step 1: original CN derivation
    scalar_step1 = crypto.derive_secret_key(recv_derivation, real_output_index, ack.spend_key_private)

    # step 2: add Hs(SubAddr || a || index_major || index_minor)
    subaddr_sk = None
    scalar_step2 = None
    if received_index == (0, 0):
        scalar_step2 = scalar_step1
    else:
        subaddr_sk = get_subaddress_secret_key(ack.view_key_private, major=received_index[0], minor=received_index[1])
        scalar_step2 = crypto.sc_add(scalar_step1, subaddr_sk)

    # when not in multisig, we know the full spend secret key, so the output pubkey can be obtained by scalarmultBase
    if len(ack.multisig_keys) == 0:
        pub_ver = crypto.scalarmult_base(scalar_step2)

    else:
        # When in multisig, we only know the partial spend secret key. But we do know the full spend public key,
        # so the output pubkey can be obtained by using the standard CN key derivation.
        pub_ver = crypto.derive_public_key(recv_derivation, real_output_index, ack.spend_key_public)

        # Add the contribution from the subaddress part
        if received_index != (0, 0):
            subaddr_pk = crypto.scalarmult_base(subaddr_sk)
            pub_ver = crypto.point_add(pub_ver, subaddr_pk)

    if not crypto.point_eq(pub_ver, out_key):
        raise ValueError('key image helper precomp: given output pubkey doesn\'t match the derived one')

    ki = generate_key_image(crypto.encodepoint(pub_ver), scalar_step2)
    return scalar_step2, ki


def generate_key_image_helper(creds, subaddresses, out_key, tx_public_key, additional_tx_public_keys, real_output_index):
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
        additional_recv_derivations.append(generate_key_derivation(add_pub_key, creds.view_key_private))

    subaddr_recv_info = is_out_to_acc_precomp(subaddresses, out_key, recv_derivation, additional_recv_derivations, real_output_index)
    if subaddr_recv_info is None:
        raise XmrNoSuchAddressException()

    xi, ki = generate_key_image_helper_precomp(creds, out_key, subaddr_recv_info[1], real_output_index, subaddr_recv_info[0])
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

    tx_scan_info.received = is_out_to_acc_precomp(subaddresses, crypto.decodepoint(tx_out.target.key), derivation, additional_derivations, i)
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
        res = generate_key_image_helper_precomp(creds, out_dec,
                                                tx_scan_info.received[1], i, tx_scan_info.received[0])
        tx_scan_info.in_ephemeral, tx_scan_info.ki = res
        if not tx_scan_info.ki:
            raise ValueError('Key error generation failed')

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
        raise ValueError('Unknown rv type')


def ecdh_decode_simple(rv, sk, i):
    """
    Decodes ECDH from the transaction, checks mask (decoding validity).

    :param rv:
    :param sk:
    :param i:
    :return:
    """
    if i >= len(rv.ecdhInfo):
        raise ValueError('Bad index')
    if len(rv.outPk) != len(rv.ecdhInfo):
        raise ValueError('outPk vs ecdhInfo mismatch')

    ecdh_info = rv.ecdhInfo[i]
    ecdh_info = recode_ecdh(ecdh_info, False)
    ecdh_info = ring_ct.ecdh_decode(ecdh_info, derivation=crypto.encodeint(sk))
    c_tmp = crypto.add_keys2(ecdh_info.mask, ecdh_info.amount, crypto.gen_H())
    if not crypto.point_eq(c_tmp, crypto.decodepoint(rv.outPk[i].mask)):
        raise ValueError('Amount decoded incorrectly')

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


class PreMlsagHasher(object):
    """
    Iterative construction of the pre_mlsag_hash
    """
    def __init__(self):
        self.is_simple = None
        self.state = 0
        self.kc_master = common.HashWrapper(crypto.get_keccak())
        self.rtcsig_hasher = KeccakArchive()
        self.rsig_hasher = crypto.get_keccak()

    def init(self, is_simple):
        if self.state != 0:
            raise ValueError('State error')

        self.state = 1
        self.is_simple = is_simple

    async def set_message(self, message):
        self.kc_master.update(message)

    async def set_type_fee(self, rv_type, fee):
        if self.state != 1:
            raise ValueError('State error')
        self.state = 2

        await self.rtcsig_hasher.ar.message_field(None, field=xmrtypes.RctSigBase.FIELDS[0], fvalue=rv_type)
        await self.rtcsig_hasher.ar.message_field(None, field=xmrtypes.RctSigBase.FIELDS[1], fvalue=fee)

    async def set_pseudo_out(self, out):
        if self.state != 2 and self.state != 3:
            raise ValueError('State error')
        self.state = 3

        await self.rtcsig_hasher.ar.field(out, xmrtypes.KeyV.ELEM_TYPE)

    async def set_ecdh(self, ecdh):
        if self.state != 2 and self.state != 3 and self.state != 4:
            raise ValueError('State error')
        self.state = 4

        await self.rtcsig_hasher.ar.field(ecdh, xmrtypes.EcdhInfo.ELEM_TYPE)

    async def set_out_pk(self, out_pk, mask=None):
        if self.state != 4 and self.state != 5:
            raise ValueError('State error')
        self.state = 5

        await self.rtcsig_hasher.ar.field(mask if mask else out_pk.mask, xmrtypes.ECKey)

    async def rctsig_base_done(self):
        if self.state != 5:
            raise ValueError('State error')
        self.state = 6

        c_hash = self.rtcsig_hasher.kwriter.get_digest()
        self.kc_master.update(c_hash)
        del self.rtcsig_hasher

    async def rsig_val(self, p, bulletproof):
        if self.state == 8:
            raise ValueError('State error')

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
            raise ValueError('State error')
        self.state = 8

        c_hash = self.rsig_hasher.digest()
        del self.rsig_hasher

        self.kc_master.update(c_hash)
        return self.kc_master.digest()


async def get_pre_mlsag_hash(rv):
    """
    Generates final message for the Ring CT signature
    
    :param rv:
    :type rv: xmrtypes.RctSig
    :return:
    """
    kc_master = common.HashWrapper(crypto.get_keccak())
    kc_master.update(rv.message)

    is_simple = rv.type in [xmrtypes.RctType.Simple, xmrtypes.RctType.SimpleBulletproof]
    inputs = len(rv.pseudoOuts) if is_simple else 0
    outputs = len(rv.ecdhInfo)

    kwriter = get_keccak_writer()
    ar = xmrserialize.Archive(kwriter, True)
    await rv.serialize_rctsig_base(ar, inputs, outputs)
    c_hash = kwriter.get_digest()
    kc_master.update(c_hash)

    kc = crypto.get_keccak()
    if rv.type in [xmrtypes.RctType.FullBulletproof, xmrtypes.RctType.SimpleBulletproof]:
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


def copy_ecdh(ecdh):
    """
    Clones ECDH tuple
    :param ecdh:
    :return:
    """
    return xmrtypes.EcdhTuple(mask=ecdh.mask, amount=ecdh.amount)


def recode_ecdh(ecdh, encode=True):
    """
    In-place ecdhtuple recoding
    :param ecdh:
    :param encode: if true encodes to byte representation, otherwise decodes from byte representation
    :return:
    """
    recode_int = crypto.encodeint if encode else crypto.decodeint
    ecdh.mask = recode_int(ecdh.mask)
    ecdh.amount = recode_int(ecdh.amount)
    return ecdh


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


def recode_msg(mgs, encode=True):
    """
    Recodes MGs signatures from raw forms to bytearrays so it works with serialization
    :param rv:
    :param encode: if true encodes to byte representation, otherwise decodes from byte representation
    :return:
    """
    recode_int = crypto.encodeint if encode else crypto.decodeint
    recode_point = crypto.encodepoint if encode else crypto.decodepoint

    for idx in range(len(mgs)):
        mgs[idx].cc = recode_int(mgs[idx].cc)
        if hasattr(mgs[idx], 'II') and mgs[idx].II:
            for i in range(len(mgs[idx].II)):
                mgs[idx].II[i] = recode_point(mgs[idx].II[i])

        for i in range(len(mgs[idx].ss)):
            for j in range(len(mgs[idx].ss[i])):
                mgs[idx].ss[i][j] = recode_int(mgs[idx].ss[i][j])
    return mgs


def recode_rct(rv, encode=True):
    """
    Recodes RCT MGs signatures from raw forms to bytearrays so it works with serialization
    :param rv:
    :param encode: if true encodes to byte representation, otherwise decodes from byte representation
    :return:
    """
    rv.p.MGs = recode_msg(rv.p.MGs, encode=encode)
    return rv


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
            raise ValueError('Bad MGs size')
        for n in range(len(tx.vin)):
            rv.p.MGs[n].II = [tx.vin[n].k_image]

    else:
        raise ValueError('Unsupported rct tx type %s' % rv.type)

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

        pub = get_subaddress_spend_public_key(creds.view_key_private,
                                              creds.spend_key_public,
                                              major=account, minor=idx)
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
    raise ValueError('Input transaction is buggy, contains two tx keys')


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

