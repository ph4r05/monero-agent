#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from monero_serialize import xmrtypes, xmrserialize
from . import common as common
from . import crypto
from . import b58
from . import b58_mnr
import binascii
import base64
import struct


class TsxData(xmrserialize.MessageType):
    """
    TsxData, initial input to the transaction processing.
    Serialization structure for easy hashing.
    """
    __slots__ = ['version', 'payment_id', 'unlock_time', 'outputs', 'change_dts']
    FIELDS = [
        ('version', xmrserialize.UVarintType),
        ('payment_id', xmrserialize.BlobType),
        ('unlock_time', xmrserialize.UVarintType),
        ('outputs', xmrserialize.ContainerType, xmrtypes.TxDestinationEntry),
        ('change_dts', xmrtypes.TxDestinationEntry),
    ]

    def __init__(self, payment_id=None, outputs=None, change_dts=None, **kwargs):
        super().__init__(**kwargs)

        self.payment_id = payment_id
        self.change_dts = change_dts
        self.outputs = outputs if outputs else []  # type: list[xmrtypes.TxDestinationEntry]


def net_version():
    """
    Network version bytes
    :return:
    """
    return b'\x12'


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
            num_subaddresses+=1
            single_dest_subaddress = tx.addr
        else:
            num_stdaddresses+=1
    return num_stdaddresses, num_subaddresses, single_dest_subaddress


async def parse_extra_fields(extra_buff):
    """
    Parses extra buffer to the extra fields vector
    :param extra_buff:
    :return:
    """
    extras = []
    rw = xmrserialize.MemoryReaderWriter(extra_buff)
    ar2 = xmrserialize.Archive(rw, False)
    while len(rw.buffer) > 0:
        extras.append(await ar2.variant(elem_type=xmrtypes.TxExtraField))
    return extras


def find_tx_extra_field_by_type(extra_fields, msg):
    """
    Finds given message type in the extra array, or returns None if not found
    :param extra_fields:
    :param msg:
    :return:
    """
    for x in extra_fields:
        if isinstance(x, msg):
            return x


def has_encrypted_payment_id(extra_nonce):
    """
    Returns true if encrypted payment id is present
    :param extra_nonce:
    :return:
    """
    return len(extra_nonce) == 9 and extra_nonce[0] == 1


def get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce):
    """
    Extracts encrypted payment id from extra
    :param extra_nonce:
    :return:
    """
    if 9 != len(extra_nonce):
        raise ValueError('Nonce size mismatch')
    if 0x1 != extra_nonce[0]:
        raise ValueError('Nonce payment type invalid')
    return extra_nonce[1:]


def set_payment_id_to_tx_extra_nonce(payment_id):
    """
    Sets payment ID to the extra
    :param payment_id:
    :return:
    """
    return b'\x00' + payment_id


def absolute_output_offsets_to_relative(off):
    """
    Relative offsets, prev + cur = next.
    Helps with varint encoding size.
    :param off:
    :return:
    """
    if len(off) == 0:
        return off
    res = sorted(off)
    for i in range(len(off)-1, 0, -1):
        res[i] -= res[i-1]
    return res


def get_destination_view_key_pub(destinations, change_addr=None):
    """
    Returns destination address public view key
    :param destinations:
    :type destinations: list[xmrtypes.TxDestinationEntry]
    :param change_addr:
    :return:
    """
    addr = xmrtypes.AccountPublicAddress(m_spend_public_key=crypto.NULL_KEY_ENC, m_view_public_key=crypto.NULL_KEY_ENC)
    count = 0
    for dest in destinations:
        if dest.amount == 0:
            continue
        if change_addr and dest.addr == change_addr:
            continue
        if dest.addr == addr:
            continue
        if count > 0:
            return [0]*32
        addr = dest.addr
        count += 1
    return addr.m_view_public_key


def encrypt_payment_id(payment_id, public_key, secret_key):
    """
    Encrypts payment_id hex.
    Used in the transaction extra. Only recipient is able to decrypt.
    :param payment_id:
    :param public_key:
    :param secret_key:
    :return:
    """
    derivation_p = crypto.generate_key_derivation(public_key, secret_key)
    derivation = crypto.encodepoint(derivation_p)
    derivation += b'\x8b'
    hash = crypto.cn_fast_hash(derivation)
    pm_copy = bytearray(payment_id)
    for i in range(8):
        pm_copy[i] ^= hash[i]
    return pm_copy


def set_encrypted_payment_id_to_tx_extra_nonce(payment_id):
    return b'\x01' + payment_id


async def remove_field_from_tx_extra(extra, mtype):
    """
    Removes extra field of fiven type from the buffer
    Reserializes with skipping the given mtype.
    :param extra:
    :param mtype:
    :return:
    """
    if len(extra) == 0:
        return []

    reader = xmrserialize.MemoryReaderWriter(extra)
    writer = xmrserialize.MemoryReaderWriter()
    ar_read = xmrserialize.Archive(reader, False)
    ar_write = xmrserialize.Archive(writer, True)
    while len(reader.buffer) > 0:
        c_extras = await ar_read.variant(elem_type=xmrtypes.TxExtraField)
        if not isinstance(c_extras, mtype):
            await ar_write.variant(c_extras, elem_type=xmrtypes.TxExtraField)

    return writer.buffer


def add_extra_nonce_to_tx_extra(extra, extra_nonce):
    """
    Appends nonce extra to the extra buffer
    :param extra:
    :param extra_nonce:
    :return:
    """
    if len(extra_nonce) > 255:
        raise ValueError('Nonce could be 255 bytes max')
    extra += b'\x02' + len(extra_nonce).to_bytes(1, byteorder='big') + extra_nonce
    return extra


def add_tx_pub_key_to_extra(tx_extra, pub_key):
    """
    Adds public key to the extra
    :param tx_extra:
    :param pub_key:
    :return:
    """
    tx_extra.append(1)  # TX_EXTRA_TAG_PUBKEY
    tx_extra.extend(crypto.encodepoint(pub_key))


async def add_additional_tx_pub_keys_to_extra(tx_extra, additional_pub_keys):
    """
    Adds all pubkeys to the extra
    :param tx_extra:
    :param additional_pub_keys:
    :return:
    """
    pubs_msg = xmrtypes.TxExtraAdditionalPubKeys(data=[crypto.encodepoint(x) for x in additional_pub_keys])

    rw = xmrserialize.MemoryReaderWriter()
    ar = xmrserialize.Archive(rw, True)

    # format: variant_tag (0x4) | array len varint | 32B | 32B | ...
    await ar.variant(pubs_msg, xmrtypes.TxExtraField)
    tx_extra.extend(rw.buffer)


def get_subaddress_secret_key(secret_key, index=None, major=None, minor=None):
    """
    Builds subaddress secret key from the subaddress index
    Hs(SubAddr || a || index_major || index_minor)

    TODO: handle endianity in the index
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
    :return:
    """
    if index:
        major = index.major
        minor = index.minor
    prefix = b'SubAddr'
    buffer = bytearray(len(prefix) + 1 + 32 + 4 + 4)
    struct.pack_into('=7sb32sLL', buffer, 0, prefix, 0, crypto.encodeint(secret_key), major, minor)
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

    :param ack:
    :param out_key:
    :param recv_derivation:
    :param real_output_index:
    :param received_index:
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

    # TODO: multisig here
    # ...

    pub_ver = crypto.scalarmult_base(scalar_step2)

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
    :param out_key:
    :param tx_public_key:
    :param additional_tx_public_keys:
    :param real_output_index:
    :return:
    """
    recv_derivation = generate_key_derivation(tx_public_key, creds.view_key_private)

    additional_recv_derivations = []
    for add_pub_key in additional_tx_public_keys:
        additional_recv_derivations.append(generate_key_derivation(add_pub_key, creds.view_key_private))

    subaddr_recv_info = is_out_to_acc_precomp(subaddresses, out_key, recv_derivation, additional_recv_derivations, real_output_index)

    xi, ki = generate_key_image_helper_precomp(creds, out_key, subaddr_recv_info[1], real_output_index, subaddr_recv_info[0])
    return xi, ki, recv_derivation


async def get_transaction_prefix_hash(tx):
    """
    Computes transaction prefix in one step
    :param tx:
    :return:
    """
    writer = common.get_keccak_writer()
    ar1 = xmrserialize.Archive(writer, True)
    await ar1.message(tx, msg_type=xmrtypes.TransactionPrefix)
    return writer.get_digest()


class PreMlsagHasher(object):
    """
    Iterative construction of the pre_mlsag_hash
    """
    def __init__(self):
        self.is_simple = None
        self.state = 0
        self.kc_master = common.HashWrapper(common.get_keccak())
        self.rtcsig_hasher = common.KeccakArchive()
        self.rsig_hasher = common.get_keccak()

    def init(self, is_simple, message):
        if self.state != 0:
            raise ValueError('State error')

        self.state = 1
        self.is_simple = is_simple
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
        if self.state != 6 and self.state != 7:
            raise ValueError('State error')
        self.state = 7

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
        if self.state != 7:
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
    kc_master = common.HashWrapper(common.get_keccak())
    kc_master.update(rv.message)

    if len(rv.mixRing) == 0:
        raise ValueError('Empty mixring')

    is_simple = rv.type in [xmrtypes.RctType.Simple, xmrtypes.RctType.SimpleBulletproof]
    inputs = len(rv.mixRing) if is_simple else len(rv.mixRing[0])
    outputs = len(rv.ecdhInfo)

    kwriter = common.get_keccak_writer()
    ar = xmrserialize.Archive(kwriter, True)
    await rv.serialize_rctsig_base(ar, inputs, outputs)
    c_hash = kwriter.get_digest()
    kc_master.update(c_hash)

    kc = common.get_keccak()
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


def recode_rangesig(rsig, encode=True):
    """
    In - place rsig recoding
    :param rsig:
    :param encode: if true encodes to byte representation, otherwise decodes from byte representation
    :return:
    """
    recode_int = crypto.encodeint if encode else crypto.decodeint
    recode_point = crypto.encodepoint if encode else crypto.decodepoint

    for i in range(len(rsig.Ci)):
        rsig.Ci[i] = recode_point(rsig.Ci[i])
    for i in range(len(rsig.asig.s0)):
        rsig.asig.s0[i] = recode_int(rsig.asig.s0[i])
    for i in range(len(rsig.asig.s1)):
        rsig.asig.s1[i] = recode_int(rsig.asig.s1[i])
    rsig.asig.ee = recode_int(rsig.asig.ee)
    return rsig


def recode_rct(rv, encode=True):
    """
    Recodes RCT MGs signatures from raw forms to bytearrays so it works with serialization
    :param rv:
    :param encode: if true encodes to byte representation, otherwise decodes from byte representation
    :return:
    """
    recode_int = crypto.encodeint if encode else crypto.decodeint
    recode_point = crypto.encodepoint if encode else crypto.decodepoint

    mgs = rv.p.MGs
    for idx in range(len(mgs)):
        mgs[idx].cc = recode_int(mgs[idx].cc)
        if hasattr(mgs[idx], 'II') and mgs[idx].II:
            for i in range(len(mgs[idx].II)):
                mgs[idx].II[i] = recode_point(mgs[idx].II[i])

        for i in range(len(mgs[idx].ss)):
            for j in range(len(mgs[idx].ss[i])):
                mgs[idx].ss[i][j] = recode_int(mgs[idx].ss[i][j])
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

