from monero_glue.compat.collections import namedtuple
from monero_glue.xmr import crypto
from monero_glue.xmr.sub.xmr_net import (
    NetworkTypes,
    net_version,
    MainNet,
    TestNet,
    StageNet,
)


PubAddress = namedtuple("PubAddress", ("spend_public_key", "view_public_key"))


class AddrInfo(object):
    def __init__(self, ver=None, data=None, payment_id=None):
        self.view_key = None
        self.spend_key = None
        self.net_type = None
        self.is_sub_address = None
        self.is_integrated = None
        self.payment_id = payment_id
        self.addr = None
        self.base_addr = None
        if ver is not None and data is not None:
            self.set_addr(ver, data, self.payment_id)

    def set_addr(self, ver, data, payment_id=None):
        self.net_type = get_addr_type(ver)
        self.is_sub_address = is_subaddress(ver)
        self.is_integrated = is_integrated(ver)
        self.spend_key = data[0:32]
        self.view_key = data[32:64]
        if self.is_integrated:
            self.payment_id = data[64:]
        else:
            self.payment_id = payment_id
        self.recompute_addr()
        return self

    def recompute_addr(self):
        addr = build_address(self.spend_key, self.view_key)
        self.base_addr = public_addr_encode(addr, self.is_sub_address, self.net_type)
        self.addr = public_addr_encode(
            addr, self.is_sub_address, self.net_type, self.payment_id
        )
        return self

    def recompute_sub(self, spend_key, view_key, major=0, minor=0):
        self.spend_key = spend_key
        self.view_key = view_key
        self.is_sub_address = major != 0 and minor != 0
        self.recompute_addr()


def addr_to_hash(addr):
    """
    Creates hashable address representation
    :param addr:
    :return:
    """
    return bytes(addr.spend_public_key + addr.view_public_key)


def encode_addr(version, spend_pub, view_pub, payment_id=None):
    """
    Encodes public keys as versions
    :param version:
    :param spend_pub:
    :param view_pub:
    :param payment_id:
    :return:
    """
    buf = spend_pub + view_pub
    if payment_id:
        buf += bytes(payment_id)
    return crypto.xmr_base58_addr_encode_check(ord(version), bytes(buf))


def decode_addr(addr):
    """
    Given address, get version and public spend and view keys.

    :param addr:
    :return:
    """
    d, version = crypto.xmr_base58_addr_decode_check(bytes(addr))
    return AddrInfo(version, d)


def build_address(spend_key, view_key):
    """
    Builds address compatible object from byte encoded keys
    :param spend_key:
    :param view_key:
    :return:
    """
    return PubAddress(spend_key, view_key)


def build_address_encode(spend_key, view_key):
    """
    Builds address compatible object from object keys
    :param spend_key:
    :param view_key:
    :return:
    """
    return PubAddress(crypto.encodepoint(spend_key), crypto.encodepoint(view_key))


def public_addr_encode(
    pub_addr, is_sub=False, net=NetworkTypes.MAINNET, payment_id=None
):
    """
    Encodes public address to Monero address
    :param pub_addr:
    :type pub_addr: apps.monero.xmr.serialize_messages.addr.AccountPublicAddress
    :param is_sub:
    :param net:
    :param payment_id: for integrated address
    :return:
    """
    if payment_id and len(payment_id) != 8:
        raise ValueError("Payment ID has to have exactly 8B for an integrated address")
    net_ver = net_version(net, is_sub, payment_id is not None)
    return encode_addr(
        net_ver, pub_addr.spend_public_key, pub_addr.view_public_key, payment_id
    )


def classify_subaddresses(tx_dests, change_addr):
    """
    Classify destination subaddresses
    void classify_addresses()
    :param tx_dests:
    :type tx_dests: list[apps.monero.xmr.serialize_messages.tx_construct.TxDestinationEntry]
    :param change_addr:
    :return:
    """
    num_stdaddresses = 0
    num_subaddresses = 0
    single_dest_subaddress = None
    addr_set = set()
    for tx in tx_dests:
        if change_addr and addr_eq(change_addr, tx.addr):
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


def addr_eq(a, b):
    """
    Address comparisson. Allocation free.
    :param a:
    :param b:
    :return:
    """
    return (
        a.spend_public_key == b.spend_public_key
        and a.view_public_key == b.view_public_key
    )


def get_change_addr_idx(outputs, change_dts):
    """
    Returns ID of the change output from the change_dts and outputs
    :param tsx_data:
    :return:
    """
    if change_dts is None:
        return None

    change_idx = None
    change_coord = change_dts.amount, change_dts.addr
    for idx, dst in enumerate(outputs):
        if (
            change_coord
            and change_coord[0]
            and change_coord[0] == dst.amount
            and addr_eq(change_coord[1], dst.addr)
        ):
            change_idx = idx
    return change_idx


def is_integrated(ver):
    return ver in [
        MainNet.PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        TestNet.PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        StageNet.PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    ]


def is_subaddress(ver):
    return ver in [
        MainNet.PUBLIC_SUBADDRESS_BASE58_PREFIX,
        TestNet.PUBLIC_SUBADDRESS_BASE58_PREFIX,
        StageNet.PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ]


def get_addr_type(ver):
    if ver in [
        MainNet.PUBLIC_ADDRESS_BASE58_PREFIX,
        MainNet.PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        MainNet.PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ]:
        return NetworkTypes.MAINNET
    elif ver in [
        TestNet.PUBLIC_ADDRESS_BASE58_PREFIX,
        TestNet.PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        TestNet.PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ]:
        return NetworkTypes.TESTNET
    elif ver in [
        StageNet.PUBLIC_ADDRESS_BASE58_PREFIX,
        StageNet.PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        StageNet.PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ]:
        return NetworkTypes.STAGENET
    else:
        raise ValueError("Unknown address type")
