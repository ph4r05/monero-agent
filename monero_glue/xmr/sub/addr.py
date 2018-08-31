from monero_glue.xmr import crypto
from monero_glue.xmr.sub.xmr_net import (
    NetworkTypes,
    net_version,
    MainNet,
    TestNet,
    StageNet,
)


class AddrInfo(object):
    def __init__(self, ver=None, data=None):
        self.view_key = None
        self.spend_key = None
        self.net_type = None
        self.is_sub_address = None
        self.is_integrated = None
        self.payment_id = None
        if ver is not None and data is not None:
            self.set_addr(ver, data)

    def set_addr(self, ver, data):
        self.net_type = get_addr_type(ver)
        self.is_sub_address = is_subaddress(ver)
        self.is_integrated = is_integrated(ver)
        self.spend_key = data[0:32]
        self.view_key = data[32:64]
        if self.is_integrated:
            self.payment_id = data[64:]
        return self


def addr_to_hash(addr):
    """
    Creates hashable address representation
    :param addr:
    :return:
    """
    return bytes(addr.spend_public_key + addr.view_public_key)


def encode_addr(version, spend_pub, view_pub):
    """
    Encodes public keys as versions
    :param version:
    :param spend_pub:
    :param view_pub:
    :return:
    """
    buf = spend_pub + view_pub
    return crypto.xmr_base58_addr_encode_check(ord(version), bytes(buf))


def decode_addr(addr):
    """
    Given address, get version and public spend and view keys.

    :param addr:
    :return:
    """
    d, version = crypto.xmr_base58_addr_decode_check(bytes(addr))
    return AddrInfo(version, d)


def public_addr_encode(pub_addr, is_sub=False, net=NetworkTypes.MAINNET):
    """
    Encodes public address to Monero address
    :param pub_addr:
    :type pub_addr: apps.monero.xmr.serialize_messages.addr.AccountPublicAddress
    :param is_sub:
    :param net:
    :return:
    """
    net_ver = net_version(net, is_sub)
    return encode_addr(net_ver, pub_addr.spend_public_key, pub_addr.view_public_key)


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
    return pub_eq(a.spend_public_key, b.spend_public_key) and pub_eq(
        a.view_public_key, b.view_public_key
    )


def pub_eq(a, b):
    """
    Simple non-constant time public key compare
    :param a:
    :param b:
    :return:
    """
    if a == b:
        return True
    if (a is None and b is not None) or (a is not None and b is None):
        return False
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


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
