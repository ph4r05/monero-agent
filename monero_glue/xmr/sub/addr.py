from monero_glue.xmr import crypto
from monero_glue.xmr.sub.xmr_net import NetworkTypes, net_version


def addr_to_hash(addr):
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
    pub_spend_key = d[0:32]
    pub_view_key = d[32:64]
    return version, pub_spend_key, pub_view_key


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
    return encode_addr(net_ver, pub_addr.m_spend_public_key, pub_addr.m_view_public_key)


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


def addr_eq(a, b):
    return bytes(a.m_spend_public_key) == bytes(b.m_spend_public_key) \
           and bytes(a.m_view_public_key) == bytes(b.m_view_public_key)
