# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p
if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None  # type: ignore


class CardanoTxInputType(p.MessageType):
    FIELDS = {
        1: ('address_n', p.UVarintType, p.FLAG_REPEATED),
        2: ('prev_hash', p.BytesType, 0),
        3: ('prev_index', p.UVarintType, 0),
        4: ('type', p.UVarintType, 0),
    }

    def __init__(
        self,
        address_n: List[int] = None,
        prev_hash: bytes = None,
        prev_index: int = None,
        type: int = None,
    ) -> None:
        self.address_n = address_n if address_n is not None else []
        self.prev_hash = prev_hash
        self.prev_index = prev_index
        self.type = type