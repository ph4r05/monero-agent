# Automatically generated by pb2py
from .. import protobuf as p


class MoneroRctSig(p.MessageType):
    FIELDS = {
        1: ('txn_fee', p.UVarintType, 0),
        2: ('message', p.BytesType, 0),
        3: ('rv_type', p.UVarintType, 0),
    }

    def __init__(
        self,
        txn_fee: int = None,
        message: bytes = None,
        rv_type: int = None
    ) -> None:
        self.txn_fee = txn_fee
        self.message = message
        self.rv_type = rv_type
