# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p


class PassphraseStateRequest(p.MessageType):
    MESSAGE_WIRE_TYPE = 77
    FIELDS = {
        1: ('state', p.BytesType, 0),
    }

    def __init__(
        self,
        state: bytes = None,
    ) -> None:
        self.state = state