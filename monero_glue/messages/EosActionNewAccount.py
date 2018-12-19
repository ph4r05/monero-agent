# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .EosAuthorization import EosAuthorization


class EosActionNewAccount(p.MessageType):

    def __init__(
        self,
        creator: int = None,
        name: int = None,
        owner: EosAuthorization = None,
        active: EosAuthorization = None,
    ) -> None:
        self.creator = creator
        self.name = name
        self.owner = owner
        self.active = active

    @classmethod
    def get_fields(cls):
        return {
            1: ('creator', p.UVarintType, 0),
            2: ('name', p.UVarintType, 0),
            3: ('owner', EosAuthorization, 0),
            4: ('active', EosAuthorization, 0),
        }
