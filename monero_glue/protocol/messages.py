#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

from monero_glue import protobuf
from monero_glue import messages
from monero_glue.messages import *


def get_message_type(msg=None, cls=None):
    if msg is not None:
        cls = msg.__class__

    type_id = getattr(MessageType, cls.__name__)
    if type_id is None:
        raise ValueError('Could not find message ID for: %s' % msg)
    return type_id


def get_message_from_type(type_id):
    all_msg = [x for x in dir(MessageType) if not x.startswith('_')]
    for m in all_msg:
        cur_id = getattr(MessageType, m)
        if cur_id == type_id:
            return getattr(messages, m)
    raise ValueError('Could not find message with type: %s' % type_id)


class MessageConverter(object):
    """
    Converts protobuf messages between base packages.
    Converts our protobufs <-> trezorlib
    Required for protobuf encoders
    """
    
    def __init__(self):
        self.imported = False
        self.tlib_msgs = None
        self.tlib_p = None

    def _init(self):
        if self.imported:
            return

        from trezorlib import messages as tlib_msgs
        from trezorlib import protobuf as tlib_protobuf
        self.tlib_msgs = tlib_msgs
        self.tlib_p = tlib_protobuf
        self.imported = True

    def _transform(self, msg, src_proto, dst_package):
        if isinstance(msg, src_proto.MessageType):
            msg_name = msg.__class__.__name__
            tlib_msg = getattr(dst_package, msg_name)

            nmsg = tlib_msg()
            for tag in msg.FIELDS:
                field = msg.FIELDS[tag]
                field_name = field[0]
                if hasattr(msg, field_name):
                    cval = getattr(msg, field_name, None)
                    setattr(nmsg, field_name, self.to_trezorlib(cval))
            return nmsg

        elif isinstance(msg, list):
            return [self.to_trezorlib(x) for x in msg]
        elif isinstance(msg, dict):
            return {v:self.to_trezorlib(x) for v,x in msg.items()}
        else:
            return msg

    def to_phlib(self, msg):
        self._init()
        return self._transform(msg, self.tlib_p, messages)

    def to_trezorlib(self, msg):
        self._init()
        return self._transform(msg, protobuf, self.tlib_msgs)

