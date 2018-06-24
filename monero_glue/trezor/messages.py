#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


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

