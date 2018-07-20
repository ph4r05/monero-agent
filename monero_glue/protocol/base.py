#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from monero_serialize import xmrserialize


class TMessage(object):
    def __init__(self, *args, **kwargs):
        self.status = 0

    def __repr__(self):
        dct = (
            xmrserialize.slot_obj_dict(self)
            if hasattr(self, "__slots__")
            else self.__dict__
        )
        return "<%s: %s>" % (self.__class__.__name__, dct)


class TError(TMessage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.status = 1
        self.reason = kwargs.pop("reason", None)
        self.exc = kwargs.pop("exc", None)
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])

    def __repr__(self):
        return "TError(status=%r, reason=%r, exc=%r)" % (
            self.status,
            self.reason,
            self.exc,
        )


class TTxHashNotMatchingError(TError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TResponse(TMessage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = args
        for kw in kwargs:
            setattr(self, kw, kwargs[kw])
