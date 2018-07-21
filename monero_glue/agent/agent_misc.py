#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from monero_glue.messages import Failure


class AgentError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class StubException(Exception):
    def __init__(self, text=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.text = text

    def __repr__(self):
        return "StubException(%r)" % self.text

    def __str__(self):
        return self.__repr__()


class TrezorReturnedError(AgentError):
    def __init__(self, resp=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resp = resp

    def __str__(self):
        if self.resp and isinstance(self.resp, Failure):
            return "TrezorReturnedError(Failure(code=%r, message=%r))" % (
                self.resp.code,
                self.resp.message,
            )
        else:
            return super().__str__()


class TrezorNotRunning(AgentError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
