#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


from monero_glue.messages import MoneroRespError


class AgentError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class StubException(Exception):
    def __init__(self, text=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.text = text

    def __repr__(self):
        return 'StubException(%r)' % self.text

    def __str__(self):
        return self.__repr__()


class TrezorReturnedError(AgentError):
    def __init__(self, resp=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resp = resp

    def __str__(self):
        if self.resp and isinstance(self.resp, MoneroRespError):
            return 'TrezorReturnedError(MoneroRespError(status=%r, reason=%r))\n\nCaused by: %s' \
                   % (self.resp.status, self.resp.reason, self.resp.exc)
        else:
            return super().__str__()


class TrezorNotRunning(AgentError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
