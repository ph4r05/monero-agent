#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018


class AgentError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TrezorReturnedError(AgentError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class TrezorNotRunning(AgentError):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


