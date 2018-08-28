from monero_glue.xmr import crypto


class KeccakArchive(object):
    def __init__(self, ctx=None):
        from monero_serialize import xmrserialize

        self.kwriter = get_keccak_writer(ctx=ctx)
        self.ar = xmrserialize.Archive(self.kwriter, True)

    def ctx(self):
        return self.kwriter.ctx()

    def refresh(self, ctx=None, xser=None):
        from monero_serialize import xmrserialize

        if ctx is None:
            ctx = self.kwriter.ctx()
        if xser is None:
            xser = xmrserialize

        self.kwriter = get_keccak_writer(ctx=ctx)
        self.ar = xser.Archive(self.kwriter, True)
        return self.ar


class KeccakXmrArchive(object):
    def __init__(self, ctx=None):
        self.kwriter = get_keccak_writer(ctx=ctx)
        self.ar = None
        self.keeping = False

    def ctx(self):
        return self.kwriter.ctx()

    def get_digest(self):
        return self.kwriter.get_digest()

    def refresh(self, ctx=None):
        if ctx is None:
            ctx = self.kwriter.ctx()
        self.kwriter = get_keccak_writer(ctx=ctx)

    def _ar(self, xser=None):
        if self.keeping and self.ar:
            return self.ar
        if xser:
            ar = xser.Archive(self.kwriter, True)
        else:
            from monero_serialize import xmrserialize

            ar = xmrserialize.Archive(self.kwriter, True)
        self.ar = ar if self.keeping else None
        return ar

    def keep(self, keep=True):
        self.keeping = keep

    def release(self):
        self.ar = None

    async def field(self, elem=None, elem_type=None, params=None, xser=None):
        ar = self._ar(xser)
        return await ar.field(elem, elem_type, params)

    async def message_field(self, msg, field, fvalue=None, xser=None):
        ar = self._ar(xser)
        return await ar.message_field(msg, field, fvalue)

    async def container_size(
        self, container_len=None, container_type=None, params=None, xser=None
    ):
        ar = self._ar(xser)
        return await ar.container_size(container_len, container_type, params)


class HashWrapper(object):
    def __init__(self, ctx):
        self.ctx = ctx

    def update(self, buf):
        if len(buf) == 0:
            return
        self.ctx.update(buf)

    def digest(self):
        return self.ctx.digest()

    def hexdigest(self):
        return self.ctx.hexdigest()


class AHashWriter:
    def __init__(self, hasher, sub_writer=None):
        self.hasher = hasher
        self.sub_writer = sub_writer

    async def awrite(self, buf):
        self.hasher.update(buf)
        if self.sub_writer:
            await self.sub_writer.awrite(buf)
        return len(buf)

    def get_digest(self, *args) -> bytes:
        return self.hasher.digest(*args)

    def ctx(self):
        return self.hasher.ctx


def get_keccak_writer(sub_writer=None, ctx=None):
    """
    Creates new fresh async Keccak writer
    :param sub_writer:
    :param ctx:
    :return:
    """
    return AHashWriter(
        HashWrapper(crypto.get_keccak() if ctx is None else ctx), sub_writer=sub_writer
    )
