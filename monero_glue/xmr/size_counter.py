import sys

SIZE_BOOL = 1
SIZE_INT = 8
SIZE_SC = 32
SIZE_PT = 32
SIZE_PT_FULL = 10 * 32 * 4
SIZE_SC_FULL = 9 * 32


def sizeof(x):
    try:
        return sys.getsizeof(x)
    except:
        return 0


def getcells(x):
    try:
        return sys.getcells(x)
    except:
        return tuple()


class SizeCounter:
    def __init__(self, real=False, do_track=True, do_trace=False):
        self.real = real
        self.do_track = do_track
        self.do_trace = do_trace
        self.track = set() if do_track else None
        self.trace = [] if do_trace else None
        self.acc = 0
        self._clos = lambda x: x * int(do_track) * int(do_trace)  # just to capture closure type
        self._lambda = lambda x: 0

    def check_type(self, tp, v, name, real):
        print("Unknown type: ", name, ", v", v, ", tp", tp)
        return 0

    def comp_size(self, v, name=None, real=False):
        if v is None:
            return 0

        real = self.real if self else real
        tp = type(v)
        iid = id(v)
        addc = True

        if self and self.do_track and not isinstance(v, (int, bool, float)):
            if iid in self.track:
                return 0
            else:
                self.track.add(iid)

        c = 0
        if tp == int:
            c = SIZE_INT if not real else sizeof(v)
        elif tp == bool:
            c = 1 if not real else sizeof(v)
        elif tp == bytearray:
            c = len(v) if not real else sizeof(v)
        elif tp == bytes:
            c = len(v) if not real else sizeof(v)
        elif tp == str:
            c = len(v) if not real else sizeof(v)
        elif tp == memoryview:
            c = len(v) if not real else sizeof(v)
        elif tp == type(self._lambda):
            c = 1 if not real else sizeof(1)
        elif tp == type(self._clos):
            cc = 1 if not real else sizeof(v)
            self.acc += cc
            c = (
                sum(
                    [
                        self.comp_size(x, "%s[%s, %s]" % (name, i, type(x)))
                        for i, x in enumerate(getcells(v))
                    ]
                )
                + cc
            )
            addc = False

        elif tp == list or tp == tuple:
            cc = 0 if not real else sizeof(v)
            self.acc += cc
            c = (
                sum(
                    [
                        self.comp_size(x, "%s[%s, %s]" % (name, i, type(x)))
                        for i, x in enumerate(v)
                    ]
                )
                + cc
            )
            addc = False

        else:
            return self.check_type(tp, v, name, real)

        return self.tailsum(c, name, addc)

    def tailsum(self, c, name, addc=True):
        if addc:
            self.acc += c
        if self.do_trace:
            self.trace.append((name, c))
        return c

    def slot_sizes(self, obj, slots, real=False, name=""):
        if not slots or not obj:
            return 0
        return sum(
            [self.comp_size(getattr(obj, x, None), "%s.%s" % (name, x)) for x in slots]
        )

    def report(self):
        if not self.do_trace:
            return
        
        print('SizeReport: {"real": %s, "report":[' % self.real)
        ln = len(self.trace)
        for ix, x in enumerate(self.trace):
            print(('  {"%s": %s}' % x) + (',' if ix+1 < ln else ''))
        print("]}")


def slot_sizes(obj, slots, real=False, name=""):
    return 0


def comp_size(v, name=None, real=False):
    return SizeCounter(real, False).comp_size(v, name)
