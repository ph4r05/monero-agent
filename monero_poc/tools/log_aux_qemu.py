import argparse
import fileinput
import io
import json
import logging
import os
import re
import time
import copy
import collections

import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)


def remove_ctl(line):
    return re.sub(r"\x1b\[\d+m", "", line.rstrip("\n"))


def avg(iterable):
    return sum(iterable) / float(len(iterable))


def count_elements(seq) -> dict:
    hist = {}
    for i in seq:
        hist[i] = hist.get(i, 0) + 1
    return hist


def ascii_histogram(seq) -> None:
    """A horizontal frequency-table/histogram plot."""
    counted = count_elements(seq)
    for k in sorted(counted):
        print("{0:5d} {1}".format(k, "+" * counted[k]))


def toi(x):
    return int(x, 16)


def binary_search(data, val):
    highIndex = len(data)-1
    lowIndex = 0
    while highIndex > lowIndex:
        index = (highIndex + lowIndex) // 2
        sub = data[index]
        if data[lowIndex] == val:
            return [lowIndex, lowIndex]
        elif sub == val:
            return [index, index]
        elif data[highIndex] == val:
            return [highIndex, highIndex]
        elif sub > val:
            if highIndex == index:
                return sorted([highIndex, lowIndex])
            highIndex = index
        else:
            if lowIndex == index:
                return sorted([highIndex, lowIndex])
            lowIndex = index
    return sorted([highIndex, lowIndex])


class TxtSymbol(object):
    def __init__(self, fid=None, symbol=None, addr=None, obj=None, offset=None):
        self.fid = fid
        self.symbol = symbol
        self.addr = addr
        self.obj = obj
        self.offset = offset
        self._shortid = None

    @property
    def shortid(self):
        if not self._shortid:
            iid = self.fid
            if os.path.sep in self.fid:
                iid = os.path.basename(iid)
            self._shortid = iid[:3]
        return self._shortid

    def fulldesc(self):
        sobj = (': %s:%s' % (self.obj, hex(self.offset) if self.offset else '0x0')) if self.obj else ''
        return 'Symbol(%s -> %s%s)' % (self.symbol, hex(self.addr), sobj)

    def shortref(self):
        return '%s:%s' % (self.shortid, self.symbol)

    def __repr__(self):
        sobj = ''
        if self.obj:
            sobj = ': %s' % self.obj.split('/')[-1]
        iid = '%s:' % self.fid[:2]
        return 'Symbol(%s%s -> %s%s)' % (iid, self.symbol, hex(self.addr), sobj)


class Mapper(object):
    """Linker map file parser - extracts symbols for symbol resolution"""
    SEC = 'Linker script and memory map'

    def __init__(self):
        self.bases = collections.defaultdict(lambda: None)
        self.symbs = collections.defaultdict(lambda: None)
        self.addrs = []

    def resolve(self, addr):
        if isinstance(addr, str):
            addr = int(addr, 16)
        return self.symbs[hex(addr)]

    def resolve_ish(self, addr):
        if isinstance(addr, str):
            addr = int(addr, 16)

        prec = self.symbs[hex(addr)]
        if prec:
            return prec

        lo, hi = binary_search(self.addrs, addr)
        return self.symbs[hex(self.addrs[lo])]

    def add_map(self, fname):
        data = open(fname).read()
        ix = data.find('SEC')
        if ix < 0:
            raise ValueError('Section not found')

        lines = data[ix:].split('\n')

        csec = None
        csymb = None
        is_txt = False
        is_txt_scanning = False

        for ix, line in enumerate(lines):
            msec = re.match(r' \.(\w+).*', line)  # just simple section det
            msecfull = re.match(r' \.(\w+)(?:\.([\w.\-]+))?\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.*)\s*', line)
            msecshort = re.match(r' \.(\w+)\.([\w.\-]+).*', line)

            if msec:
                csec = msec.group(1)
                is_txt = csec == 'text'

            if msecfull:
                csymb = TxtSymbol(fname, None,
                                  addr=toi(msecfull.group(3)),
                                  obj=msecfull.group(5),
                                  offset=toi(msecfull.group(4)))
                is_txt_scanning = is_txt

            elif msecshort:
                is_txt_scanning = is_txt
                csymb = msecshort.group(2)
                csymb = TxtSymbol(fname, csymb, None)

            elif msec:
                pass

            elif is_txt_scanning:
                #                 0x0000000008005404       0x70 build/boardloader/vendor/blabla.o
                maddr = re.match(r'^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.*)\s*', line)
                #                 0x0000000008005324                HAL_SRAM_Init
                msymb = re.match(r'^\s*(0x[0-9a-fA-F]+)\s+([^.\s][\w_\-.]+)\s*', line)

                if maddr:
                    csymb.addr = toi(maddr.group(1))
                    csymb.offset = toi(maddr.group(2))
                    csymb.obj = maddr.group(3)
                    self.add_symbol(csymb)

                elif msymb:
                    csymb.addr = toi(msymb.group(1))
                    csymb.symbol = msymb.group(2)
                    self.add_symbol(csymb)
                    csymb.symbol = None

                else:
                    is_txt_scanning = False

            else:
                pass

        self.addrs = sorted([x.addr for x in self.symbs.values()])

    def add_symbol(self, o):
        # TODO: conflicting addresses? shared symbol ...
        self.symbs[hex(o.addr)] = copy.deepcopy(o)

    def add_txt_symbol(self, fid, symb, addr, object=None, offset=None):
        if self.bases[fid] is None:
            self.bases[fid] = os.path.basename(fid)

        bname = self.bases[fid]
        intaddr = int(addr, 16)
        o = TxtSymbol(bname, symb, intaddr, object, offset)
        self.symbs[hex(intaddr)] = o
        return o


class QEMULogAnalyzer(object):
    def __init__(self):
        self.args = None
        self.mapper = Mapper()
        self.max_line_len = 0
        self.tee_file = None
        self.time_prev = 0
        self.frame = []

    def print_line(self, line):
        print(line)
        if self.args.tee_aux:
            self.tee_line(line)

    def tee_line(self, line):
        if self.tee_file:
            self.tee_file.write(line)
            self.tee_file.write("\n")

    def process(self, line):
        line = line.strip()
        if self.args.no_ctl:
            line = remove_ctl(line)

        if not self.args.tee_aux:
            self.tee_line(line)

        line = line.replace('\t', ' ')
        m = re.findall(r'(0x[0-9a-fA-F]+)', line)
        if not m:
            self.print_line(line)
            return

        ctime_r = time.time()
        c_prev = self.time_prev
        self.time_prev = ctime_r
        self.max_line_len = max(self.max_line_len, min(len(line), 160))

        if self.args.no_aug:
            self.print_line(line)
            return

        # symbol resolution on line
        symbs = []
        for x in m:
            if int(x, 16) < 32:
                continue
            pr, cs = 1, self.mapper.resolve(x)
            if cs is None:
                pr, cs = 0, self.mapper.resolve_ish(x)
            symbs.append((pr, cs))

        # instruction analysis
        # 0x0807394c:  460e       mov r6, r1
        m2 = re.match(r'^\s*(0x[0-9a-fA-F]+):\s+([0-9a-fA-F]+)(?:\s+([0-9a-fA-F]+))?\s+(.+?)\s*$', line)
        if m2:
            instline = m2.group(4)
            instparts = instline.split(' ')
            inst = instparts[0]
            if inst.startswith('ldr'):
                if 'pc' == instparts[1]:
                    self.frame.pop()
            elif inst.startswith('pop'):
                if 'pc' in instline:
                    self.frame.pop()
            elif inst.startswith('bl'):
                self.frame.append(symbs[-1])
            elif inst == 'b':
                self.frame.append(symbs[-1])
            else:
                pass

        symbss = ', '.join([('%s%s' % ('?' if not x[0] else '', x[1].shortref() if x[1] else '?')) for x in symbs])
        ldiff = self.max_line_len - len(line)

        self.print_line(
            "%s%s |  %s"
            % (line, (" " * ldiff), symbss)
        )

    def read_files(self, files):
        for idx, line in enumerate(fileinput.input(files)):
            self.process(line)

    def process_maps(self):
        if not self.args.mmap:
            return
        for fl in self.args.mmap:
            self.mapper.add_map(fl)

    def main(self):
        parser = argparse.ArgumentParser(description="QEMU log reader and parser")
        parser.add_argument(
            "--map",
            dest="mmap",
            nargs="*",
            help="linker memory maps used for translation",
            default=[],
        )
        parser.add_argument(
            "--no-time",
            dest="no_time",
            default=False,
            action="store_const",
            const=True,
            help="Do not show time",
        )
        parser.add_argument(
            "--no-aug",
            dest="no_aug",
            default=False,
            action="store_const",
            const=True,
            help="Do not augment the log output",
        )
        parser.add_argument(
            "--tee", dest="tee", default=None, help="File to copy raw output to"
        )
        parser.add_argument(
            "--tee-aux",
            dest="tee_aux",
            default=False,
            action="store_const",
            const=True,
            help="Tee augmented lines",
        )
        parser.add_argument(
            "--tee-append",
            dest="tee_append",
            default=False,
            action="store_const",
            const=True,
            help="Append to the tee file",
        )
        parser.add_argument(
            "--no-ctl",
            dest="no_ctl",
            default=False,
            action="store_const",
            const=True,
            help="Removes shell control sequences",
        )
        parser.add_argument(
            "files",
            metavar="FILE",
            nargs="*",
            help="files to read, if empty, stdin is used",
        )
        args = parser.parse_args()

        self.args = args
        if args.tee:
            ex = os.path.exists(args.tee)
            if ex and not args.tee_append:
                raise ValueError("Tee file already exists")

            self.tee_file = open(args.tee, "w+" if not ex else "a+")
            if ex:
                self.tee_file.write(("=" * 80) + (" Time: %s" % time.time()))

        self.process_maps()
        try:
            self.read_files(args.files)

        except KeyboardInterrupt:
            logger.info("Terminating")

        if self.tee_file:
            self.tee_file.close()


def main():
    anz = QEMULogAnalyzer()
    anz.main()


if __name__ == "__main__":
    main()
