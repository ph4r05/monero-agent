import fileinput
import re
import io
import argparse
import logging
import coloredlogs
import time

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)


TICKS_PER_SECOND = 1000000.


def tic2sec(tic):
    return tic/TICKS_PER_SECOND


class LogAnalyzer(object):
    def __init__(self):
        self.max_line_len = 0
        self.time_prev = 0
        self.time_ref = 0
        self.time_ref_r = 0
        self.mem_alloc_prev = 0
        self.mem_alloc_ref = None
        self.mem_alloc_max = 0
        self.serial_device = None

    def process(self, line):
        line = line.strip()
        m = re.match(r'^(\d+)\s([^\s]+?)\s([^\s]+?)\s(.*)$', line)
        if m is None:
            return

        ctime_r = time.time()
        ctime = int(m.group(1))
        c_prev = self.time_prev
        c_prev_alloc = self.mem_alloc_prev
        self.time_prev = ctime

        if '----diagnostic' in line:
            self.time_ref = ctime
            self.time_ref_r = ctime_r
            return

        self.max_line_len = max(self.max_line_len, min(len(line), 140))
        abs_time = tic2sec(ctime - self.time_ref)
        diff_time = tic2sec(ctime - c_prev)

        mem_free = None
        mem_alloc = None

        mmem = re.match(r'.+?F:\s*(\d+)\sA:\s*(\d+)', line)
        if mmem:
            mem_free = int(mmem.group(1))
            mem_alloc = int(mmem.group(2))

        mmem = re.match(r'.+?Free:\s*(\d+)\sAllocated:\s*(\d+)', line)
        if mmem:
            mem_free = int(mmem.group(1))
            mem_alloc = int(mmem.group(2))

        memstr = ''
        if mem_alloc:
            self.mem_alloc_prev = mem_alloc
            self.mem_alloc_max = max(self.mem_alloc_max, mem_alloc)
            if self.mem_alloc_ref is None:
                self.mem_alloc_ref = mem_alloc

            memstr = 'Alloc diff: %5d, refdi: %5d' % (mem_alloc - self.mem_alloc_ref, mem_alloc - c_prev_alloc)

        ldiff = self.max_line_len - len(line)
        print('%s%s |  AbsTime: %7.3f,   Diff %5.3f  | %s' % (line, ' '*ldiff, abs_time, diff_time, memstr))

        if '====' in line or '####' in line:
            abs_r = ''
            if self.serial_device:
                abs_time_r = ctime_r - self.time_ref_r
                abs_r = 'r: %7.2f, ticks p.s.: %7.3f' % (abs_time_r, (ctime - self.time_ref) / float(abs_time_r))
            print(' ++ TOTAL: %7.2f, %s mem max: %s' % (abs_time, abs_r, self.mem_alloc_max - self.mem_alloc_ref))

            self.time_ref = ctime
            self.time_ref_r = ctime_r
            if mem_alloc is not None:
                self.mem_alloc_ref = mem_alloc
                self.mem_alloc_max = mem_alloc

    def read_serial(self, device, brate):
        try:
            import serial  # pip install pyserial
        except ImportError:
            raise ValueError('pip install pyserial')

        while True:
            try:
                ser = serial.Serial(device, brate, timeout=.1)
                logger.info('Connected: %s' % ser)

                sio = io.TextIOWrapper(io.BufferedRWPair(ser, ser))
                while True:
                    line = sio.readline()
                    line = line.strip()
                    if len(line) == 0:
                        continue

                    self.process(line)

            except Exception as e:
                logger.warning('Exc: %s' % e)
                time.sleep(2)


    def read_files(self, files):
        for idx, line in enumerate(fileinput.input(files)):
            anz.process(line)

    def main(self):
        parser = argparse.ArgumentParser(description='Trezor log reader and parser')
        parser.add_argument('--serial', default=None, help='Serial device to read from')
        parser.add_argument('--brate', type=int, default=115200, help='Baud rate')
        parser.add_argument("--retry", dest="retry", default=True, action="store_const", const=True, help="Retry reconnect")
        parser.add_argument('files', metavar='FILE', nargs='*', help='files to read, if empty, stdin is used')
        args = parser.parse_args()

        if args.serial:
            self.serial_device = args.serial
            self.read_serial(args.serial, args.brate)
        else:
            self.read_files(args.files)


if __name__ == '__main__':
    anz = LogAnalyzer()
    anz.main()
