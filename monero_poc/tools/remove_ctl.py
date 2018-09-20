import fileinput
import re
import argparse
import logging
import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)


class CtlRemover(object):
    def __init__(self):
        self.max_line_len = 0
        self.time_prev = 0
        self.time_ref = 0
        self.time_ref_r = 0
        self.mem_alloc_prev = 0
        self.mem_alloc_ref = None
        self.mem_alloc_max = 0
        self.serial_device = None
        self.tee_file = None

    def process(self, line):
        print(re.sub(r'\x1b\[\d+m', '', line.rstrip('\n')))

    def read_files(self, files):
        for idx, line in enumerate(fileinput.input(files)):
            anz.process(line)

    def main(self):
        parser = argparse.ArgumentParser(description='Removes shell controll sequences (e.g., colouring)')
        parser.add_argument('files', metavar='FILE', nargs='*', help='files to read, if empty, stdin is used')
        args = parser.parse_args()

        try:
            self.read_files(args.files)

        except KeyboardInterrupt:
            logger.info('Terminating')


if __name__ == '__main__':
    anz = CtlRemover()
    anz.main()
