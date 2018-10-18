import argparse
import fileinput
import logging
import re

import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)


def remove_ctl(line):
    return re.sub(r"\x1b\[\d+m", "", line.rstrip("\n"))


class CtlRemover(object):
    def __init__(self):
        pass

    def process(self, line):
        return remove_ctl(line)

    def read_files(self, files):
        for idx, line in enumerate(fileinput.input(files)):
            print(anz.process(line))

    def main(self):
        parser = argparse.ArgumentParser(
            description="Removes shell controll sequences (e.g., colouring)"
        )
        parser.add_argument(
            "files",
            metavar="FILE",
            nargs="*",
            help="files to read, if empty, stdin is used",
        )
        args = parser.parse_args()

        try:
            self.read_files(args.files)

        except KeyboardInterrupt:
            logger.info("Terminating")


if __name__ == "__main__":
    anz = CtlRemover()
    anz.main()
