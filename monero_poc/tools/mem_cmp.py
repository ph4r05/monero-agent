import argparse
import logging
import re

import coloredlogs

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.INFO, use_chroot=False)


def avg(iterable):
    return sum(iterable) / float(len(iterable))


class MemReader(object):
    def __init__(self, data):
        self.data = data
        self.cline = -1

    def full_line(self):
        return self.data[self.cline]

    def next_section(self):
        offset = 0
        res = self.next_entry()
        if res is None:
            return None
        while not res[1]:
            offset += 1
            res = self.next_entry()
            if res is None:
                return None
        return res[0], res[1], offset

    def next(self, to_section=False):
        if to_section:
            return self.next_section()
        else:
            return self.next_entry()

    def next_entry(self):
        for i in range(self.cline + 1, len(self.data)):
            self.cline = i
            line = self.data[i]

            ma = re.match(r"^.*A:\s*(\d+).*", line)
            if ma is None:
                continue

            mfree = int(ma.group(1))
            is_section = "####" in line

            return mfree, is_section

        return None, None


class MemCompare(object):
    def __init__(self):
        self.args = None

    def read_files(self, files):
        file_data = []

        for idx, file in enumerate(files):
            with open(file) as fh:
                file_data.append(fh.readlines())

        if len(file_data) != 2:
            raise ValueError("Exactly 2 files are required")

        ma = MemReader(file_data[0])
        mb = MemReader(file_data[1])

        m_a_sec = []
        m_b_sec = []
        m_a_all = []
        m_b_all = []
        m_diffs_sec = []
        m_diffs_all = []

        while True:
            ar = ma.next()
            br = mb.next()
            a_off = 0
            b_off = 0

            # End
            if ar is None or br is None:
                if ar is None and br is not None:
                    logger.info("Source A ended before B")
                elif ar is not None and br is None:
                    logger.info("Source B ended before A")
                break

            # Align sections
            if ar[1] and not br[1]:
                br = mb.next_section()
                b_off = br[2]
                logger.info("Skipped %s mem lines from B" % b_off)

            elif not ar[1] and br[1]:
                ar = ma.next_section()
                a_off = ar[2]
                logger.info("Skipped %s mem lines from A" % a_off)

            m_a_all.append(ar[0])
            m_b_all.append(br[0])

            if ar[1]:
                m_a_sec.append(ar[0])
            if br[1]:
                m_b_sec.append(br[0])

            m_diffs_all.append(ar[0] - br[0])
            if ar[1] and br[1]:
                m_diffs_sec.append(ar[0] - br[0])

            if self.args.verbose:
                pass

        avg_all_a = avg(m_a_all)
        avg_all_b = avg(m_b_all)
        avg_sec_a = avg(m_a_sec)
        avg_sec_b = avg(m_b_sec)

        print("Diffs sec: %s" % avg(m_diffs_sec))
        print("Diffs all: %s\n" % avg(m_diffs_all))

        print(
            "Avg Sec A: %s  Sec B: %s  diff: %s   ratio:  %s"
            % (
                avg_sec_a,
                avg_sec_b,
                avg_sec_a - avg_sec_b,
                avg_sec_a / float(avg_sec_b),
            )
        )
        print(
            "Avg All A: %s  All B: %s  diff: %s   ratio:  %s"
            % (
                avg_all_a,
                avg_all_b,
                avg_all_a - avg_all_b,
                avg_all_a / float(avg_all_b),
            )
        )

    def main(self):
        parser = argparse.ArgumentParser(
            description="Compares two log files and used memory"
        )
        parser.add_argument(
            "--verbose",
            dest="verbose",
            default=False,
            action="store_const",
            const=True,
            help="Append to the tee file",
        )
        parser.add_argument(
            "files",
            metavar="FILE",
            nargs="*",
            help="files to read, if empty, stdin is used",
        )
        args = parser.parse_args()
        self.args = args

        try:
            self.read_files(args.files)

        except KeyboardInterrupt:
            logger.info("Terminating")


if __name__ == "__main__":
    anz = MemCompare()
    anz.main()
