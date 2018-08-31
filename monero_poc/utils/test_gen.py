import fileinput
import re
import io
import argparse
import logging
import coloredlogs
import time
import asyncio
import sys
import binascii

from monero_serialize.helpers import ArchiveException

from monero_glue.xmr import wallet, crypto, monero
from monero_glue.xmr.sub.creds import AccountCreds

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.DEBUG, use_chroot=False)


class TestGen(object):
    def __init__(self):
        self.args = None
        self.dest_keys = None  # type: AccountCreds
        self.cur_keys = None  # type: AccountCreds
        self.cur_subs = {}

    async def process(self, idx, inp):
        is_stdin = False
        if inp == b"-":
            file = getattr(sys.stdin, "buffer", sys.stdin)
            is_stdin = True
        else:
            file = open(inp, "rb")

        try:
            logger.debug("Processing: %s" % inp)
            data = file.read()
            unsigned_tx = await wallet.load_unsigned_tx(self.cur_keys.view_key_private, data)
            new_unsigned = await self.process_unsigned(unsigned_tx)

            inp = new_unsigned.txes[0].sources[0]
            new_bin = await wallet.dump_unsigned_tx(self.dest_keys.view_key_private, new_unsigned)
            sys.stdout.buffer.write(new_bin)

        except ArchiveException as ae:
            logger.error(ae)
            logger.error(ae.tracker)

        finally:
            if not is_stdin:
                file.close()

    async def process_unsigned(self, unsigned_txs):
        for tx in unsigned_txs.txes:
            tx.use_bulletproofs = False
            logger.debug(
                "Transaction with %s inputs, %s oputpus, %s mix ring"
                % (len(tx.sources), len(tx.splitted_dsts), len(tx.sources[0].outputs))
            )

            for inp in tx.sources:
                self.rekey_input(inp, self.cur_keys, self.cur_subs, self.dest_keys)

        return unsigned_txs

    def rekey_input(self, inp, keys, subs=None, new_keys=None):
        subs = subs if subs else {}
        real_out_key = inp.outputs[inp.real_output][1]
        out_key = crypto.decodepoint(real_out_key.dest)
        tx_key = crypto.decodepoint(inp.real_out_tx_key)
        additional_keys = [
            crypto.decodepoint(x) for x in inp.real_out_additional_tx_keys
        ]

        logger.debug('Current out key: %s' % binascii.hexlify(real_out_key.dest))
        secs = monero.generate_key_image_helper(
            keys,
            subs,
            out_key,
            tx_key,
            additional_keys,
            inp.real_output_in_tx_index,
        )
        xi, ki, di = secs

        # rekey = new dst key, update just dst part of the output key
        if len(additional_keys) > 0:
            raise ValueError('Unsupported now')

        # real_out_key.dst = Hs(R*new_a || idx)G + newB
        new_deriv = crypto.generate_key_derivation(tx_key, new_keys.view_key_private)
        new_out_pr = crypto.derive_secret_key(new_deriv, inp.real_output_in_tx_index, new_keys.spend_key_private)
        new_out = crypto.scalarmult_base(new_out_pr)
        real_out_key.dest = crypto.encodepoint(new_out)
        logger.debug('New pub: %s' % binascii.hexlify(real_out_key.dest))

        # Self-check
        new_subs = {}
        self.precompute(new_keys, new_subs, 1, 10)
        secs = monero.generate_key_image_helper(
            new_keys,
            new_subs,
            crypto.decodepoint(real_out_key.dest),
            tx_key,
            additional_keys,
            inp.real_output_in_tx_index,
        )
        return inp

    def precompute(self, keys, subs, major_cnt=10, minor_cnt=200):
        for i in range(major_cnt):
            monero.compute_subaddresses(keys, i, list(range(0, minor_cnt)), subs)

    def parse_keys(self, keyvar, ktype="current"):
        if len(keyvar) != 2 * 2 * 32:
            raise ValueError(
                "Keys for the %s destination length invalid. Format: SpendKey || ViewKey hexcoded"
                % ktype
            )
        keys_bin = binascii.unhexlify(keyvar)
        spend_key = crypto.decodeint(keys_bin[:32])
        view_key = crypto.decodeint(keys_bin[32:64])

        return AccountCreds.new_wallet(view_key, spend_key)

    async def work(self):
        self.cur_keys = self.parse_keys(self.args.current)
        self.dest_keys = self.parse_keys(self.args.dest, "destination")
        self.precompute(self.cur_keys, self.cur_subs)

        files = self.args.files if self.args.files and len(self.args.files) else [b"-"]
        for idx, line in enumerate(files):
            await self.process(idx, line)

    async def main(self):
        parser = argparse.ArgumentParser(
            description="Test generator - changing unsigned transactions"
        )
        parser.add_argument(
            "--dest",
            default=None,
            required=True,
            help="Destination address to transform to",
        )
        parser.add_argument(
            "--current", type=None, required=True, help="Current destination address"
        )
        parser.add_argument(
            "files",
            metavar="FILE",
            nargs="*",
            help="files to read, if empty, stdin is used",
        )
        self.args = parser.parse_args()
        return await self.work()


async def amain():
    tgen = TestGen()
    res = await tgen.main()
    sys.exit(res)


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain())
    loop.close()


if __name__ == "__main__":
    main()
