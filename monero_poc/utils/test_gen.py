import re
import io
import os
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
        self.dest_subs = {}

        self.add_additionals = False
        self.dest_sub_major = 0
        self.dest_sub_minor = 0

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
            new_unsigned = await self.rekey_unsigned(unsigned_tx)

            new_bin = await wallet.dump_unsigned_tx(self.dest_keys.view_key_private, new_unsigned)

            if self.args.output:
                nbase = 'output.bin' if is_stdin else os.path.basename(inp)
                ndest = os.path.join(self.args.output, nbase)
                with open(ndest, 'wb') as fh:
                    fh.write(new_bin)
                logger.info('Result written to: %s' % ndest)

            else:
                sys.stdout.buffer.write(new_bin)

        except ArchiveException as ae:
            logger.error(ae)
            logger.error(ae.tracker)

        finally:
            if not is_stdin:
                file.close()

    async def rekey_unsigned(self, unsigned_txs):
        for tx in unsigned_txs.txes:
            tx.use_bulletproofs = False
            logger.debug(
                "Transaction with %s inputs, %s oputpus, %s mix ring"
                % (len(tx.sources), len(tx.splitted_dsts), len(tx.sources[0].outputs))
            )

            for inp in tx.sources:
                self.rekey_input(inp, self.cur_keys, self.cur_subs, self.dest_keys, self.dest_subs)

        return unsigned_txs

    def rekey_input(self, inp, keys, subs=None, new_keys=None, new_subs=None):
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

        need_additional = additional_keys and len(additional_keys) > 0
        is_dst_sub = self.dest_sub_major != 0 and self.dest_sub_minor != 0

        if is_dst_sub and self.add_additionals:
            need_additional = True

        if is_dst_sub:
            m = monero.get_subaddress_secret_key(new_keys.view_key_private, major=self.dest_sub_major, minor=self.dest_sub_minor)
            M = crypto.scalarmult_base(m)
            d = crypto.sc_add(m, new_keys.spend_key_private)
            D = crypto.point_add(new_keys.spend_key_public, M)
            C = crypto.scalarmult(D, new_keys.view_key_private)

        if not need_additional and not is_dst_sub:
            # real_out_key.dst = Hs(R*new_a || idx)G + newB
            r = crypto.random_scalar()
            tx_key = crypto.scalarmult_base(r)
            new_deriv = crypto.generate_key_derivation(new_keys.view_key_public, r)
            new_out_pr = crypto.derive_secret_key(new_deriv, inp.real_output_in_tx_index, new_keys.spend_key_private)
            new_out = crypto.scalarmult_base(new_out_pr)
            real_out_key.dest = crypto.encodepoint(new_out)

        elif not need_additional and is_dst_sub:
            # real_out_key.dst = Hs(r*C || idx)G + newB, R=rD
            r = crypto.random_scalar()
            tx_key = crypto.scalarmult(D, r)
            new_deriv = crypto.generate_key_derivation(C, r)
            new_out_pr = crypto.derive_secret_key(new_deriv, inp.real_output_in_tx_index, new_keys.spend_key_private)
            new_out = crypto.scalarmult_base(new_out_pr)
            real_out_key.dest = crypto.encodepoint(new_out)

        else:
            r = crypto.random_scalar()
            tx_key = crypto.scalarmult_base(r)

            gen_additionals = min(2, inp.real_output_in_tx_index + 1)
            if additional_keys is None or len(additional_keys) < gen_additionals:
                additional_keys = [crypto.scalarmult_base(crypto.random_scalar()) for _ in range(gen_additionals)]

            ri = crypto.random_scalar()
            if is_dst_sub:
                add_tx = crypto.scalarmult(D, ri)
                new_deriv = crypto.generate_key_derivation(C, ri)
                new_out_pr = crypto.derive_secret_key(new_deriv, inp.real_output_in_tx_index, d)
                new_out = crypto.scalarmult_base(new_out_pr)
                if not crypto.point_eq(new_out, crypto.derive_public_key(new_deriv, inp.real_output_in_tx_index, D)):
                    raise ValueError('Invalid txout computation')

            else:
                add_tx = crypto.scalarmult_base(ri)
                new_deriv = crypto.generate_key_derivation(new_keys.view_key_public, r)
                new_out_pr = crypto.derive_secret_key(new_deriv, inp.real_output_in_tx_index,
                                                      new_keys.spend_key_private)
                new_out = crypto.scalarmult_base(new_out_pr)

            additional_keys[inp.real_output_in_tx_index] = add_tx
            real_out_key.dest = crypto.encodepoint(new_out)

        inp.real_out_tx_key = crypto.encodepoint(tx_key)
        inp.real_out_additional_tx_keys = [crypto.encodepoint(x) for x in additional_keys]

        logger.debug('New pub: %s' % binascii.hexlify(real_out_key.dest))

        # Self-check
        secs = monero.generate_key_image_helper(
            new_keys,
            new_subs,
            crypto.decodepoint(real_out_key.dest),
            tx_key,
            additional_keys,
            inp.real_output_in_tx_index,
        )
        return inp

    def precompute_subaddr(self, keys, subs, major_cnt=10, minor_cnt=200):
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
        self.dest_sub_major = self.args.major
        self.dest_sub_minor = self.args.minor
        self.add_additionals = self.args.add_extra
        self.precompute_subaddr(self.cur_keys, self.cur_subs)
        self.precompute_subaddr(self.dest_keys, self.dest_subs)

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
            "--output",
            default=None,
            help="Output directory to write results to",
        )

        parser.add_argument(
            "--major",
            default=0,
            type=int,
            help="Destination major address index",
        )

        parser.add_argument(
            "--minor",
            default=0,
            type=int,
            help="Destination minor address index",
        )

        parser.add_argument('--add-extra', dest='add_extra', action='store_const', const=True, default=False,
                            help='Adds additional tx keys')

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
