#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Dusan Klinec, ph4r05, 2018

#
# Note pickling is used for message serialization.
# This is just for the prototyping & fast PoC, pickling wont be used in the production.
# Instead, protobuf messages will be defined and parsed to avoid malicious pickling.
#

import argparse
import asyncio
import binascii
import json
import logging
import os
import re
import sys
import threading
import time

from monero_glue.agent import agent_lite, agent_misc
from monero_glue.messages import DebugMoneroDiagRequest, GetEntropy, Entropy
from monero_glue.xmr import common, crypto, monero, wallet, wallet_rpc
from monero_glue.xmr.enc import chacha_poly, chacha
from monero_poc.utils import misc, trace_logger
from monero_poc.utils import cli
from monero_poc.utils.trezor_server_proxy import TokenProxy
from monero_serialize import xmrtypes, xmrserialize, xmrboost

import coloredlogs
from cmd2 import Cmd

logger = logging.getLogger(__name__)
coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.WARNING, use_chroot=False)


class HostAgent(cli.BaseCli):
    """
    Host agent wrapper
    """

    prompt = "$> "

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.args = None

        self.network_type = None
        self.address = None
        self.priv_view = None
        self.pub_view = None
        self.pub_spend = None
        self.network_type = None
        self.wallet_salt = None
        self.wallet_password = b""
        self.wallet_file = None
        self.monero_bin = None
        self.rpc_addr = "127.0.0.1:18081"
        self.rpc_passwd = None
        self.rpc_bind_port = 48084
        self.rpc_running = False

        self.trace_logger = trace_logger.Tracelogger(logger)
        self.loop = asyncio.get_event_loop()
        self.worker_loop = asyncio.new_event_loop()
        self.worker_thread = threading.Thread(
            target=self.looper, args=(self.worker_loop,)
        )
        self.worker_thread.setDaemon(True)
        self.worker_thread.start()
        self.wallet_thread = None
        self.terminating = False

        self.trezor_proxy = None  # type: TokenProxy
        self.agent = None  # type: agent_lite.Agent
        self.token_debug = False
        self.token_path = None

        self.wallet_proxy = wallet_rpc.WalletRpc(
            self, self.rpc_bind_port, self.rpc_passwd
        )

    def looper(self, loop):
        """
        Main looper
        :param loop:
        :return:
        """
        asyncio.set_event_loop(loop)
        loop.run_forever()

    def submit_coro(self, coro):
        """
        Submits corroutine to the worker loop
        :param fnc:
        :param args:
        :param kwargs:
        :return:
        """
        return asyncio.run_coroutine_threadsafe(coro, self.worker_loop)

    def wait_coro(self, coro):
        """
        Runs corouting, waits for result
        :param fnc:
        :param args:
        :param kwargs:
        :return:
        """
        future = self.submit_coro(coro)
        return future.result()

    #
    # CLI
    #

    def update_intro(self):
        """
        Updates intro text for CLI header - adds version to it.
        :return:
        """
        self.intro = (
            "-" * self.get_term_width()
            + "\n    Monero Trezor agent\n"
            + "\n"
            + "-" * self.get_term_width()
        )

    def update_prompt(self):
        """
        Prompt update
        :return:
        """
        rpc_flag = "" if self.rpc_running else "R!"
        flags = [rpc_flag]
        flags_str = "|".join(flags)
        flags_suffix = "|" + flags_str if len(flags_str) > 0 else ""

        self.prompt = "[wallet %s%s]: " % (
            self.address[:6].decode("ascii"),
            flags_suffix,
        )

    def token_cmd(self, coro):
        try:
            res = self.wait_coro(coro)
            return res

        except Exception as e:
            print("Trezor not connected (e: %s)" % e)
            self.trace_logger.log(e)

    #
    # Handlers
    #

    def do_quit(self, line):
        self.terminating = True
        return super().do_quit(line)

    do_q = do_quit
    do_Q = do_quit

    def do_address(self, line):
        print(self.address.decode("ascii"))

    def do_ping(self, line):
        pres = self.token_cmd(self.trezor_proxy.ping())
        if pres:
            print("OK %s" % pres)

    def do_get_watch_only(self, line):
        pres = self.token_cmd(self.agent.get_watch_only())
        print("View key:  %s" % binascii.hexlify(pres.watch_key).decode("utf8"))
        print("Address:   %s" % pres.address.decode("utf8"))

    def do_get_address(self, line):
        pres = self.token_cmd(self.agent.get_address())
        print("Address:   %s" % pres.address.decode("utf8"))

    def do_balance(self, line):
        res = self.wallet_proxy.balance()
        print("Balance: %.5f" % wallet.conv_disp_amount(res["result"]["balance"]))
        print(
            "Unlocked Balance: %.5f"
            % wallet.conv_disp_amount(res["result"]["unlocked_balance"])
        )

    def do_height(self, line):
        res = self.wallet_proxy.height()
        print("Height: %s" % res["result"]["height"])

    def do_get_transfers(self, line):
        res = self.wallet_proxy.get_transfers({"pool": True, "in": True, "out": True})
        print(json.dumps(res, indent=2))

    def do_rescan_bc(self, line):
        res = self.wallet_proxy.rescan_bc()
        print(json.dumps(res, indent=2))

    def do_key_image_sync(self, line):
        self.wait_coro(self.key_image_sync(line))

    def do_refresh(self, line):
        res = self.wallet_proxy.refresh()
        print(json.dumps(res, indent=2))

    def do_transfer(self, line):
        if len(line) == 0:
            print(
                "Usage: transfer [<priority>] [<ring_size>] <address> <amount> [<payment_id>]"
            )
        parts = [x for x in line.split(" ") if len(x.strip()) > 0]

        res = misc.parse_transfer_cmd(parts)
        return self.transfer_cmd(res)

    def do_sign(self, line):
        self.wait_coro(self.sign_wrap(line))

    def do_init(self, line):
        mnemonic12 = "alcohol woman abuse must during monitor noble actual mixed trade anger aisle"
        mnemonic24 = "permit universe parent weapon amused modify essay borrow tobacco budget walnut lunch consider gallery ride amazing frog forget treat market chapter velvet useless topple"

        mnemonic = mnemonic12 if len(line) == 0 or int(line) == 0 else mnemonic24
        self.trezor_proxy.client.wipe_device()
        self.trezor_proxy.client.load_device_by_mnemonic(
            mnemonic=mnemonic,
            pin="",
            passphrase_protection=False,
            label="ph4test",
            language="english",
        )

    def do_get_entropy(self, line):
        parts = line.split(' ')
        size = int(parts[0])
        path = parts[1]
        self.wait_coro(self.get_entropy(size, path))

    def do_tdeb(self, line):
        is_deb = bool(int(line))
        print("Token debug set to: %s" % is_deb)
        self.token_debug = is_deb

    def do_switch(self, line):
        path = "bridge:web01"
        if line == "udp":
            path = "udp:127.0.0.1:21324"
        elif ':' in line:
            path = line

        if 'bridge' in path:
            self.token_debug = False

        print("Switching to device: %s" % path)
        self.token_path = path
        self.wait_coro(self.connect(path))

    def do_reconnect(self, line):
        self.wait_coro(self.connect())

    def do_enumerate(self, line):
        from monero_glue.trezor import manager as tmanager
        r = tmanager.Trezor.enumerate()
        for x in r:
            print(x)

    def do_diag(self, line):
        diag_code = int(line)
        print("Diagnosis: %d" % diag_code)
        msg = DebugMoneroDiagRequest(ins=diag_code)
        try:
            resp = self.wait_coro(self.trezor_proxy.call(msg))
            print(resp)

        except Exception as e:
            self.trace_logger.log(e)
            logger.warning(e)

    complete_sign = Cmd.path_complete

    #
    # Logic
    #

    def set_network_type(self, ntype):
        self.network_type = ntype
        self.agent.network_type = ntype

    async def is_connected(self):
        """
        Returns True if Trezor is connected
        :return:
        """
        try:
            await self.trezor_proxy.ping()
            return True

        except Exception as e:
            return False

    async def load_watchonly(self):
        """
        Loads watch-only credentials from connected Trezor
        :return:
        """
        if not await self.is_connected():
            logger.error("Trezor is not connected")
            raise agent_misc.TrezorNotRunning("Could not load watch-only credentials")

        try:
            print(
                "Loading watch-only credentials from Trezor. Please, confirm the request on Trezor."
            )
            self.set_network_type(
                monero.NetworkTypes.TESTNET
                if self.args.testnet
                else monero.NetworkTypes.MAINNET
            )

            res = await self.agent.get_watch_only()  # type: messages.MoneroWatchKey

            self.priv_view = crypto.decodeint(res.watch_key)
            self.address = res.address
            await self.open_with_keys(self.priv_view, self.address)

        except Exception as e:
            raise ValueError(e)

    async def get_entropy(self, size, path):
        """
        Loads entropy from the device, writes to the path
        :param size:
        :param path:
        :return:
        """
        logger.info('Loading entropy of %s B to %s' % (size, path))
        with open(path, 'wb+') as fh:
            csize = 0
            while csize < size:
                req = GetEntropy(size=1024*10)
                res = await self.trezor_proxy.call_in_session(req)  # type: Entropy
                csize += len(res.entropy)
                logger.debug(' .. loaded %s / %s (%s %%)' % (csize, size, 100.0*csize / size))
                fh.write(res.entropy)
        logger.info('Entropy loading done')

    def load_params(self):
        """
        Args
        :return:
        """
        if self.args.rpc_addr:
            self.rpc_addr = self.args.rpc_addr
        if self.args.watch_wallet:
            self.wallet_file = self.args.watch_wallet
        if self.args.monero_bin:
            self.monero_bin = self.args.monero_bin

    async def connect(self, path=None):
        """
        Connects to the trezor
        :return:
        """
        if self.args.trezor or self.args.trezor_path or path:
            from monero_glue.trezor import manager as tmanager

            self.trezor_proxy = tmanager.Trezor(
                path=path if path else self.args.trezor_path, debug=self.token_debug
            )

        else:
            self.trezor_proxy = TokenProxy()

        ntype = self.agent.network_type if self.agent else self.network_type
        self.agent = agent_lite.Agent(self.trezor_proxy, network_type=ntype)

    async def open_account(self):
        """
        Opens the watch only account
        :return:
        """
        creds_passed = self.args.view_key is not None and self.args.address is not None
        account_file_set = self.args.account_file is not None
        account_file_ex = (
            os.path.exists(self.args.account_file) if account_file_set else False
        )

        if creds_passed:
            await self.open_account_passed()
        elif account_file_ex:
            await self.open_account_file(self.args.account_file)
        else:
            self.load_params()
            await self.check_params(True)
            await self.load_watchonly()

        self.load_params()
        if account_file_set and not account_file_ex:
            await self.check_params(True)
            self.wallet_password = await self.prompt_password(True)

        # Create watch only wallet file for monero-wallet-rpc
        await self.ensure_watch_only()

        # Write acquired data to the account file
        if account_file_set and not account_file_ex:
            await self.save_account(self.args.account_file)

        print(
            "Public spend key: %s"
            % binascii.hexlify(crypto.encodepoint(self.pub_spend)).decode("ascii")
        )
        print(
            "Public view key : %s"
            % binascii.hexlify(crypto.encodepoint(self.pub_view)).decode("ascii")
        )
        print("Address:          %s" % self.address.decode("utf8"))
        self.update_intro()
        self.update_prompt()

    async def check_params(self, new_wallet=False):
        """
        All params correctly entered?
        :return:
        """
        if not new_wallet:
            return
        if self.args.sign is not None:
            return
        if self.wallet_file is None:
            logger.error(
                "--watch-wallet file is not set. Please specify path where to create the monero watch wallet"
            )
            sys.exit(1)
        if self.monero_bin is None:
            logger.error(
                "--monero-bin is not set. Please specify path to the monero binaries"
            )
            sys.exit(1)

    async def prompt_password(self, new_wallet=False):
        """
        Prompts password for a new wallet
        :param new_wallet:
        :return:
        """
        if new_wallet:
            passwd = self.ask_password(
                "Creating a new wallet. Please, enter the password: ", True
            )
        else:
            passwd = self.ask_password("Please, enter the wallet password: ", False)
        return passwd.encode("utf8")

    async def save_account(self, file):
        """
        Stores account data
        :param file:
        :return:
        """
        if self.wallet_salt is None:
            self.wallet_salt = crypto.random_bytes(32)

        # Wallet view key encryption
        wallet_enc_key = misc.wallet_enc_key(self.wallet_salt, self.wallet_password)
        ciphertext = chacha_poly.encrypt_pack(wallet_enc_key, crypto.encodeint(self.priv_view))

        with open(file, "w") as fh:
            data = {
                "view_key_enc": binascii.hexlify(ciphertext).decode("ascii"),
                "address": self.address.decode("ascii"),
                "network_type": self.network_type,
                "wallet_salt": binascii.hexlify(self.wallet_salt).decode("ascii"),
                "rpc_addr": self.rpc_addr,
                "wallet_file": self.wallet_file,
                "monero_bin": self.monero_bin,
            }
            json.dump(data, fh, indent=2)

    async def check_existing_wallet_file(self, key_file):
        """
        Checks existing wallet file correctness
        :param key_file:
        :return:
        """
        wl = await wallet.load_keys_file(key_file, self.wallet_password)
        addr = wl["key_data"]["m_keys"]["m_account_address"]
        spend_pub = addr["m_spend_public_key"]
        view_pub = addr["m_view_public_key"]

        match = spend_pub == crypto.encodepoint(
            self.pub_spend
        ) and view_pub == crypto.encodepoint(self.pub_view)
        net_ver = monero.net_version(self.network_type, False)
        addr = monero.encode_addr(net_ver, spend_pub, view_pub)
        return addr, match

    async def ensure_watch_only(self):
        """
        Ensures watch only wallet for monero exists
        :return:
        """
        if self.wallet_file is None:
            return

        key_file = "%s.keys" % self.wallet_file
        if os.path.exists(key_file):
            logger.debug("Watch only wallet key file exists: %s" % key_file)
            match, addr = False, None
            try:
                addr, match = await self.check_existing_wallet_file(key_file)
            except Exception as e:
                logger.error("Wallet key file processing exception: %s" % e)

            if not match:
                logger.error("Key file address is not correct: %s" % addr)
                print("Please, move the file so Agent can create correct key file")
                sys.exit(2)
            return

        account_keys = xmrtypes.AccountKeys()
        key_data = wallet.WalletKeyData()

        wallet_data = wallet.WalletKeyFile()
        wallet_data.key_data = key_data
        wallet_data.watch_only = 1
        wallet_data.testnet = self.network_type == monero.NetworkTypes.TESTNET

        key_data.m_creation_timestamp = int(time.time())
        key_data.m_keys = account_keys

        account_keys.m_account_address = xmrtypes.AccountPublicAddress(
            m_spend_public_key=crypto.encodepoint(self.pub_spend),
            m_view_public_key=crypto.encodepoint(self.pub_view),
        )
        account_keys.m_spend_secret_key = crypto.encodeint(crypto.sc_0())
        account_keys.m_view_secret_key = crypto.encodeint(self.priv_view)

        await wallet.save_keys_file(key_file, self.wallet_password, wallet_data)
        logger.debug("Watch-only wallet keys generated: %s" % key_file)

    async def open_account_passed(self):
        """
        Loads passed credentials
        :return:
        """
        priv_view = self.args.view_key.encode("ascii")
        self.priv_view = crypto.b16_to_scalar(priv_view)
        self.address = self.args.address.encode("ascii")
        self.set_network_type(
            monero.NetworkTypes.TESTNET
            if self.args.testnet
            else monero.NetworkTypes.MAINNET
        )
        self.wallet_file = self.args.watch_wallet
        self.monero_bin = self.args.monero_bin
        await self.open_with_keys(self.priv_view, self.address)

    async def open_account_file(self, file):
        """
        Opens account file
        :param file:
        :return:
        """
        with open(file) as fh:
            js = json.load(fh)

        # Wallet key encryption
        self.wallet_password = await self.prompt_password()
        self.wallet_salt = common.defvalkey(js, "wallet_salt")
        if self.wallet_salt is None:
            self.wallet_salt = crypto.random_bytes(32)
        else:
            self.wallet_salt = binascii.unhexlify(self.wallet_salt)

        # Wallet view key dec.
        if "view_key" in js:
            self.priv_view = crypto.b16_to_scalar(js["view_key"].encode("utf8"))

        elif "view_key_enc" in js:
            wallet_enc_key = misc.wallet_enc_key(self.wallet_salt, self.wallet_password)
            plain = chacha_poly.decrypt_pack(wallet_enc_key, binascii.unhexlify(js["view_key_enc"]))
            self.priv_view = crypto.decodeint(plain)

        self.address = js["address"].encode("utf8")
        self.wallet_file = js["wallet_file"]
        self.monero_bin = js["monero_bin"]
        self.set_network_type(js["network_type"])
        self.rpc_addr = js["rpc_addr"]

        await self.open_with_keys(self.priv_view, self.address)

    async def open_with_keys(self, view_key, address):
        """
        Processess view key private + address
        :param view_key:
        :param address:
        :return:
        """
        self.pub_view = crypto.scalarmult_base(view_key)

        version, pub_spend, pub_view = monero.decode_addr(address)
        self.pub_spend = crypto.decodepoint(pub_spend)

        if not crypto.point_eq(self.pub_view, crypto.decodepoint(pub_view)):
            raise ValueError(
                "Computed view public key does not match the one from address"
            )

    def wallet_rpc_main(self, *args, **kwargs):
        """
        Wallet RPC thread
        :return:
        """
        rpc_cmd = os.path.join(self.monero_bin, "monero-wallet-rpc")
        if not os.path.exists(rpc_cmd):
            logger.error("Wallet rpc binary not found: %s" % rpc_cmd)
            sys.exit(1)

        self.rpc_passwd = misc.gen_simple_passwd(16)
        self.wallet_proxy.set_creds(["trezor", self.rpc_passwd])

        # TODO: pass via config-file. Passwords visible via proclist. ideally ENV VARS
        args = [
            "--daemon-address %s" % misc.escape_shell(self.rpc_addr),
            "--wallet-file %s" % misc.escape_shell(self.wallet_file),
            "--password %s" % misc.escape_shell(self.wallet_password),
            "--rpc-login=%s" % ("trezor:%s" % self.rpc_passwd),
            "--rpc-bind-port %s" % int(self.rpc_bind_port),
        ]

        if self.args.testnet or self.network_type == monero.NetworkTypes.TESTNET:
            args.append("--testnet")

        cmd = "%s %s" % (rpc_cmd, " ".join(args))

        feeder = misc.Feeder()
        p = misc.run(
            cmd,
            input=feeder,
            async_=True,
            stdout=misc.Capture(timeout=1, buffer_size=1),
            stderr=misc.Capture(timeout=1, buffer_size=1),
            cwd=os.getcwd(),
            env=None,
            shell=True,
        )

        ret_code = 1
        out_acc, err_acc = [], []
        try:
            self.rpc_running = True
            self.update_prompt()
            while len(p.commands) == 0:
                time.sleep(0.15)

            while p.commands[0].returncode is None:
                out, err = p.stdout.read(1), p.stderr.read(1)
                if not common.is_empty(out):
                    out_acc.append(out.decode("utf8"))
                if not common.is_empty(err):
                    err_acc.append(err.decode("utf8"))

                p.commands[0].poll()
                if self.terminating and p.commands[0].returncode is None:
                    feeder.feed("quit\n\n")
                    misc.sarge_sigint(p.commands[0])
                    p.close()

                time.sleep(0.01)
            ret_code = p.commands[0].returncode
            out_acc = misc.add_readlines(p.stdout.readlines(), out_acc)
            err_acc = misc.add_readlines(p.stderr.readlines(), err_acc)
            self.rpc_running = False
            self.update_prompt()

            if not self.terminating:
                logger.error("Wallet RPC ended prematurely with code: %s" % ret_code)
                logger.info("Command: %s" % cmd)
                logger.info("Std out: %s" % "".join(out_acc))
                logger.info("Error out: %s" % "".join(err_acc))

        except Exception as e:
            logger.error("Exception in wallet RPC command: %s" % e)
            self.trace_logger.log(e)

    def shutdown_rpc(self):
        """
        Waits for rpc shutdown
        :return:
        """
        if self.args.wallet_rpc_addr:  # using already running rpc
            return
        if not self.rpc_running:
            return

        # Gracegul stop with save
        try:
            self.wallet_proxy.stop_wallet()
            self.terminating = True
            time.sleep(1)
        except Exception as e:
            logger.warning("Stopping wallet failed: %s" % e)

        # Terminating with sigint
        logger.info("Waiting for wallet-RPC to terminate...")
        self.terminating = True
        while self.rpc_running:
            time.sleep(0.1)

    async def wallet_rpc(self):
        """
        Starts wallet RPC server
        :return:
        """
        if self.args.wallet_rpc_addr:  # using existing RPC?
            self.wallet_proxy.set_addr(self.args.wallet_rpc_addr)
            self.wallet_proxy.set_creds(self.args.wallet_rpc_creds)
            self.rpc_running = True
            self.update_prompt()
            return

        self.wallet_thread = threading.Thread(target=self.wallet_rpc_main, args=(None,))
        self.wallet_thread.setDaemon(False)
        self.wallet_thread.start()

    async def entry(self):
        """
        Entry point
        :return:
        """
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG, use_chroot=False)
        misc.install_sarge_filter()

        await self.connect()
        await self.open_account()

        if self.args.sign:
            res = await self.sign_wrap(self.args.sign)
            return res if isinstance(res, int) else 0

        await self.wallet_rpc()

        self.update_intro()
        self.cmdloop()
        self.shutdown_rpc()
        logger.info("Terminating")

    #
    # Sign op
    #

    def transfer_cmd(self, parts):
        """
        Transfer logic
        :param parts:
        :return:
        """
        priority, mixin, address, amount, payment_id = parts
        try:
            address_b = address.encode("ascii")
            version, pub_spend_key, pub_view_key = monero.decode_addr(address_b)

        except Exception as e:
            print("Address invalid: %s " % address)
            return

        print("Sending %s monero to %s" % (amount, address))
        print(
            "Priority: %s, mixin: %s, payment_id: %s"
            % (
                priority if priority else "default",
                mixin if mixin else "default",
                payment_id,
            )
        )

        ask_res = self.ask_proceed_quit("Do you confirm (y/n) ? ")
        if ask_res != self.PROCEED_YES:
            return

        params = {
            "destinations": [
                {
                    "amount": int((10 ** monero.DISPLAY_DECIMAL_POINT) * amount),
                    "address": address,
                }
            ],
            "account_index": 0,
            "subaddr_indices": [],
            "unlock_time": 0,
            "get_tx_keys": True,
            "do_not_relay": True,
            "get_tx_hex": False,
            "get_tx_metadata": False,
        }
        if priority is not None:
            params["priority"] = priority

        if mixin is not None:
            params["mixin"] = mixin

        if payment_id is not None:
            params["payment_id"] = payment_id

        # Call RPC to prepare unsigned transaction
        self.transfer_params(params)

    def transfer_params(self, params):
        res = self.wallet_proxy.transfer(params)
        if "result" not in res:
            logger.error("Transfer error: %s" % res)
            raise ValueError("Could not transfer")

        result = res["result"]
        print("Fee: %s" % wallet.conv_disp_amount(result["fee"]))

        ask_res = self.ask_proceed_quit("Do you confirm (y/n) ? ")
        if ask_res != self.PROCEED_YES:
            return

        if "unsigned_txset" not in result:
            logger.error(
                "Unsigned transaction not found in the response. "
                "Please make sure you are using compatible monero-wallet-rpc"
            )
            logger.debug(res)
            return

        unsigned = binascii.unhexlify(result["unsigned_txset"])
        self.wait_coro(self.sign_unsigned(unsigned))

    async def sign_unsigned(self, unsigned_txset):
        """
        Signs unsigned txset with the Trezor
        :param unsigned_txset:
        :return:
        """
        res = await self.sign_wrap(fdata=unsigned_txset)
        if isinstance(res, int):
            logger.error("Error")
            return

        print("Transaction has been signed. ")
        ask_res = self.ask_proceed_quit("Do you wish to submit (y/n) ? ")
        if ask_res != self.PROCEED_YES:
            return

        params = {"tx_data_hex": binascii.hexlify(res).decode("ascii")}

        res = self.wallet_proxy.submit_transfer(params)
        try:
            if len(res["result"]["tx_hash_list"]) == 0:
                raise ValueError("Transaction submit failed")

            print("SUCCESS: Transaction has been submitted!")

        except Exception as e:
            logger.debug("Res: %s" % res)
            print("Transaction submit failed: %s" % e)

    async def sign_wrap(self, file=None, fdata=None):
        """
        Sign wrapper
        :param file:
        :param fdata:
        :return:
        """
        if not self.priv_view:
            logger.error("View key not set, cannot sign")
            return -3

        try:
            return await self.sign(file, fdata)

        except agent_misc.TrezorReturnedError as e:
            self.trace_logger.log(e)
            print("Trezor returned an error: %s" % e)
            return 1

        except agent_misc.TrezorNotRunning as e:
            logger.error("Trezor server is not running")
            return 2

    async def sign(self, file=None, fdata=None):
        """
        Performs TX signature
        :param file:
        :param fdata:
        :return:
        """
        try:
            await self.trezor_proxy.ping()
        except Exception as e:
            raise agent_misc.TrezorNotRunning(e)

        if file and not os.path.exists(file):
            raise ValueError("Could not find unsigned transaction file")

        data = fdata
        if data is None:
            with open(file, "rb") as fh:
                data = fh.read()

        msg = await wallet.load_unsigned_tx(self.priv_view, data)

        # Key image sync
        # key_images = await self.agent.import_outputs(msg.transfers)
        # For now sync only spent key images to the hot wallet.
        key_images = [td.m_key_image for td in msg.transfers]
        max_ki_size = 0
        if len(key_images) == 0:
            logger.info('Wallet did not return transfer list :/')
            for tx in msg.txes:
                for idx in range(len(tx.selected_transfers)):
                    max_ki_size = max(max_ki_size, tx.selected_transfers[idx])
            key_images = [b'\x01' + b'\x00'*31] * (max_ki_size + 1)

        txes = []
        pendings = []
        for tx in msg.txes:  # type: xmrtypes.TxConstructionData
            print("Signing transaction with Trezor")
            print("Please check the Trezor and confirm / reject the transaction\n")

            res = await self.agent.sign_transaction_data(tx)
            cdata = self.agent.last_transaction_data()
            await self.store_cdata(cdata, res, tx, msg.transfers)

            # obj = await xmrobj.dump_message(None, res)
            # print(xmrjson.json_dumps(obj, indent=2))

            # Key image sync for spent TXOs
            # Updating only spent.
            for idx in range(len(tx.selected_transfers)):
                idx_mapped = cdata.source_permutation[idx]
                key_images[tx.selected_transfers[idx_mapped]] = res.vin[idx].k_image

            txes.append(await self.agent.serialize_tx(res))
            pending = wallet.construct_pending_tsx(res, tx)
            pendings.append(pending)

        # Key images array has to cover all transfers sent.
        # Watch only wallet does not have key images.
        signed_tx = xmrtypes.SignedTxSet(ptx=pendings, key_images=key_images)
        signed_data = await wallet.dump_signed_tx(self.priv_view, signed_tx)
        with open("signed_monero_tx", "wb+") as fh:
            fh.write(signed_data)
            print("Signed transaction file: signed_monero_tx")

        print(
            "Key images: %s"
            % [binascii.hexlify(ff).decode("utf8") for ff in key_images]
        )
        for idx, tx in enumerate(txes):
            fname = "transaction_%02d" % idx
            with open(fname, "wb+") as fh:
                fh.write(tx)

            # relay_fname = 'transaction_%02d_relay.sh' % idx
            # hex_ctx = binascii.hexlify(tx).decode('utf8')
            # with open(relay_fname, 'w+') as fh:
            #     fh.write('#!/bin/bash\n')
            #     fh.write('curl -X POST http://%s/sendrawtransaction '
            #              '-d \'{"tx_as_hex":"%s", "do_not_relay":false}\' '
            #              '-H \'Content-Type: application/json\'\n' % (self.args.rpc_addr, hex_ctx))
            #
            # print('Transaction %02d stored to %s, relay script: %s' % (idx, fname, relay_fname))

            # Relay:
            # payload = {'tx_as_hex': hex_ctx, 'do_not_relay': False}
            # resp = requests.post('http://%s/sendrawtransaction' % (self.args.rpc_addr, ), json=payload)
            # print('Relay response: %s' % resp.json())

        # print('Please note that by manual relaying hot wallet key images get out of sync')
        return signed_data

    async def store_cdata(self, cdata, signed_tx, tx, transfers):
        """
        Stores transaction data for later usage.
            - cdata.enc_salt1, cdata.enc_salt2, cdata.enc_keys
            - tx_keys are AEAD protected, key derived from spend key - only token can open.
            - construction data for further proofs.

        :param cdata:
        :param signed_tx:
        :param tx:
        :param transfers:
        :return:
        """
        hash = cdata.tx_prefix_hash
        prefix = binascii.hexlify(hash[:12])

        tx_key_salt = crypto.random_bytes(32)
        tx_key_inp = hash + crypto.encodeint(self.priv_view)
        tx_view_key = crypto.pbkdf2(tx_key_inp, tx_key_salt, 2048)

        unsigned_data = xmrtypes.UnsignedTxSet()
        unsigned_data.txes = [tx]
        unsigned_data.transfers = transfers if transfers is not None else []

        writer = xmrserialize.MemoryReaderWriter()
        ar = xmrboost.Archive(writer, True)
        await ar.root()
        await ar.message(unsigned_data)

        unsigned_key = crypto.keccak_2hash(b'unsigned;' + tx_view_key)
        ciphertext = chacha_poly.encrypt_pack(unsigned_key, bytes(writer.get_buffer()))

        # Serialize signed transaction
        writer = xmrserialize.MemoryReaderWriter()
        ar = xmrserialize.Archive(writer, True)
        await ar.root()
        await ar.message(signed_tx)
        signed_tx_bytes = writer.get_buffer()
        signed_tx_hmac_key = crypto.keccak_2hash(b'hmac;' + tx_view_key)
        signed_tx_hmac = crypto.compute_hmac(signed_tx_hmac_key, signed_tx_bytes)

        try:
            js = {
                "time": int(time.time()),
                "hash": binascii.hexlify(hash).decode("ascii"),
                "enc_salt1": binascii.hexlify(cdata.enc_salt1).decode("ascii"),
                "enc_salt2": binascii.hexlify(cdata.enc_salt2).decode("ascii"),
                "tx_keys": binascii.hexlify(cdata.enc_keys).decode("ascii"),
                "unsigned_data": binascii.hexlify(ciphertext).decode("ascii"),
                "tx_salt": binascii.hexlify(tx_key_salt).decode("ascii"),
                "tx_signed": binascii.hexlify(signed_tx_bytes).decode("ascii"),
                "tx_signed_hmac": binascii.hexlify(signed_tx_hmac).decode("ascii"),
            }

            with open("transaction_%s.json" % prefix.decode("ascii"), "w") as fh:
                json.dump(js, fh, indent=2)
                fh.write("\n")

        except Exception as e:
            self.trace_logger.log(e)
            print(
                "Unable to save transaction data for transaction %s"
                % binascii.hexlify(hash).decode("ascii")
            )

    async def key_image_sync(self, line):
        """
        Key image sync with Trezor
        :param line:
        :return:
        """
        res = self.wallet_proxy.export_outputs()
        outputs_data_hex = res["result"]["outputs_data_hex"]

        outs_data = binascii.unhexlify(outputs_data_hex)
        exps = await wallet.load_exported_outputs(self.priv_view, outs_data)

        # Check if for this address
        match = exps.m_spend_public_key == crypto.encodepoint(
            self.pub_spend
        ) and exps.m_view_public_key == crypto.encodepoint(self.pub_view)
        net_ver = monero.net_version(self.network_type, False)
        addr = monero.encode_addr(
            net_ver, exps.m_spend_public_key, exps.m_view_public_key
        )
        if not match:
            logger.error(
                "Exported outputs from different wallet: %s" % addr.decode("ascii")
            )
            return

        self.poutput("Exported outputs loaded.")
        self.poutput("Please confirm the key image sync on the Trezor ")
        res = await self.agent.import_outputs(exps.tds)

        # Generate import key image requests
        key_images = []
        for kie in res:
            key_images.append(
                {
                    "key_image": binascii.hexlify(kie[0]).decode("ascii"),
                    "signature": binascii.hexlify(kie[1][0] + kie[1][1]).decode(
                        "ascii"
                    ),
                }
            )

        import_req = {"signed_key_images": key_images}

        res = self.wallet_proxy.import_key_images(import_req)
        print("Height: %s" % res["result"]["height"])
        print("Spent: %.5f" % wallet.conv_disp_amount(res["result"]["spent"]))
        print("Unspent: %.5f" % wallet.conv_disp_amount(res["result"]["unspent"]))

    async def main(self):
        """
        Entry point
        :return:
        """
        parser = argparse.ArgumentParser(description="Trezor Agent")

        parser.add_argument("--address", dest="address", help="Full address")

        parser.add_argument(
            "--view-key", dest="view_key", help="Hex coded private view key"
        )

        parser.add_argument(
            "--account-file",
            dest="account_file",
            help="Account file with watch-only creds",
        )

        parser.add_argument(
            "--watch-wallet", dest="watch_wallet", help="Watch-only wallet files"
        )

        parser.add_argument(
            "--monero-bin", dest="monero_bin", help="Directory with monero binaries"
        )

        parser.add_argument(
            "--rpc-addr", dest="rpc_addr", default=None, help="RPC address of full node"
        )

        parser.add_argument(
            "--rpc-wallet",
            dest="wallet_rpc_addr",
            default=None,
            help="Use running monero-wallet-rpc",
        )

        parser.add_argument(
            "--rpc-wallet-creds",
            dest="wallet_rpc_creds",
            default=None,
            help="Running monero-wallet-rpc credentials",
        )

        parser.add_argument(
            "--sign", dest="sign", default=None, help="Sign the unsigned file"
        )

        parser.add_argument(
            "--debug",
            dest="debug",
            default=False,
            action="store_const",
            const=True,
            help="Debugging output",
        )

        parser.add_argument(
            "--testnet",
            dest="testnet",
            default=False,
            action="store_const",
            const=True,
            help="Testnet",
        )

        parser.add_argument(
            "--trezor",
            dest="trezor",
            default=False,
            action="store_const",
            const=True,
            help="Use Trezor connector",
        )

        parser.add_argument(
            "--trezor-path", dest="trezor_path", default=None, help="Trezor path"
        )

        args_src = sys.argv
        self.args, unknown = parser.parse_known_args(args=args_src[1:])

        if self.args.rpc_addr:
            if not re.match(r"^\[?([.0-9a-f:]+)\]?(:[0-9]+)?$", self.args.rpc_addr):
                logger.error("Invalid deamon address: %s" % self.args.rpc_addr)
                return -1

        sys.argv = [args_src[0]]
        res = await self.entry()
        sys.argv = args_src
        return res


async def amain():
    agent = HostAgent()
    res = await agent.main()
    sys.exit(res)


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(amain())
    # loop.run_forever()
    loop.close()


if __name__ == "__main__":
    main()
