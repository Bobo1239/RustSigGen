import asyncio
import configparser
import logging
import os
from pathlib import Path

import ida_diskio
import ida_funcs
import ida_idaapi
import ida_nalt
import qasync
from PyQt5.QtWidgets import QApplication

import ida_rust_plugin


class RustSignatureGenerator(ida_idaapi.plugmod_t):
    def run(self, arg):
        print("Starting signature generation...")
        asyncio.create_task(self.generate_and_apply_signature())

    async def generate_and_apply_signature(self):
        # Get the path of the original binary
        # Alternatively we could also get the bytes from the .idb; e.g. https://github.com/polymorf/findcrypt-yara/blob/42a02818586732a1ebd1bce8a9e241b1c46781a0/findcrypt3.py#L212
        bin_path = ida_nalt.get_input_file_path()
        signatures_path = Path(ida_diskio.get_user_idadir()).joinpath("sig", "pc")
        os.makedirs(signatures_path, exist_ok=True)

        config = configparser.ConfigParser()
        config.read(os.path.join(os.path.dirname(__file__), "ida-rust-plugin.cfg"))
        flair_path = config["ida-rust-plugin"]["flair_path"]

        # NOTE: Errors from the Rust side do get propagated here
        sig_path = await ida_rust_plugin.generate_signature_for_bin(
            bin_path, flair_path, signatures_path
        )
        ida_funcs.plan_to_apply_idasgn(sig_path)


class RustSignatureGeneratorPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    help = "TODO"
    wanted_name = "Rust Signature Generator"

    def init(self):
        LOG_FORMAT = "[%(levelname)s] %(message)s"
        logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

        # Set asyncio event loop to the QT one; without this the GUI freezes during script runtime and
        # strange Rust crashes occur
        asyncio.set_event_loop(
            qasync.QEventLoop(QApplication.instance(), already_running=True)
        )

        return RustSignatureGenerator()


def PLUGIN_ENTRY():
    return RustSignatureGeneratorPlugin()
