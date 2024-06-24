import asyncio
import configparser
import logging
import os
from pathlib import Path

import ida_diskio
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_rust_plugin
import qasync
from PyQt5.QtWidgets import QApplication

ACTION_DESCRIPTION = "Generate Rust signatures"
ACTION_NAME = "rust:generate_signatures"


class GenerateSignatures(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        print("Starting signature generation...")
        asyncio.ensure_future(self.generate_and_apply_signature())
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

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


def register_action():
    action = ida_kernwin.action_desc_t(
        ACTION_NAME, ACTION_DESCRIPTION, GenerateSignatures()
    )
    if ida_kernwin.register_action(action):
        ida_kernwin.attach_action_to_toolbar("AnalysisToolBar", ACTION_NAME)
        print("Registed action")
        return True
    else:
        return False


LOG_FORMAT = "%(levelname)s %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

# Set asyncio event loop to the QT one; without this the GUI freezes during script runtime and
# strange Rust crashes occur
asyncio.set_event_loop(qasync.QEventLoop(QApplication.instance(), already_running=True))

# Try registering action; can fail if we're reloading this script so we may need to retry
if not register_action():
    # Related cleanup (e.g. menu items) will be done automatically
    ida_kernwin.unregister_action(ACTION_NAME)
    register_action()
