import asyncio
import logging
import multiprocessing as mp
import shutil
import traceback
import time
from pathlib import Path

import binaryninja
from binaryninja import (
    PluginCommand,
    mainthread,
)

from . import binja_rust_plugin


async def generate_rust_signatures(bv):
    tmp_dir = await binja_rust_plugin.download_rust_std(bv.file.original_filename)
    sig_name = await binja_rust_plugin.signature_library_name(bv.file.original_filename)

    files = list(Path(tmp_dir).iterdir())
    # TODO: Replace these with some other synchronization primites which are intended for
    #       thread-based parallelism (since we're not using using multiple processes here)
    remaining = mp.Value("i", len(files))
    func_info = {}
    for path in files:
        new_bv = binaryninja.load(path, update_analysis=False)
        new_bv.add_analysis_completion_event(on_analysis_complete(remaining, func_info))
        new_bv.update_analysis()

    while True:
        time.sleep(0.1)
        with remaining.get_lock():
            if remaining.value == 0:
                break
    shutil.rmtree(tmp_dir)

    # NOTE: We do late loading here since our plugin may get loaded before `Vector35_sigkit` is made
    #       available by binja (happens when the Sigkit plugin gets loaded) and that library is not
    #       included in Python's search path.
    import Vector35_sigkit as sigkit

    trie = sigkit.signaturelibrary.new_trie()
    sigkit.trie_ops.trie_insert_funcs(trie, func_info)
    sigkit.trie_ops.finalize_trie(trie, func_info)

    sig_dir = Path(binaryninja.user_directory()) / "signatures" / str(bv.platform)
    out_file = sig_dir / f"{sig_name}.sig"
    with open(out_file, "wb") as f:
        f.write(sigkit.sig_serialize_fb.dumps(trie))

    num_fns = len(set(trie.all_functions()))
    print(f"Generated signatures for {num_fns} functions. Saved to {out_file}.")

    # Trigger signature matcher
    bv.add_analysis_option("signaturematcher")
    bv.update_analysis()


def on_analysis_complete(remaining, func_info):
    def _on_analysis_complete(self):
        process_object_bv(self.view, func_info)
        self.view.file.close()
        with remaining.get_lock():
            remaining.value -= 1

    return _on_analysis_complete


def process_object_bv(bv, func_info):
    import Vector35_sigkit as sigkit

    guess_relocs = len(bv.relocation_ranges) == 0
    for func in bv.functions:
        try:
            if bv.get_symbol_at(func.start) is None:
                continue
            node, info = sigkit.generate_function_signature(func, guess_relocs)
            func_info[node] = info
        except:
            traceback.print_exc()
    print("done:", bv.file.filename)


def run_future_on_worker_thread(future):
    # NOTE: Couldn't get `qasync` to work (like with the IDA plugin). For now just run async
    #       functions on a separate worker thread.
    # TODO: There's also the `BackgroundTaskThread` API which may be better?
    #       (https://gist.github.com/psifertex/6fbc7532f536775194edd26290892ef7#file-make_functions-py-L5)
    mainthread.worker_enqueue(lambda: asyncio.run(future))


def plugin_generate_rust_signatures(bv):
    run_future_on_worker_thread(generate_rust_signatures(bv))


# TODO: Better integration with binja's logging system
LOG_FORMAT = "%(levelname)s %(message)s"
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

PluginCommand.register(
    "Generate Rust signatures",
    "Generate Rust signatures",
    plugin_generate_rust_signatures,
)
