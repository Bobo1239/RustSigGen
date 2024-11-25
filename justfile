# Load environment variables from .env; Currently only useful for loading IDA_FLAIR_PATH
set dotenv-load

ida_build_path := "target/ida-plugin"
ida_install_path := "~/.idapro/plugins/ida-rust-plugin"

run *args:
    mold -run cargo build
    # Don't use mold when generating our crate signatures (probably doesn't matter)
    cargo run -- {{args}}

ida-plugin:
    cargo build --release -p ida-rust-plugin
    mkdir -p {{ida_build_path}}
    cp target/release/libida_rust_plugin.so {{ida_build_path}}/ida_rust_plugin.so
    cp ida-rust-plugin/ida-plugin.json {{ida_build_path}}
    cp ida-rust-plugin/ida-rust-plugin.py {{ida_build_path}}
    cp ida-rust-plugin/ida-rust-plugin.cfg {{ida_build_path}}

install-ida-plugin: ida-plugin
    mkdir -p {{ida_install_path}}
    cp {{ida_build_path}}/ida_rust_plugin.so {{ida_install_path}}
    cp {{ida_build_path}}/ida-plugin.json {{ida_install_path}}
    cp {{ida_build_path}}/ida-rust-plugin.py {{ida_install_path}}
    cp -n ida-rust-plugin/ida-rust-plugin.cfg {{ida_install_path}}

binja-plugin:
    cargo build --release -p binja-rust-plugin
    mkdir -p target/binja-plugin
    -ln -s -r target/release/libbinja_rust_plugin.so ./target/binja-plugin/binja_rust_plugin.so
    -ln -s -r binja-rust-plugin/* target/binja-plugin/

install-binja-plugin: binja-plugin
    -ln -s -T -r target/binja-plugin ~/.binaryninja/plugins/binja-rust-plugin
