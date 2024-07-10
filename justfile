ida-plugin:
    cargo build --release -p ida-rust-plugin
    mkdir -p target/ida-plugin
    cp target/release/libida_rust_plugin.so ./target/ida-plugin/ida_rust_plugin.so
    cp ida-rust-plugin/ida-rust-plugin.py ./target/ida-plugin/
    cp -n ida-rust-plugin/ida-rust-plugin.cfg ./target/ida-plugin/

install-ida-plugin: ida-plugin
    cp target/ida-plugin/ida_rust_plugin.so ~/.idapro/plugins/
    cp target/ida-plugin/ida-rust-plugin.py ~/.idapro/plugins/
    cp -n ida-rust-plugin/ida-rust-plugin.cfg ~/.idapro/plugins/

binja-plugin:
    cargo build --release -p binja-rust-plugin
    mkdir -p target/binja-plugin
    -ln -s -r target/release/libbinja_rust_plugin.so ./target/binja-plugin/binja_rust_plugin.so
    -ln -s -r binja-rust-plugin/* target/binja-plugin/

install-binja-plugin: binja-plugin
    -ln -s -T -r target/binja-plugin ~/.binaryninja/plugins/binja-rust-plugin
