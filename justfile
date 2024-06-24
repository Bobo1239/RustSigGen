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
