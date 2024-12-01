# RustSigGen

A tool for generating tailor-made function signature libraries for Rust binaries.

Given a stripped Rust binary this tool can:
- Determine the used rustc version
- Determine the target triple of the binary
- Generate signatures for the used std library
- Generate signatures for crate dependencies of the binary

There's also a IDA Pro 9.0 plugin which can do std signature generation. Crate dependencies are too
finicky to create atm so that isn't included in the plugin.

## Runtime dependencies
- `git`
- [`rustup`](https://rustup.rs/)
- [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin)

> We depend on an unreleased [PR](https://github.com/rust-cross/cargo-xwin/pull/123) for
> `cargo-xwin` so currently a git installation is required: `cargo install --locked --git
> https://github.com/rust-cross/cargo-xwin.git cargo-xwin`

## Usage examples
Set `IDA_FLAIR_PATH=/path/to/flair90` or add `-f /path/to/flair90` to the example usages.

Generate std signatures:
```bash
rust-sig-gen std path/to/binary
```

Generate crate signatures: (Initial run will take a long time!)
```bash
rust-sig-gen crates path/to/binary # Uses default release profile for compilation
rust-sig-gen crates path/to/binary --lto fat # Additionally enable LTO
```

Debug specific crate compilation/signatures:
```bash
rust-sig-gen crates path/to/binary -d dependency_name
```
Check the output logs to see where the tmpdir used for crate compilation lies. Consider enabling addition logging by settings `RUST_LOG=debug`.

## Install instructions

### CLI version
```bash
> cargo install --path .
```

### IDA Pro Plugin
```bash
> just install-ida-plugin
# Make sure to adjust `~/.idapro/plugins/ida-rust-plugin/ida-rust-plugin.cfg`!
```
You can now generate std signatures in IDA via Edit > Plugins > Rust Signature Generator.

### Binary Ninja Plugin (currently unsupported)
The official "Signature Kit Plugin" must be installed as a prerequisite which can be done using the
built-in plugin manager.
```bash
> just install-binja-plugin
```
You should now see the "Generate Rust signatures" command in the command palette.

## Developer Notes
- VS Code autocompletion
    - IDA Pro:
        ```
        {
            "python.autoComplete.extraPaths": [
                "/path/to/idapro-8.4/python/3"
            ]
        }
        ```
