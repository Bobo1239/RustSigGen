# Rust Signature Generator
TODO: Better name

## Runtime dependencies
- `git`
- [`rustup`](https://rustup.rs/)
- [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin)

> We depend on an unreleased [PR](https://github.com/rust-cross/cargo-xwin/pull/123) for
> `cargo-xwin` so currently a git installation is required: `cargo install --locked --git
> https://github.com/rust-cross/cargo-xwin.git cargo-xwin`

## Install instructions

### IDA Pro
```bash
> just install-ida-plugin
# Make sure to adjust `~/.idapro/plugins/ida-rust-plugin/ida-rust-plugin.cfg`!
```
You can now generate std signatures in IDA via Edit > Plugins > Rust Signature Generator.

### Binary Ninja
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
