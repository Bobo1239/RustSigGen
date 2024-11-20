# Rust Signature Generator
TODO: Better name

## Runtime dependencies
- `git`
- [`rustup`](https://rustup.rs/)
- [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin)

## Install instructions

### IDA Pro
```bash
> just install-ida-plugin
# Make sure to adjust `~/.idapro/plugins/ida-rust-plugin.cfg`!
```
You should now see the `rust:*` actions in your IDA Pro command palette.

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
