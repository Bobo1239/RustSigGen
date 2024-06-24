# Rust Signature Generator
TODO: Better name

## Install instructions

### IDA Pro
```bash
> just install-ida-plugin
# Make sure to adjust `~/.idapro/plugins/ida-rust-plugin.cfg`!
```
You should now see the `rust:*` actions in your IDA Pro command palette.

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
