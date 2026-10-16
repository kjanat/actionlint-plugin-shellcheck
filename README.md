# actionlint-plugin-shellcheck

ShellCheck for the `run:` steps actionlint analyzes, as a WebAssembly component built on
[shellcheck-rs](https://github.com/kjanat/shellcheck-rs). The component implements
`kjanat:actionlint/analyzer@0.1.0` from [`wit/analyzer.wit`](wit/analyzer.wit) and reports under the rule name
`shellcheck-rs`. actionlint runs it in a fresh instance per document; no ShellCheck executable, filesystem,
network or environment is involved.

## Use

```sh
actionlint --shellcheck= --plugin actionlint_plugin_shellcheck.wasm
```

`--shellcheck=` or `tools.shellcheck.enabled: false` in the actionlint configuration turns off the built-in rule,
which would otherwise check the same scripts with a ShellCheck executable.

Each finding carries the ShellCheck code as `code`, the ShellCheck level as `severity`, the message in the form
`shellcheck reported issue in this script: SC2086:info:1:6: ...` and, when ShellCheck offers one, a fix with edits
mapped into the workflow file. Findings in composite action scripts point at the action file.

The plugin selects the dialect the way actionlint's built-in rule does: the resolved runner shell, a
`# shellcheck shell=` directive at the top of the script, and the runner's startup options such as `set -e -o pipefail`
for an explicit `bash`. Steps whose shell is unknown, `pwsh`, `python` or a custom template that hides the script
are skipped. `${{ }}` expressions are masked before analysis, and SC1091, SC2194, SC2050, SC2153, SC2154, SC2157 and
SC2043 are excluded for the same reasons the built-in rule excludes them.

## Options

The host passes a JSON object; every key is optional:

| Key                 | Value                                                         |
| ------------------- | ------------------------------------------------------------- |
| `shell`             | `bash`, `sh`, `dash`, `ksh` or `busybox`; overrides inference |
| `disable`           | Codes such as `SC2086` or `2086` to exclude                   |
| `enable`            | Optional ShellCheck checks such as `require-variable-braces`  |
| `extended-analysis` | Enable or disable dataflow analysis                           |
| `severity`          | Lowest reported level: `error`, `warning`, `info` or `style`  |

Unknown keys and invalid values fail the analysis with a message naming the key.

## Build

Requirements: the Rust toolchain in `rust-toolchain.toml` with the `wasm32-wasip2` target, which `rustup` installs
on first use, and Go 1.26 for the host test.

```sh
cargo build --locked --release --target wasm32-wasip2
```

The component is `target/wasm32-wasip2/release/actionlint_plugin_shellcheck.wasm`.

## Test

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
go -C tests/host test ./...
```

The Go test loads the built component through actionlint's public `plugin` package and runs it against a workflow,
checking positions, fixes and option handling. `ACTIONLINT_PLUGIN_SHELLCHECK` points it at another component file.

## License

GPL-3.0-or-later, as shellcheck-rs and ShellCheck.
