# actionlint-plugin-shellcheck

ShellCheck for the `run:` steps actionlint analyzes, as a WebAssembly component built on
[shellcheck-rs](https://github.com/kjanat/shellcheck-rs). The component implements
`kjanat:actionlint/analyzer@0.1.0` from [`wit/analyzer.wit`](wit/analyzer.wit) and reports under the rule name
`shellcheck-rs`. actionlint runs it in a fresh instance per document; no ShellCheck executable, filesystem,
network or environment is involved.

## Use

```sh
actionlint check --shellcheck= --plugin artifacts/plugin.wasm
```

`--shellcheck=` or `tools.shellcheck.enabled: false` in the actionlint configuration turns off the built-in rule,
which would otherwise check the same scripts with a ShellCheck executable.

Each finding carries the ShellCheck code as `code`, the ShellCheck level as `severity`, the message in the form
`shellcheck reported issue in this script: SC2086:info:1:6: ...` and, when ShellCheck offers one, a fix with edits
mapped into the workflow file. Findings in composite action scripts point at the action file.
Findings remain available when another script or the engine's dataflow analysis cannot complete;
the host also receives an explicit incomplete-analysis error.

The plugin selects the dialect the way actionlint's built-in rule does: the resolved runner shell, a
`# shellcheck shell=` directive at the top of the script, and the runner's startup options such as `set -e -o pipefail`
for an explicit `bash`. Without a shell directive, steps whose shell is unknown, `pwsh`, `python` or a custom template
that hides the script are skipped. `${{ }}` expressions are masked before analysis, and SC1091, SC2194, SC2050, SC2153, SC2154, SC2157 and
SC2043 are excluded for the same reasons the built-in rule excludes them.

## Options

The host passes a JSON object; every key is optional:

| Key                 | Value                                                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `shell`             | `bash`, `sh`, `dash`, `ksh` or `busybox`; overrides supported-shell inference unless a header directive selects a dialect |
| `disable`           | Codes such as `SC2086` or `2086` to exclude                                                                               |
| `enable`            | Exact optional-check names such as `require-variable-braces`, or `all`; not diagnostic codes                              |
| `extended-analysis` | Enable or disable dataflow analysis                                                                                       |
| `severity`          | Lowest reported level: `error`, `warning`, `info` or `style`                                                              |

Unknown keys and invalid values fail the analysis with a message naming the key.
The rule exposes a generated options schema for editor/tool discovery, also packaged as `artifacts/schema.json`.
An explicit dialect option does not turn an unknown or unsupported runtime shell into a shell script.
`disable` identifies emitted diagnostics by number; `enable` selects optional analysis passes by name. Unknown
optional-check names, misspellings and numeric enable selectors are rejected. Both schema and validation use
shellcheck-rs's typed optional-check catalogue; no CLI output parsing or copied catalogue is involved.

## Build

Requirements: the Rust toolchain in `rust-toolchain.toml` with the `wasm32-wasip2` target, which `rustup` installs
on first use, and Go 1.27 for the host test.

```sh
cargo build --locked --release --lib --target wasm32-wasip2
cargo run --locked --features package --bin package -- target/wasm32-wasip2/release/actionlint_plugin_shellcheck.wasm artifacts
```

Distribute `artifacts/plugin.wasm`. The package also contains `metadata.json`, `schema.json`, `LICENSE` and
`SHA256SUMS`. Packaging preserves the component and prepends its top-level `actionlint.plugin` discovery section;
repackaging the same input produces identical bytes. The declaration's contract checksum is SHA-256 of the
vendored WIT with LF line endings, matching actionlint's contract identity. The runtime descriptor and static
declaration share rule metadata. This is a component, not the core-Wasm script-engine ABI.

The vendored contract and host tests target actionlint revision `1934c2afefdce90fec149fb089e57d0b129f1643`.
Update them together when the contract changes; the full structural interface is checked when loading.
Packaging and local validation do not publish a GitHub release or registry entry.

## Test

```sh
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
go -C tests/host test -mod=readonly ./...
```

Build and package before running the Go tests. They inspect the packaged metadata without executing it, then load
the same component through actionlint's public `plugin` package, checking positions, fixes, option errors, descriptor
parity and package checksums. `ACTIONLINT_PLUGIN_SHELLCHECK` selects another packaged component with its sidecars.
Native tests also cover partial dataflow/startup failures without discarding other findings.

## License

GPL-3.0-or-later, as shellcheck-rs and ShellCheck.
