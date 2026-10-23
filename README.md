# actionlint-plugin-shellcheck

ShellCheck for the `run:` steps actionlint analyzes, as a WebAssembly component built on
[shellcheck-rs](https://github.com/kjanat/shellcheck-rs). The component implements
`kjanat:actionlint/analyzer@0.1.0` from [`wit/analyzer.wit`](wit/analyzer.wit). Its component identity is
`shellcheck-rs`; the official registry installation exposes its findings under the standard `shellcheck` rule.
actionlint runs it in a fresh instance per document. Source reads use explicit read-only host grants;
no native ShellCheck executable or network access is needed.

## Use

```sh
actionlint plugin install shellcheck
actionlint check
```

The registry installation selects this plugin as the ShellCheck backend.
`--no-shellcheck` or `tools.shellcheck.enabled: false` disables ShellCheck analysis, including this plugin.
Loading the artifact directly with `--plugin artifacts/plugin.wasm` creates a standalone analyzer instead,
configured under `lint.rules.plugins.shellcheck-rs`; it receives no automatic filesystem grants.

Each finding carries the ShellCheck code as `code`, the ShellCheck level as `severity`, the message in the form
`shellcheck reported issue in this script: SC2086:info:1:6: ...` and, when ShellCheck offers one, a fix with edits
mapped into the workflow file. Findings in composite action scripts point at the action file.
Findings remain available when another script or the engine's dataflow analysis cannot complete;
the host also receives an explicit incomplete-analysis error.

The plugin selects the dialect the way actionlint's built-in rule does: the resolved runner shell, a
`# shellcheck shell=` directive at the top of the script, and the runner's startup options such as `set -e -o pipefail`
for an explicit `bash`. Without a shell directive, steps whose shell is unknown, `pwsh`, `python` or a custom template
that hides the script are skipped. `${{ }}` expressions are masked before analysis, and SC1091, SC2194, SC2050, SC2153,
SC2154, SC2157 and
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
| `external-sources`  | Follow sources within the read-only directories granted by the host; default false                                        |
| `source-path`       | Source search directories in the guest filesystem                                                                         |
| `source-roots`      | Host-to-guest path mappings supplied by the adapter; mappings do not grant file access                                    |

Unknown keys and invalid values fail the analysis with a message naming the key.
The rule exposes a generated options schema for editor/tool discovery, also packaged as `artifacts/schema.json`.
An explicit dialect option does not turn an unknown or unsupported runtime shell into a shell script.
`disable` identifies emitted diagnostics by number; `enable` selects optional analysis passes by name. Unknown
optional-check names, misspellings and numeric enable selectors are rejected. Both schema and validation use
shellcheck-rs's typed optional-check catalogue; no CLI output parsing or copied catalogue is involved.

For the managed plugin, `tools.shellcheck.config.external-sources: true` grants
the workspace read-only. Explicit `source-path` directories also enable access
and can select directories outside the workspace. The host maps absolute source
directives into those grants, records actual reads and keeps file snapshots for
the duration of the call. Clean and transitively sourced files are dependencies
even when they emit no findings. ShellCheck directives cannot expand the host's
grants. Rc files still require the native adapter.

With explicit filesystem grants, absolute source paths and absolute search
directories work even without a known working directory. Relative paths still
require a known base. Source lookup follows ShellCheck's search order, including
its relative search candidates before falling back to an absolute source name.

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

The vendored contract and host tests target actionlint revision
[kjanat/actionlint@`a30ed059a11e`](https://github.com/kjanat/actionlint/commit/a30ed059a11e5d30b26758c4a41fceafa49ee959).
Update them together when the contract changes. The full structural interface is checked when loading.

## Release

Enable **immutable releases** in the repository settings before the first release. Push a signed `v` tag matching
`Cargo.toml`. The Release workflow reuses CI to build with locked dependencies, package once,
and test that package through actionlint's public loader. A separate publication job downloads those tested bytes;
it does not rebuild. Its `contents: write` permission publishes the five package files, and `id-token: write`
authenticates the tag and repository to the pinned registry submission action. No publisher secret is needed.

The workflow stages assets in a draft, downloads and compares all five files, then publishes and requires GitHub's
`immutable` release flag before registry submission. Existing assets must match exactly; reruns never overwrite
different bytes. An interrupted draft can resume missing uploads. Published releases must already be complete.

Registry acceptance is asynchronous. The workflow polls for up to 20 minutes and succeeds only on `published`;
`pending`, `validating`, rejection, failure and timeout are not publication success. The retained
`registry-publication-receipt` artifact records the submission ID, tested digest, status URL and last response.
After a timeout or recoverable registry failure, inspect that URL and rerun the tag workflow (or dispatch Release
with the existing tag selected). An identical resubmission preserves the registry identity. Branch dispatches
cannot publish: registry OIDC authorization requires the workflow itself to run from the submitted tag.

After publication, the workflow builds the same pinned actionlint host used by integration tests, installs the
published version in a fresh project, checks an expected diagnostic and repeats checking offline with the lockfile.
For normal use, install the selected version using actionlint's registry installer and commit its project lockfile.

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

PR CI installs a pinned published release into an empty cache and verifies its digest, lockfile and SC2086 finding.
It repeats checking with a blocked proxy, then removes the cached Wasm and requires checking to fail.
The `installation-verification` artifact retains the result. The tag workflow performs the same checks for the
newly published version.

## License

GPL-3.0-or-later, as shellcheck-rs and ShellCheck.
