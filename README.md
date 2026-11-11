# actionlint-plugin-shellcheck

This plugin runs ShellCheck on the `run:` steps that actionlint analyzes. It is a WebAssembly component built on
[rshellcheck](https://github.com/kjanat/shellcheck-rs) and needs no ShellCheck executable or network connection.
The component declares the `shellcheck` rule through `kjanat:actionlint/analyzer@0.2.0`. actionlint creates a new
instance for each document.

## Install and run

```sh
actionlint plugin install shellcheck
actionlint check
```

The registry installs the plugin as the managed ShellCheck backend. The plugin advertises that role through
`kjanat:actionlint/tool-integration@0.2.0` and negotiates the
[`shellcheck-config@0.1.0` profile](vendor/actionlint-extension-api/json/shellcheck-config-0.1.0.md). It declines
configurations that need rc files, diagnostic ranges or `disable: [all]`. The host can then run native ShellCheck for
them. Disable ShellCheck with `--no-shellcheck` or `tools.shellcheck.enabled: false`.

You can also load `artifacts/plugin.wasm` with `--plugin`. The host discovers the same tool integration and negotiates
the same configuration. Direct analyzer callers can pass plugin options. With `external-sources` enabled, they must also
grant read-only filesystem access. `external-sources` is off by default.

## Analysis

A finding has the ShellCheck code in `code`, the ShellCheck level in `severity`, and the ShellCheck message without its
trailing period. If ShellCheck offers a fix, the finding carries its edits mapped to the workflow file. Findings for
composite action scripts point to the action file. If one script or the dataflow analysis fails, the plugin still
returns the findings it has and reports an incomplete-analysis error.

The host must provide `kjanat:actionlint-script/shell-script-inputs@0.3.0`. It supplies the resolved runner shell, a
leading `# shellcheck shell=` directive and runner startup options, such as `set -e -o pipefail` for explicit `bash`.
Without a shell directive, the plugin skips unknown shells, `pwsh`, `python` and custom templates that hide the script.
The host masks `${{ }}` expressions. It declares environment names without their values, each in its exported spelling.
SC2153 and SC2154 check these names unless unresolved declarations prevent the host from determining them. The plugin
excludes SC1091, SC2194, SC2050, SC2157 and SC2043 by default.

The host must also provide `kjanat:actionlint/source-annotations@0.2.0`. It passes YAML comments attached to a script,
including leading and trailing directives:

```yaml
- name: Leading directive
  # shellcheck disable=SC2086
  run: echo $HI
- run: echo $HI # shellcheck disable=SC2086
- run: | # shellcheck disable=SC2086
    echo $HI
```

Directives inside block scalars follow ShellCheck's usual scope rules. Trailing directives in shell text retain
ShellCheck's placement error. Errors in YAML directives point to the comment. Findings and fixes retain their original
positions for anchored scripts and invoked composite actions. A directive on an alias applies only to that declaration.

## Configure the plugin

The host passes a JSON object. Every key is optional.

| Key                 | Purpose                                                                                                |
| ------------------- | ------------------------------------------------------------------------------------------------------ |
| `shell`             | Select `bash`, `sh`, `dash`, `ksh` or `busybox`. A header directive takes precedence over this option. |
| `disable`           | Exclude diagnostic codes such as `SC2086` or `2086`.                                                   |
| `enable`            | Enable optional checks by exact name, such as `require-variable-braces`, or use `all`.                 |
| `extended-analysis` | Enable or disable dataflow analysis.                                                                   |
| `severity`          | Set the lowest reported level to `error`, `warning`, `info` or `style`.                                |
| `external-sources`  | Follow sources in directories granted by the host. The default is `false`.                             |
| `source-path`       | Set source search directories. The host translates them through its granted filesystem roots.          |

An unknown key or invalid value stops analysis with an error that names the key. `disable` accepts diagnostic
numbers. `enable` accepts optional-check names. The plugin rejects misspelled names and numeric enable selectors.
The generated schema and runtime validator both use rshellcheck's typed optional-check catalogue. The package includes
the schema as `artifacts/schema.json`. Setting a dialect does not turn an unsupported runtime shell into a shell script.

## Source files

For managed installations, `tools.shellcheck.config.external-sources: true` grants read-only access to the workspace.
Explicit `source-path` directories also grant access. They must stay inside the workspace after the host resolves
symlinks. A path or symlink that leaves the workspace fails analysis. Plugin options can narrow host grants, but cannot
restore disabled access or add directories outside the workspace. ShellCheck directives cannot expand grants either.

The required `kjanat:actionlint/source-files@0.2.0` import supplies mount translations. The host maps absolute source
directives into granted directories, records reads and keeps file snapshots for the call. Clean and transitively sourced
files remain dependencies even if they produce no findings. Rc files require the native adapter.

Absolute source paths and search directories work without a known working directory when the host grants access.
Relative paths require a known base. ShellCheck searches relative candidates before falling back to an absolute source
name.

## Build and package

Install the Rust toolchain specified in `rust-toolchain.toml` and its `wasm32-wasip2` target. `rustup` installs the
target on first use. The host tests also require Go 1.27.

Cargo and the Go host tests pin the same actionlint revision in `Cargo.toml`, `Cargo.lock` and `tests/host/go.mod`.
The plugin embeds the integration schema from `src/configuration.schema.json`.

```sh
cargo build --locked --release --lib --target wasm32-wasip2
cargo run --locked --features package --bin package -- target/wasm32-wasip2/release/actionlint_plugin_shellcheck.wasm artifacts
```

Distribute `artifacts/plugin.wasm` with `metadata.json`, `schema.json`, `LICENSE` and `SHA256SUMS`. The packager
preserves the component and prepends its `actionlint.plugin` discovery section. The same input produces identical bytes.
The declaration uses the SHA-256 of the SDK's canonical analyzer WIT with LF line endings as its contract checksum.
The runtime descriptor and static declaration share rule metadata. The component uses the analyzer ABI.

The vendored SDK and Go host tests target actionlint commit `70c824363f307a5097e73531d18d00189cca6fe8`. The
[snapshot manifest](vendor/actionlint-extension-api.snapshot.json) records the unmodified SDK's revision and hashes.
A build does not need a sibling actionlint checkout or a module replacement. Update the WIT, JSON profiles, Rust
bindings and Go host dependency together.

The SDK provides guest bindings, the component export macro and native packaging. This repository provides the plugin's
descriptor, Cargo identity, engine, capabilities and license. The SDK's `source-annotations` feature imports YAML
comments from compatible hosts without changing the analyzer interface. The host validates the full structural interface
when loading the component.

## Test

Build and package the component first, then run:

```sh
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
go -C tests/host test -mod=readonly ./...
```

The Go tests inspect the package metadata and load the component through actionlint's private host packages. They check
diagnostic positions, fixes, option errors, descriptors and checksums. Set `ACTIONLINT_PLUGIN_SHELLCHECK` to test a
different packaged component and its sidecars. The unpublished test module uses the actionlint module prefix to access
private packages and pins the published host revision. The distributed component depends on the guest contract, not the
host's Go API. Native tests check that a dataflow or startup failure keeps the other findings.

PR CI also installs the candidate from a local registry catalogue and runs
[the installation fixture](tests/installation.ts). The fixture checks source reads, positions, edits and read-only
grants. CI then repeats the check without the catalogue, removes the cached Wasm and expects the check to fail. The
`candidate-verification` artifact records the package digest, host and fixture. This check needs no tag, registry
submission or publisher credential. The registry's
[candidate check instructions](https://github.com/kjanat/actionlint-registry#check-a-candidate) explain how to run it
locally.

## Release

Enable immutable releases in the repository settings, then push a signed `v` tag matching `Cargo.toml`. The release
workflow reuses CI and downloads the tested package and receipt. The registry's shared `publish` action requires both.
It uses `contents: write` to publish files and `id-token: write` to authenticate the tag and repository. It needs no
publisher secret.

The workflow uploads the five files to a draft, downloads them and compares their bytes. It publishes the release and
checks GitHub's `immutable` flag before registry submission. Existing assets must match. A rerun can upload missing
draft assets but cannot overwrite different bytes. An already published release must contain all files.

The registry processes submissions asynchronously. The workflow polls for up to 30 minutes and succeeds only when the
status is `published`. Pending, validating, rejected and failed statuses, as well as timeouts, fail the workflow. The
`registry-publication-receipt` artifact records the submission ID, digest, status URL and last response. After a timeout
or recoverable failure, inspect that URL and rerun the tag workflow or dispatch Release with the existing tag. An
identical resubmission preserves the registry identity. A branch dispatch cannot publish because registry OIDC requires
the workflow to run from the submitted tag.

After publication, the shared action installs the exact version and digest from the production registry and reruns the
fixture with the same host revision. For normal use, install the selected version with actionlint's registry installer
and commit the project lockfile.

## License

GPL-3.0-or-later. rshellcheck and ShellCheck use the same license.
