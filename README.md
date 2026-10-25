# actionlint-plugin-shellcheck

ShellCheck for the `run:` steps actionlint analyzes, as a WebAssembly component built on
[shellcheck-rs](https://github.com/kjanat/shellcheck-rs). The component implements
`kjanat:actionlint/analyzer@0.1.0` through
[`actionlint-extension-api`](vendor/actionlint-extension-api/README.md).
Its analyzer declares the `shellcheck` rule directly; the engine provider is `shellcheck-rs`.
actionlint runs it in a fresh instance per document. Source reads use explicit read-only host grants;
no native ShellCheck executable or network access is needed.

## Use

```sh
actionlint plugin install shellcheck
actionlint check
```

The registry installation selects this plugin as the ShellCheck backend.
Selection uses its exported `kjanat:actionlint/tool-integration@0.1.0` interface,
not its package name. It negotiates the versioned
[`shellcheck-config@0.1.0` profile](vendor/actionlint-extension-api/schemas/shellcheck-config-0.1.0.md),
declining rc files, diagnostic ranges and `disable: [all]` so the host can select native execution.
`--no-shellcheck` or `tools.shellcheck.enabled: false` disables ShellCheck analysis, including this plugin.
Loading the artifact with `--plugin artifacts/plugin.wasm` discovers the same
tool-integration declaration and negotiates the same host tool configuration.
Raw analyzer calls can supply plugin options directly; filesystem access still
requires explicit caller-supplied grants.

Each finding carries the ShellCheck code as `code`, the ShellCheck level as `severity`, the message in the form
`shellcheck reported issue in this script: SC2086:info:1:6: ...` and, when ShellCheck offers one, a fix with edits
mapped into the workflow file. Findings in composite action scripts point at the action file.
Findings remain available when another script or the engine's dataflow analysis cannot complete;
the host also receives an explicit incomplete-analysis error.

The required `kjanat:actionlint/prepared-scripts@0.1.0` host import supplies the
same preparation used by native ShellCheck: the resolved runner shell, a
`# shellcheck shell=` directive at the top of the script, and the runner's startup options such as `set -e -o pipefail`
for an explicit `bash`. Without a shell directive, steps whose shell is unknown, `pwsh`, `python` or a custom template
that hides the script are skipped. `${{ }}` expressions are masked before analysis, and SC1091, SC2194, SC2050, SC2153,
SC2154, SC2157 and
SC2043 are excluded for the same reasons the built-in rule excludes them.

ShellCheck directives attached as YAML comments apply to that script:

```yaml
- name: Leading directive
  # shellcheck disable=SC2086
  run: echo $HI
- run: echo $HI # shellcheck disable=SC2086
- run: | # shellcheck disable=SC2086
    echo $HI
```

The host supplies these comments through `kjanat:actionlint/source-annotations@0.1.0`, independently of script text.
The artifact requires a host providing that optional interface. Directives inside block scalars keep normal ShellCheck
scope; trailing directives inside shell text retain ShellCheck's placement error. Invalid YAML directives point at
their comment. Script findings and fixes retain their original positions, including anchored scripts and invoked
composite actions. Alias-use YAML directives apply only to that declaration.

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
| `source-path`       | Source search directories, translated through the granted filesystem roots                                               |

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
grants. Mount translations come from `kjanat:actionlint/source-files@0.1.0`,
never from plugin options. This import, `source-annotations` and `prepared-scripts` are required
by the component. Rc files still require the native adapter.
Plugin options can narrow these grants; they cannot enable disabled host access
or add directories outside the workspace and host-configured source paths.

With explicit filesystem grants, absolute source paths and absolute search
directories work even without a known working directory. Relative paths still
require a known base. Source lookup follows ShellCheck's search order, including
its relative search candidates before falling back to an absolute source name.

## Build

Requirements: the Rust toolchain in `rust-toolchain.toml` with the `wasm32-wasip2` target, which `rustup` installs
on first use, and Go 1.27 for the host test.

The public SDK is vendored under `vendor/actionlint-extension-api` while its new
interfaces await publication. This snapshot is self-contained; builds need no
sibling actionlint checkout. Keep its WIT, schemas and Rust bindings together
when updating the snapshot.

The host integration test module still pins the previous published host.
These new interfaces were tested with a temporary module replacement against
the matching host changes. Update that published host pin before CI or release.

```sh
cargo build --locked --release --lib --target wasm32-wasip2
cargo run --locked --features package --bin package -- target/wasm32-wasip2/release/actionlint_plugin_shellcheck.wasm artifacts
```

Distribute `artifacts/plugin.wasm`. The package also contains `metadata.json`, `schema.json`, `LICENSE` and
`SHA256SUMS`. Packaging preserves the component and prepends its top-level `actionlint.plugin` discovery section;
repackaging the same input produces identical bytes. The declaration's contract checksum is SHA-256 of the
SDK's canonical analyzer WIT with LF line endings, matching actionlint's contract identity. The runtime descriptor and
static
declaration share rule metadata. This is a component, not the core-Wasm script-engine ABI.

The SDK owns guest bindings, the component export macro and native packaging. This plugin supplies its
descriptor, Cargo identity, engine, capabilities and license. Its `source-annotations` feature imports
attached YAML comments from compatible hosts; the original analyzer interface remains unchanged.
The full structural interface is checked when loading.

## Release

PR CI checks the packaged candidate before a release exists. The registry's shared `check` action exports a local
catalogue, installs through `actionlint plugin install`, and runs [this plugin's fixture](tests/installation.ts).
It checks source following, exact diagnostic positions, source edits and read-only grants. Checking runs again
after deleting the catalogue, then must fail after removing the cached Wasm. The receipt records the candidate
digest, host and fixture used. No tag, registry submission or publisher credential is needed.

Enable **immutable releases** in the repository settings. Push a signed `v` tag matching `Cargo.toml`.
Release reuses CI, then downloads the tested package and receipt. The registry's shared `publish` action requires
both before publishing. Its `contents: write` permission publishes package files; `id-token: write` authenticates
the tag and repository. No publisher secret is needed.

The workflow stages assets in a draft, downloads and compares all five files, then publishes and requires GitHub's
`immutable` release flag before registry submission. Existing assets must match exactly; reruns never overwrite
different bytes. An interrupted draft can resume missing uploads. Published releases must already be complete.

Registry acceptance is asynchronous. The workflow polls for up to 30 minutes and succeeds only on `published`;
`pending`, `validating`, rejection, failure and timeout are not publication success. The retained
`registry-publication-receipt` artifact records the submission ID, tested digest, status URL and last response.
After a timeout or recoverable registry failure, inspect that URL and rerun the tag workflow (or dispatch Release
with the existing tag selected). An identical resubmission preserves the registry identity. Branch dispatches
cannot publish: registry OIDC authorization requires the workflow itself to run from the submitted tag.

After publication, the shared action installs the exact candidate version and digest from the production registry
and runs the same fixture with the same host revision. This checks delivery after candidate verification.
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

The `candidate-verification` CI artifact contains the receipt for the package built by that run.
The fixture also runs through the registry CLI locally; see its
[candidate check instructions](https://github.com/kjanat/actionlint-registry#check-a-candidate).

## License

GPL-3.0-or-later, as shellcheck-rs and ShellCheck.
