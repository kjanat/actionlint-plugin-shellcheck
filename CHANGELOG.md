# Changelog

## [0.3.1] - 2026-11-08

- Skip scripts using PowerShell, Python, `cmd` or another non-shell interpreter. Parse leading directives with ShellCheck's parser and choose exclusions using the host's environment facts. ([#16](https://github.com/kjanat/actionlint-plugin-shellcheck/pull/16))
- Update shellcheck-rs to `0b64935`. ([#13](https://github.com/kjanat/actionlint-plugin-shellcheck/pull/13))

## [0.3.0] - 2026-11-07

- This breaking change requires the host's `kjanat:actionlint-script/shell-script-inputs@0.3.0` interface. Older hosts reject this release. SC2153 and SC2154 now check scoped environment names without their values, instead of being disabled for every script. ([#14](https://github.com/kjanat/actionlint-plugin-shellcheck/pull/14))
- Match environment names case-sensitively in Bash. On Windows, merged declarations retain the first spelling. ([#14](https://github.com/kjanat/actionlint-plugin-shellcheck/pull/14))

## [0.2.1] - 2026-11-02

- Return plain ShellCheck messages, with the code, severity and location in separate fields.

## [0.2.0] - 2026-10-29

- This breaking change requires `kjanat:actionlint/analyzer@0.2.0`. Hosts limited to version `0.1.0` reject this release.
- Request shell preparation by script occurrence, as required by the `0.2.0` `prepared-scripts` import.

## [0.1.2] - 2026-10-24

- Follow sourced scripts through read-only host grants, including configured search paths and source-file locations. ([#1](https://github.com/kjanat/actionlint-plugin-shellcheck/pull/1))
- Follow ShellCheck's search order for absolute source names and declare filesystem access in package metadata. ([#2](https://github.com/kjanat/actionlint-plugin-shellcheck/pull/2))

## [0.1.1] - 2026-10-20

- Correct verification of registry installations. ([commit](https://github.com/kjanat/actionlint-plugin-shellcheck/commit/63d4e6111bd32505fc40a202e9f0c3d27ec23a71))

## [0.1.0] - 2026-10-20

- Publish the first release.

[0.3.1]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.3.1
[0.3.0]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.3.0
[0.2.1]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.2.1
[0.2.0]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.2.0
[0.1.2]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.1.2
[0.1.1]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.1.1
[0.1.0]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.1.0
