# Changelog

## [0.2.0] - 2026-10-29

### Changed

- **Breaking:** implement `kjanat:actionlint/analyzer@0.2.0` for actionlint v2 hosts; hosts supporting only `0.1.0` reject this release.
- Request shell preparation by script occurrence instead of source reference, matching the `0.2.0` `prepared-scripts` import.

## [0.1.2] - 2026-10-24

### Added

- Follow sourced shell scripts through read-only host grants, including configured search paths and source-file diagnostic locations (https://github.com/kjanat/actionlint-plugin-shellcheck/pull/1).

### Fixed

- Preserve ShellCheck's search order when resolving absolute source names (https://github.com/kjanat/actionlint-plugin-shellcheck/pull/2).
- Declare filesystem access in package metadata for source-file analysis (https://github.com/kjanat/actionlint-plugin-shellcheck/pull/2).

## [0.1.1] - 2026-10-20

*This release corrects verification of registry installations ([`63d4e61`](https://github.com/kjanat/actionlint-plugin-shellcheck/commit/63d4e6111bd32505fc40a202e9f0c3d27ec23a71)).*

## [0.1.0] - 2026-10-20

*First release.*

[0.2.0]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.2.0
[0.1.2]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.1.2
[0.1.1]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.1.1
[0.1.0]: https://github.com/kjanat/actionlint-plugin-shellcheck/releases/tag/v0.1.0
