# Changelog

All notable changes to LinkSiren will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.5] - 2026-06-26
### Fixed
- `process_targets` no longer crashes on blank or whitespace-only lines in target files. Offending lines (and malformed UNC entries) are logged and skipped instead.
- `handle_cleanup` now accumulates per-host delete failures across the whole target list. Previously it reassigned the failure list on each iteration, silently dropping failures from earlier hosts.

### Changed
- Bumped runtime minimums: `impacket >= 0.12.0`, `tqdm >= 4.68.0`.
- Pinned dev tooling minimums (`black >= 25`, `ruff >= 0.7`, `pytest >= 8.0`, `coverage >= 7.6`, `isort >= 5.13`, `bumpver >= 2024.0`, `pip-tools >= 7.4`).
- Build requirement bumped to `setuptools >= 80.0.0`.
