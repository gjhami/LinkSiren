# Changelog

All notable changes to LinkSiren will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-26
### Added
- Pass-the-Hash authentication via `-no-pass -hashes LMHASH:NTHASH` (bare NT hash form, no colon, also accepted).
- Kerberos authentication via `-no-pass -k [-aesKey <hex>] -dc-ip <ip-or-fqdn>`. TGT is loaded automatically from the ccache referenced by `$KRB5CCNAME`.
- Anonymous (NULL session) SMB via `--anonymous` for share-enumeration recon against misconfigured hosts.
- Auto-resolve IP-form target hosts to FQDN via reverse DNS when Kerberos is in use, so the `cifs/<host>` SPN can be located. If reverse DNS gives a name that does not match an AD SPN, an explicit log line tells the tester to pass `--dc-ip <exact-fqdn>` and a target file with FQDN entries.
- `AuthContext` dataclass centralizing all credential state (`domain`, `username`, `password`, `lmhash`, `nthash`, `aes_key`, `kdc_host`, `use_kerberos`, `no_pass`, `anonymous`). Backwards-compatible alias `Credentials = AuthContext` preserved for existing callers.

### Changed
- All credentialed subcommands (`rank`, `identify`, `deploy`, `cleanup`) share a single `_add_auth_args` helper, so auth flags stay identical across modes.
- `HostTarget.connect` dispatches on `credentials.use_kerberos` (kerberosLogin), `credentials.anonymous` (NULL-session login), or falls through to the standard `SMBConnection.login` with password and/or NTLM hashes.

## [0.0.5] - 2026-06-26
### Fixed
- `process_targets` no longer crashes on blank or whitespace-only lines in target files. Offending lines (and malformed UNC entries) are logged and skipped instead.
- `handle_cleanup` now accumulates per-host delete failures across the whole target list. Previously it reassigned the failure list on each iteration, silently dropping failures from earlier hosts.

### Changed
- Bumped runtime minimums: `impacket >= 0.12.0`, `tqdm >= 4.68.0`.
- Pinned dev tooling minimums (`black >= 25`, `ruff >= 0.7`, `pytest >= 8.0`, `coverage >= 7.6`, `isort >= 5.13`, `bumpver >= 2024.0`, `pip-tools >= 7.4`).
- Build requirement bumped to `setuptools >= 80.0.0`.
