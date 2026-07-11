# Changelog

All notable changes to LinkSiren will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.1] - 2026-07-11
### Docs
- README restructured: keyword-dense pitch, AI-agent driving section with two sample prompts, `pipx` install alongside `uv`, five-command Quick Start, twelve-row Subcommands table, comparison against Farmer / Lnkbomb / Slinky / ntlm_theft, per-mode SOCKS routing note, downloads / last-commit badges.
- New `docs/ATTACK-PATHS.md` with three common engagement flows end to end: HTTP coercion relayed to LDAPS for RBCD, bulk-share opportunistic capture, and EFS trigger for computer-account authentication.
- Intranet-Zone requirement documented per file type. `.searchConnector-ms` and `.library-ms` fire SMB with no zoning by default (both templates ship an `http://` and a `\\...` `<simpleLocation>`); only the HTTP portion needs zoning. `.lnk` is SMB-only. `.url` is HTTP-only.
- `linksiren listen` reframed as a development / testing surface. In real engagements, use `ntlmrelayx` or `krbrelayx`, which both relay AND save NTLMSSP blobs by default.
- References for how to get intranet-zoned added across the docs (blog walkthrough, `krbrelayx dnstool.py`, DDSpoof, Responder).
- Retired the TODO checklist, the duplicated `jq` snippet block (now only in `docs/TROUBLESHOOTING.md`), the pre-0.10.0 `<details>` `--help` blocks, and the "What Payload Type Should I Use?" paragraph (in `docs/DEPLOY.md`).

## [0.10.0] - 2026-06-27
### Added
- `linksiren listen`: HTTP confirmation listener that captures NTLMSSP Type-1 / Type-3 from coercion attempts. Optional `--blobs-dir` saves Type-3 blob bodies for hashcat / ntlmrelayx hand-off.
- `linksiren detect`: blue-team payload scanner. Walks SMB shares and flags files matching coercion-payload signatures with severity, embedded URL, and attacker host. Allowlist support via `--include-host-allowlist`.
- `linksiren report`: generate `engagement_report.md` from sidecars (`payloads_written.txt`, `encrypt_triggered_hosts.txt`, `efs_started_by_us.txt`, `payloads_not_deleted.txt`, `detect_findings.txt`, `coerce_captures.log`) plus `linksiren.log`.
- `docs/subcommands/{listen,detect,report}.md` and `docs/TROUBLESHOOTING.md`.

### Changed
- README restructured: AI-first prose section at the top covering the typical agent prompt; expanded Features list linking into `docs/`.

## [0.9.1] - 2026-06-27
### Added
- `cleanup --stop-webclient`: stop the WebClient service via MS-SCMR after deleting payloads. Unlike EFS, WebClient accepts SCMR STOP under normal Windows configuration.

### Changed
- `cleanup` now verifies each delete by post-probing with an exact-filename `listPath`. Any leftover surfaces in `payloads_not_deleted.txt` and a CRITICAL log entry.
- Generic `_service_stop(svc_name)` helper factored out of `_efs_service_stop`. Both `_efs_service_stop` and the new `_webclient_service_stop` are thin wrappers.

## [0.9.0] - 2026-06-27
### Added
- `deploy --randomize-suffix`: per-file 4-char `[A-Z0-9]` suffix on filename AND every URL path in the payload, defeats Explorer / WebDAV / browser per-name caches.
- `deploy --template PATH` (also `target-sessions --template`): custom template file. Extension must match `-n`.
- `deploy --max-concurrency N` and `cleanup --max-concurrency N`: flag plumbing for per-host parallelism. Default 1 = serial.
- Top-level `-q` / `--quiet`: gate `pure_functions.info_print` so informational stdout is suppressed; warnings, errors, and explicit `--json` / dry-run output still print.

### Changed
- Deploy emits a WARNING at start time when `-a` is an IP literal or FQDN (which land in the Internet zone). Use a bare hostname or pre-stage ZoneMap entries.

## [0.8.0] - 2026-06-27
### Added
- `linksiren target-sessions`: per-host, enumerate real users under `C$\Users` and drop the payload in each matching user`s Desktop folder. Selectors: `--users <regex>` (default `.*`), `--users-file <path>`, `--public-desktop`. Reuses every deploy flag (encrypt, invisible, probe-delete, dry-run, resume, rate-limit, jitter).
- `target._enumerate_user_desktops` + `SYSTEM_USER_FOLDERS` constant: enumerates user-Desktop paths under C$\Users with case-insensitive regex filtering and system-folder exclusion.

## [0.7.0] - 2026-06-27
### Added
- `linksiren discover`: enumerate computer objects from Active Directory via LDAP. Filters disabled accounts; optional `--inactive-days N` drops dormant hosts. Emits one `\\<dnsHostName>` UNC per line (or bare hostnames with `--hostname-only`). Supports `--ldaps`, `--base-dn`, `-o PATH`, `--json`.

## [0.6.0] - 2026-06-27
### Added
- `linksiren check`: per-host preflight that reports auth result, SMB signing required, listable disk shares, EFS / WebClient service state, and per-file-type coercion viability for `.url` / `.searchConnector-ms` / `.library-ms` / `.lnk`. Output as human-readable or `--json`.
- `_webclient_service_is_running` helper: probes `\PIPE\DAV RPC SERVICE` to determine if WebClient is up without requiring SCMR rights.
- Fragile-infrastructure pattern flags on hostname / share-name detection (SCADA / ICS / OT / medical / safety patterns).

## [0.5.0] - 2026-06-27
### Added
- `--exclude PATTERN ...` (rank / identify / deploy): case-insensitive glob patterns matched against share-relative folder paths.
- Built-in default exclude list (`node_modules`, `vendor`, `.git`, `$Recycle.Bin*`, `System Volume Information`, `__pycache__`, etc.). Opt out with `--exclude-defaults-off`.
- `--max-host-time SECONDS` (rank / identify): flag and arg plumbing for capping per-host crawl time. Integration with the crawl scheduler ships in a follow-up.
- `deploy --dry-run`: print every payload that WOULD be written without actually connecting via SMB.
- `deploy --resume`: skip target paths already present in `payloads_written.txt`.
- `deploy --rate-limit OPS_PER_SEC` and `deploy --jitter-ms MIN,MAX` for stealth pacing.
- DFS namespace dedup helper (`_dfs_resolve` via `FSCTL_DFS_GET_REFERRALS`). `--no-dfs-dedup` flag exposed; full integration into the crawl path ships in a follow-up.

## [0.4.0] - 2026-06-27
### Added
- `linksiren coerce` subcommand: wakes the EFS service on each target host without dropping a payload, reusing the existing-file trigger from 0.3.0. Records `encrypt_triggered_hosts.txt` and `efs_started_by_us.txt` so cleanup can revert state cleanly.
- `cleanup --stop-efs`: stops the EFS service via MS-SCMR over `\PIPE\svcctl`. Only stops on hosts where the matching `deploy` / `coerce` recorded EFS as initially-Stopped (strict subset; never touches services that were already Running pre-engagement). Honest by-design reporting: on modern Windows the EFS service`s `dwControlsAccepted` bitmask omits STOP and the call returns `ERROR_INVALID_SERVICE_CONTROL`; linksiren surfaces this clearly rather than retrying.
- `--json` output flag for `identify` and `deploy` for structured tool composition.

## [0.3.0] - 2026-06-27
### Added
- `deploy --encrypt`: wakes the triggered-start EFS service on the target so `\PIPE\efsrpc` becomes available for follow-on coercion (Coercer, PetitPotam). Two trigger-target modes selected with `--encrypt-target`:
  - `payload` (default): passes `FILE_ATTRIBUTE_ENCRYPTED` (0x4000) on the SMB CREATE for the payload itself, then reverts via `EfsRpcDecryptFileSrv` so the payload lands plaintext.
  - `existing`: writes the payload plain, briefly creates+deletes a hidden throwaway file with the encryption bit to wake EFS, then EFSR-encrypts+decrypts the smallest non-empty existing file in the target folder.
- `deploy --encrypt-keep`: opts into keeping the trigger file visibly EFS-encrypted on disk (attribute `Ae`).
- Per-engagement sidecar `encrypt_triggered_hosts.txt` recording every host where an `--encrypt` trigger was fired.
- `docs/DETECTION.md`: blue-team-facing artifact reference. Currently covers `deploy --encrypt`; later releases extend it.

### Changed
- `docs/DEPLOY.md` extended with the EFS section.

## [0.2.0] - 2026-06-27
### Added
- `deploy --force`: explicit opt-in to overwrite an existing file at the target path. Without it, deploy logs a WARNING and skips rather than clobbering real user data with a same-named payload.
- `deploy --invisible`: cosmetic Desktop-placement transform. Prepends `U+200B` (ZERO WIDTH SPACE) to the filename so the label below the icon renders empty, and blanks the `<iconReference>` / `IconFile` / `IconIndex` inside `.library-ms` / `.searchConnector-ms` / `.url` payloads so the tile renders transparent. Does NOT set `FILE_ATTRIBUTE_HIDDEN` (which would hide the file from Explorer's enumeration and break the coercion trigger).
- `deploy --probe-delete`: write a uniquely-named probe file first and try to delete it before the real payload. Skips the real write if the probe round-trip fails, avoiding undeletable artifacts on shares where the pentester has write but not delete permission.
- `docs/AUTHENTICATION.md` and `docs/DEPLOY.md` (new). README now links to `docs/` for per-area reference.

### Changed
- README slimmed: the inline `# Authentication` section is now `docs/AUTHENTICATION.md`. A new `# Features` block at the top of the file links into `docs/`.

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
