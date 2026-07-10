# `linksiren detect`

Blue-team-facing scanner: walks SMB shares and flags files matching coercion-payload signatures.

## Usage

```bash
linksiren detect [auth] -t <scan-targets-file> [--include-host-allowlist PATH] [-md DEPTH]
```

## Signatures

| Extension | Signature |
|---|---|
| `.url` | `URL=http://...` non-allowlisted, OR `IconFile=\\...` UNC. |
| `.searchConnector-ms` | `<url>http://...</url>` element. |
| `.library-ms` | Same as searchConnector. |
| `.lnk` | Embedded UNC in icon or target. |

## Output

`detect_findings.txt`: tab-separated per finding with UNC, signature class, embedded URL, attacker host, severity. `--json` adds structured stdout.

## Allowlist

`--include-host-allowlist PATH` reads one hostname/IP per line. Findings whose embedded host appears in the allowlist are reported at INFO instead of WARNING.
