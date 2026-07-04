# `linksiren target-sessions`

Drop a coercion payload directly on each active user's Desktop on a given host. Coerces auth as soon as the user's Explorer renders the Desktop (or opens any parent folder containing the file).

## Mechanism

For each host in `-t`:
1. Enumerate `C$\Users` and filter out system folders (`Default`, `Public`, `defaultuser0`, `All Users`, `WDAGUtilityAccount`, etc.).
2. Filter remaining usernames against `--users` regex and any patterns in `--users-file`.
3. For each matching user, treat `C$\Users\<name>\Desktop` as a deploy target.
4. Optionally include `C$\Users\Public\Desktop` via `--public-desktop`.
5. Delegate to `deploy` so every deploy flag (encrypt, invisible, probe-delete, dry-run, resume, rate-limit, jitter) works identically.

## Trigger conditions per file type

| Extension | Fires when |
|---|---|
| `.url` | User opens the file (double-click, `ii`). Coerces HTTP NTLM. |
| `.searchConnector-ms` | User opens the parent folder (e.g., logs in and Desktop renders). Coerces WebDAV NTLM. |
| `.library-ms` | Same as `.searchConnector-ms`. |
| `.lnk` | User opens the parent folder. WebDAV first on Win11; SMB fall-through if WebClient is down. |

## Intranet zoning requirement

For HTTP / WebDAV coercion, the attacker hostname in the payload must be Intranet-zoned on the victim - a bare hostname (no dots) or a pre-staged ZoneMap entry. Otherwise Windows refuses to send NTLM cross-zone.

## Auth

All four auth methods supported for deploy. The coerced auth received at the listener is whatever the victim user's session holds.
