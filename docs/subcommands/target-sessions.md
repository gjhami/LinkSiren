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

The intranet-zone requirement applies **only to the HTTP / WebDAV path** (`.searchConnector-ms`, `.library-ms`, and `.url`). Windows only sends NTLM over HTTP when the attacker URL is in the victim's Intranet Zone. A bare hostname (no dots) is Intranet by default; FQDNs and IPs are not.

The **SMB path** (`.lnk` icon UNC, `.url` `IconFile=`) has no intranet-zone requirement. It fires against any attacker host the victim can reach on 445.

To get intranet-zoned:

* [DNS Hijacking: Say My Name](https://alittleinsecure.com/dns-hijacking-say-my-name/) - definitive walkthrough.
* [krbrelayx dnstool.py](https://github.com/dirkjanm/krbrelayx) - add DNS records to AD as a domain user.
* [DDSpoof](https://github.com/akamai/DDSpoof) - DHCP DNS record poisoning, often unauthenticated.
* [Responder](https://github.com/lgandx/Responder) - LLMNR / NBNS / mDNS poisoning fallback.

## Auth

All four auth methods supported for deploy. The coerced auth received at the listener is whatever the victim user's session holds.
