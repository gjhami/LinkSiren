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

`.searchConnector-ms` and `.library-ms` templates ship with both an `http://<attacker>/test1` and a `\\<attacker>\test2` `<simpleLocation>` entry. Windows fires both; the SMB URL fires without any zoning and captures NTLM against any attacker host reachable on 445. The HTTP URL only fires if the attacker URL is in the victim's Intranet Zone (bare hostname is Intranet by default; FQDNs and IPs are not) and it is the URL that starts the WebClient service.

`.lnk` fires over SMB (icon UNC). No zoning needed.

`.url` fires over HTTP by default (the built-in template's `IconFile=` points at a local Windows DLL). To get SMB out of `.url`, use `--template` with a custom file whose `IconFile=` points at an attacker UNC.

To get intranet-zoned for the HTTP portion:

* [DNS Hijacking: Say My Name](https://alittleinsecure.com/dns-hijacking-say-my-name/) - definitive walkthrough.
* [krbrelayx dnstool.py](https://github.com/dirkjanm/krbrelayx) - add DNS records to AD as a domain user.
* [DDSpoof](https://github.com/akamai/DDSpoof) - DHCP DNS record poisoning, often unauthenticated.
* [Responder](https://github.com/lgandx/Responder) - LLMNR / NBNS / mDNS poisoning fallback.

## Auth

All four auth methods supported for deploy. The coerced auth received at the listener is whatever the victim user's session holds.
