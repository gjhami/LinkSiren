# `linksiren discover`

Enumerate computer objects from Active Directory via LDAP. Output is a targets file ready for `rank` / `identify` / `coerce`.

## Usage

```bash
linksiren discover [domain/]user:password -dc-ip <kdc-or-fqdn> [options]
```

| Flag | Default | Description |
|---|---|---|
| `--base-dn` | derived from `credentials.domain` | LDAP search base. |
| `--ldaps` | off | Use LDAPS (636) instead of LDAP (389). |
| `--inactive-days N` | 0 (off) | Drop computers whose `lastLogonTimestamp` is older than N days. |
| `--hostname-only` | off | Output bare hostnames instead of `\\host` UNCs. |
| `-o PATH` | stdout only | Write to file in addition to stdout. |
| `--json` | off | Structured output. |

Disabled accounts (`userAccountControl` bit 2 set) are always filtered out.

## Auth

NTLM password, PtH, Kerberos. Anonymous LDAP binds are typically refused by modern AD.

When `-k` is used with an IP-form `-dc-ip`, linksiren reverse-DNSes the IP to an FQDN for the `ldap/<host>` SPN; if reverse DNS fails it logs a warning and the tester is expected to pass `--dc-ip <fqdn>` explicitly.
