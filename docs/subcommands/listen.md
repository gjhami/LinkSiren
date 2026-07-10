# `linksiren listen`

Lightweight HTTP listener that captures NTLMSSP Type-1 / Type-3 from victims responding to coercion attempts.

## When to use

For development, testing, and coercion-viability sanity checks. In a real engagement, use [`ntlmrelayx`](https://github.com/fortra/impacket) (NTLM) or [`krbrelayx`](https://github.com/dirkjanm/krbrelayx) (Kerberos) instead. Both of those tools relay the inbound auth AND write the NTLMSSP blobs to disk by default, so you get relay-derived access AND cracking material without needing a second listener.

`listen` exists so you can iterate on payloads and check that coercion is firing without standing up a relay chain. It has no advantage over `ntlmrelayx` / `krbrelayx` when you actually want to use captures.

## Usage

```bash
linksiren listen [-p PORT] [--bind ADDR] [-o PATH] [--blobs-dir DIR]
```

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port` | 80 | TCP port. |
| `--bind` | 0.0.0.0 | Bind address. |
| `--timeout` | 0 (forever) | Exit after N seconds. |
| `-o` / `--output` | `coerce_captures.log` | Append captures here. |
| `--blobs-dir` | (none) | Dump Type-3 blobs here for hashcat / ntlmrelayx hand-off. |

Captures include timestamp, source IP, request line, UA, and the NTLMSSP base64 blob.
