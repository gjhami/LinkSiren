# `linksiren listen`

Lightweight HTTP listener that captures NTLMSSP Type-1 / Type-3 from victims responding to coercion attempts.

## When to use

Almost never as your primary capture path. In a real engagement you relay the inbound auth with [`ntlmrelayx`](https://github.com/fortra/impacket) (NTLM) or [`krbrelayx`](https://github.com/dirkjanm/krbrelayx) (Kerberos) so the coerced session becomes an authenticated session on a target of your choice. `listen` is useful as:

* An offline archive of every NTLMSSP blob for hashcat cracking or later replay.
* A confirmation surface when you are testing coercion viability and do not want to stand up a full relay yet.
* A fallback when the relay target isn't reachable.

Run `ntlmrelayx` first; run `listen` alongside if you want the archive.

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
