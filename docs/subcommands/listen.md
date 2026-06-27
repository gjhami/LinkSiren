# `linksiren listen`

Lightweight HTTP listener that captures NTLMSSP Type-1 / Type-3 from victims responding to coercion attempts. Confirmation surface alongside `target-sessions` / `coerce`, not a Responder replacement.

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
