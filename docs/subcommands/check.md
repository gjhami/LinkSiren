# `linksiren check`

Per-host preflight: auth result, SMB signing required, listable disk shares, EFS / WebClient state, fragile-infrastructure flags, and per-file-type coercion viability.

## Usage

```bash
linksiren check -t <targets-file> [auth flags]
linksiren check --json -t <targets-file> [auth flags] | jq .
```

## Output sections

- **auth**: `ok` | `failed` | `unreached`
- **SMB signing required**: relay-relevant boolean
- **EFS / WebClient service state**: running / stopped / unknown via pipe-open probe
- **shares**: file-system shares only; fragile-pattern flags appended
- **fragile-infra hostname pattern**: SCADA, ICS, OT, medical, safety hits
- **payload viability**: per file extension, trigger type, intranet-zone requirement, readiness

## Auth

All four auth methods supported. Anonymous degrades gracefully (some fields may show as `unknown` if the NULL session can't probe service state).
