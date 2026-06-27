# Troubleshooting

LinkSiren writes a structured JSON log at `linksiren.log`. Each event has `Timestamp`, `Level`, `Message`, `Path`, `User`, `Mode`, and (where applicable) `Exception` fields.

## Useful jq snippets

```bash
# Filter by target
cat linksiren.log | jq '. | select(.Path | startswith("\\\\10.0.1.126"))'

# Filter by log level
cat linksiren.log | jq '. | select(.Level == "ERROR")'

# Time window: ISO 8601 start..end as epoch
cat linksiren.log | TZ=UTC jq '. | select(.Timestamp + "Z" | fromdateiso8601? > 1 and fromdateiso8601? < 9999999999)'
```

## Common issues

| Symptom | Likely cause |
|---|---|
| `STATUS_OBJECT_NAME_INVALID` on filename | Invalid character. ZWSP via `--invisible` is supported; ASCII control chars (\x01-\x1F) are rejected by Win11 SMB. |
| Coercion fires but no creds at listener | Attacker URL not in Intranet zone. Use a bare hostname or stage ZoneMap. See `docs/AUTHENTICATION.md`. |
| `Refusing to overwrite existing file` WARNING | Add `--force` to overwrite. |
| `--encrypt` returns `STATUS_ACCESS_DENIED` | Calling account has no EFS certificate. Use a domain user with one. |
| `--stop-efs` says "by-design rejection" | Modern Windows EFS does not accept SCMR STOP. The message is honest, not a bug. |
