# `linksiren report`

Synthesize a markdown engagement summary from sidecar files and the JSON log.

## Usage

```bash
linksiren report [-o engagement_report.md] [--logfile linksiren.log]
```

## Sources read

- `payloads_written.txt`
- `payloads_not_deleted.txt`
- `encrypt_triggered_hosts.txt`
- `efs_started_by_us.txt`
- `detect_findings.txt`
- `coerce_captures.log` (from `linksiren listen` in the same directory)
- `linksiren.log` (JSON lines)

## Output

A single markdown file (default `engagement_report.md`) with sections for summary counts, payloads written, coercion captures, detect findings, service state changes, and log-level histogram.
