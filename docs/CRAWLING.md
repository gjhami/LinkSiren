# Crawling tuning

Options for shaping how `rank` and `identify` walk shares and how
`deploy` paces SMB writes.

## Exclude patterns

`--exclude PATTERN [PATTERN ...]` skips folders whose share-relative
path matches any glob. Case-insensitive. Matches against the full
path AND each segment, so `*backup*` catches any folder in the chain
containing `backup`.

## Default excludes

`rank`, `identify`, and `deploy` skip a built-in noise list by
default: `node_modules`, `vendor`, `.git`, `.svn`, `.hg`,
`$Recycle.Bin*`, `System Volume Information`, `__pycache__`,
`.vscode`, `.idea`, `.DS_Store`, `Thumbs.db`. Pass
`--exclude-defaults-off` to disable.

## Host time budget

`--max-host-time SECONDS` (flag plumbing; scheduler integration in
a later release). Intended to abort the crawl on a single host once
the budget is exhausted.

## DFS namespace dedup

The `_dfs_resolve` helper issues `FSCTL_DFS_GET_REFERRALS` and parses
MS-DFSC referral responses. `--no-dfs-dedup` is exposed; full crawl
integration ships in a later release.

## Pacing

| Flag | Description |
|---|---|
| `deploy --rate-limit OPS_PER_SEC` | Cap deploy SMB writes at N operations per second. |
| `deploy --jitter-ms MIN,MAX` | Random sleep MIN..MAX milliseconds between writes. |
| `deploy --dry-run` | Print planned writes; skip SMB. |
| `deploy --resume` | Skip target paths already in `payloads_written.txt`. |
