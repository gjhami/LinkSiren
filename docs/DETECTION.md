# Detection notes

Blue-team-facing artifact reference for every linksiren operation.

## `deploy --encrypt` (0.3.0+)

### What you'll see

| Layer | Signal |
|---|---|
| EFS service | Goes from Stopped to Running. Service start is via the EFS SCM trigger (FILE_ATTRIBUTE_ENCRYPTED on CREATE), so the event source is `Service Control Manager` rather than direct `sc start`. |
| `\PIPE\efsrpc` | Becomes available on the host after the trigger fires. Useful as a post-event marker. |
| File attributes | Trigger files briefly carry `FILE_ATTRIBUTE_ENCRYPTED` (0x4000) during the encrypt-then-decrypt cycle. With `--encrypt-keep`, the file stays `Ae`. |
| MS-EFSR RPC | `EfsRpcEncryptFileSrv` (opnum 4) and `EfsRpcDecryptFileSrv` (opnum 5) called over `\PIPE\efsrpc` or `\PIPE\lsarpc`. RPC auth level is PKT_PRIVACY (encrypted on the wire). |
