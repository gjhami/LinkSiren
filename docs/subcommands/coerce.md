# `linksiren coerce`

Wake the triggered-start EFS service on one or more target hosts so `\PIPE\efsrpc` becomes available for follow-on coercion (Coercer, PetitPotam) without leaving a payload behind.

## Usage

```bash
linksiren coerce -t <targets-file> [auth flags]
```

## Mechanism

For each target host:
1. Probe EFS service state via `\PIPE\efsrpc` accessibility.
2. If Stopped, briefly create+delete a hidden file with `FILE_ATTRIBUTE_ENCRYPTED` (0x4000) to trigger the EFS SCM service-start, then EFSR-encrypt+decrypt the smallest non-empty existing file in the target folder.
3. Record the host in `encrypt_triggered_hosts.txt`; if state transitioned Stopped → Running, also in `efs_started_by_us.txt`.

## Sidecars

- `encrypt_triggered_hosts.txt`: every host where a trigger fired.
- `efs_started_by_us.txt`: subset where we actually transitioned the service Stopped → Running. Used by `cleanup --stop-efs` for safe state revert.

## Auth

All four auth methods (NTLM password, Pass-the-Hash, Kerberos, anonymous) supported. EFSR calls require an account with an EFS certificate; lab `vagrant:vagrant` works, built-in `Administrator` typically does not.
