# LinkSiren

## What is this tool?

LinkSiren distributes .url files to accessible file shares to coerce NTLM authentication from hosts that open them, like [Farmer](https://github.com/mdsecactivebreach/Farmer/tree/1f37598125a92c9edf41295c6c1b7c258143968d), [Lnkbomb](https://github.com/dievus/lnkbomb), or [Slinky](https://www.infosecmatter.com/crackmapexec-module-library/?cmem=smb-slinky).

## How is this better than other tools?
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
- [ ] Enable ticket based authnentication (Kerberos)
- [ ] Multithreading/Multiprocessing for faster share crawling

## Note
This tools is designed for ethical hacking and penetration testing. It should be used exclusively on networks where explicit, written permission has been granted for testing. I accept no responsibility for the safety or effectiveness of this tool. Please don't sue me.
