# ipblisted
A python script to check an IP against blacklists

## Demo 
![Demo Image](https://github.com/krypticnetworks/ipblisted/blob/master/demo.gif)

## Usage
ipblisted supports checking a single IP address, a file containing a list of IP addresses, or an entire CIDR block

### Single IP
```
python ipblisted.py --ip 4.2.2.2
```

### Searching a CIDR block
```
python ipblisted.py --ip 198.199.134.0/24
```

### Searching from a file list
```
python ipblisted.py --infile ips.txt
```

## Sample Output
```
brian@securitas:~/Scripts/ipblisted$ python ipblisted.py --ip 202.191.62.113 --good
[*] Searching Blacklist feeds for IP 202.191.62.113
[*] Emerging Threats: No Result
[*] TOR Exit Nodes: Skipped - Disabled
[*] AlienVault: No Result
[*] BlocklistDe: No Result
[*] Dragon Research Group - SSH: No Result
[*] Dragon ResearchGroup - VNC: No Result
[*] OpenBlock: No Result
[*] NoThink- Malware: No Result
[*] NoThink - SSH: No Result
[*] antispam.imp.ch: No Result
[*] Dshield: No Result
[*] malc0de: No Result
[*] MalwareBytes: Found
[*] SpamHaus Drop: No Result
[*] SpamHaus eDrop: No Result
[*] Found on 1/15 lists.
```

## Optional Arguments
There are several optional arguments you can pass to ipblisted
- --proxy - This will let you set a proxy
- --proxy_user - This is necessary if you are behind an authenticated proxy
- --proxy_pass - Associated with the user on the authenticated proxy
- --ip - A single IP or CIDR 
- --infile - A file listing a range of IP addresses you wish to check
- --good - This flag will show lists that don't contain the IP
