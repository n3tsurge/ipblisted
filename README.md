# ipblisted
A python script to check an IP against blacklists.  Inspired by [isthisipbad](https://github.com/jgamblin/isthisipbad) and adapted to be a little more complete.

## Demo 
![Demo Image](https://github.com/krypticnetworks/ipblisted/blob/master/demo.gif)

## Changelog

**2016-07-19**
- Added threading to the application.  By default there are 5 threads, the user can set the number of threads using the --thread flag


## Open Tasks
- Add an option to throttle the checks 
- Add an option to cache DNS A and TXT results to match their TTL

## Requirements
ipblisted has a few requirements.  I am working to reduce these requirements as much as possible.
- requests
- requests_cache
- netaddr

## Usage
ipblisted supports checking a single IP address, a file containing a list of IP addresses, or an entire CIDR block, or a combination of each

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
```
brian@securitas:~/Scripts/ipblisted$ python ipblisted.py -h
Usage: usage ipblisted.py --ip [ip]

Options:
  -h, --help            show this help message and exit
  --proxy=PROXY         Useful for when behind a proxy
  --proxy_user=PROXY_USER
  --proxy_pass=PROXY_PASS
  --good                Displays lists that the IP did NOT show up on.
  --skip-dnsbl          Skips the checking DNS Blacklists
  --skip-bl             Skips the checking of text based blacklists
  --no-cache            This will prevent caching of text based blacklists
  --clear-cache         This will clear the existing cache
  --cache-timeout=CACHE_TIMEOUT
                        Number of seconds before cache results are to expire
  --infile=INFILE       A newline separated list of IP addresses
  --ip=IP               
```
