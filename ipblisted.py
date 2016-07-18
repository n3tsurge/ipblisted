#
# ipblisted - A python tool to check an IP against black lists
# Author: Brian Carroll
# Created: 2016-07-18
# Modified: 2016-07-18
# Version: 0.5
#

import os
import re
import sys
import json
import urllib
import requests
import requests_cache
import dns.resolver
from netaddr import IPSet, IPNetwork, IPAddress
from requests.auth import HTTPProxyAuth
from requests import exceptions as rexp
from optparse import OptionParser as op

# Color Codes
RED = 31
BLUE = 34
GREEN = 33

class Feed(object):
    '''
    Creates a Feed object that allows for easier interaction with each
    individual blacklist feed
    '''
    def __init__(self, data):
        '''
        Initializes the Feed object
        :param data: A JSON formatted string that builds the object
        '''
        self.__dict__.update(data)

    def check_ip(self, ip, options=None, *args, **kwargs):
        if self.type == "list":
            return self.check_ip_list(ip, options, *args, **kwargs)
        elif self.type == "dns":
            return self.check_ip_dns(ip, options, *args, **kwargs)


    def check_ip_list(self, ip, options=None, *args, **kwargs):
        '''
        Checks a given IP against the blacklist
        :param self:
        :param ip: The IP address that we want to look for
        :param options: The OptParse options from the main() function
        :return Found|No Result:
        '''

        session = requests.Session()

        # Skip the feed if it is disabled in config
        if hasattr(self, "disabled") and self.disabled:
            return "Skipped - Disabled"

        # If the user supplied a proxy, set the proxy information for requests
        if options.proxy:
            session.proxies = {"http": options.proxy, "https": options.proxy}
            session.auth = HTTPProxyAuth(options.proxy_user, options.proxy_pass)

        # Try to pull down the data from the feed URL
        try:
            result = session.get(self.url)
            if result.status_code == 200:

                # If the threat feed is in CIDR notation, pull all the listed subnets
                # then see if the IP is a member of each one, if we find it stop checking
                # If NOT CIDR notation, do the normal IP check
		if self.format == "cidr":
                    for cidr in [IPNetwork(cidr) for cidr in re.findall("((?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?))", result.content)]:
                        if IPAddress(ip) in cidr:
                            return "Found"
                    return "No Result"
                else:
                    matches = re.findall(ip, result.content)
                if matches:
                    return "Found"
                else:
                    return "No Result"
            else:
                cprint("[!] There was an issue attemping to connect to: {url}".format(url=self.url), RED)
                return "Error"
        except rexp.ConnectionError as e:
            cprint("[!] There was an issue attemping to connect to: {url}".format(url=self.url), RED)
            return "Error"

    def check_ip_dns(self, ip, options=None, *args, **kwargs):
        '''
        Checks a given IP against a DNSBL (DNS Blacklist)
        :param self:
        :param ip:  The IP we are looking for
        :param options:  The OptParse options from the main() function
        :return Found|No Result|Timeout|No Answer
        '''

        try:
        # Build our resolver
            r = dns.resolver.Resolver()

        # Create a reverse DNS query for the IP in question
            query = '.'.join(reversed(str(ip).split("."))) + "." + self.url
            r.timeout = 5
            r.lifetime = 5

            # Check for any A and TXT records matching the reverse record
            answers = r.query(query, "A")
            answers_txt = r.query(query, "TXT")

            # Return a Found response if we have anythin in either list
            if answers or answers_txt:
                return "Found"

        except dns.resolver.NXDOMAIN:
            return "Not Found"
        except dns.resolver.Timeout:
            return "Timeout"
        except dns.resolver.NoAnswer:
            return "No Answer"
        except dns.resolver.NoNameservers:
            return "No Name Servers"


def load_feeds():
    '''
    Reads in the JSON formatted feeds and builds objects for each feed
    '''
    data = json.loads(open('feeds.json', 'r').read())["feeds"]
    return [Feed(f) for f in data]


def cprint(text, color_code=39):
    '''
    Prints things in pretty colors, because colors are cool
    '''
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        print(text)
    else:
        print('\x1b[%dm%s\x1b[0m') % (color_code, text)


def main():
    '''
    Our main application
    '''

    parser = op("usage ipblisted.py --ip [ip]")
    parser.add_option('--proxy', action="store", dest="proxy", help="Useful for when behind a proxy")
    parser.add_option('--proxy_user', action="store", dest="proxy_user")
    parser.add_option('--proxy_pass', action="store", dest="proxy_pass")
    parser.add_option('--good', default=False, action="store_true", dest="show_good", help="Displays lists that the IP did NOT show up on.")
    parser.add_option('--skip-dnsbl', default=False, action="store_true", dest="skip_dnsbl", help="Skips the checking DNS Blacklists")
    parser.add_option('--skip-bl', default=False, action="store_true", dest="skip_bl", help="Skips the checking of text based blacklists")
    parser.add_option('--no-cache', default=False, action="store_true", dest="no_cache", help="This will prevent caching of text based blacklists")
    parser.add_option('--clear-cache', default=False, action="store_true", dest="clear_cache", help="This will clear the existing cache")
    parser.add_option('--cache-timeout', default=300, action="store", dest="cache_timeout", help="Number of seconds before cache results are to expire")
    parser.add_option('--infile', default=None, action="store", dest="infile", help="A newline separated list of IP addresses")
    parser.add_option('--ip', action="store", dest="ip")
    (options, args) = parser.parse_args()

    # Check if the user supplied an IP address or IP block
    if options.ip is None and options.infile is None:
        print("[!] You must supply an IP address or a file containing IP addresses.")
        sys.exit(1)

    # Set our list of IPs to an empty list
    ips = []

    # Load up the IP in the --ip flag
    if options.ip:
	if '\\' in options.ip or '/' in options.ip:
	    cprint("[!] Detected CIDR notation, adding all IP addresses in this range", BLUE)
            for ip in IPSet([options.ip]):
                ips += [str(ip)]
        else:
            ips += [options.ip]

    # If the user supplied a file load these as well
    if options.infile:
        ips += [ip for ip in file(options.infile).read().split('\n') if ip != '']

    # Check if the user set their credentials when using a proxy
    if options.proxy:
        if options.proxy_user is None or options.proxy_pass is None:
            print("[!] Warning, no proxy credentials supplied.  Authenticated proxies may not work.", BLUE)
        else:
            options.proxy_pass = urllib.quote(options.proxy_pass)

    # Load in all the feeds from the feed configuration file
    feeds = load_feeds()

    # If the user has the skip-dnsbl flag set, let them know it
    if options.skip_dnsbl:
        cprint("[!] Skipping DNS based blacklist checks", BLUE)

    # If the user has the skip-bl flag set, let them know it
    if options.skip_bl:
        cprint("[!] Skipping list based blacklist checks", BLUE)

    # Establish our cache
    if not options.no_cache:
        requests_cache.install_cache('ipblisted', expire_after=int(options.cache_timeout))

        # If the user wants to manually clear the cache, do it now
        if options.clear_cache:
            requests_cache.clear()

    # If the user is skipping certain feed types, exclude them
    if options.skip_dnsbl:
        feeds = [f for f in feeds if f.type != "dns"]
    if options.skip_bl:
        feeds = [f for f in feeds if f.type != "list"]

    # If there are no lists set, just exit the program
    if len(feeds) == 0:
        cprint("[!] No feeds were defined, please define them in feeds.json or don't skip them all.", RED)
        sys.exit(1)

    # Loop through each IP and find it
    print("[*] Checking {} IP addresses against {} lists".format(len(ips), len(feeds)))
    for ip in ips:

        print("[*] Searching Blacklist feeds for IP {ip}".format(ip=ip))

        # Set the number of lists we have found to 0
        find_count = 0

        # Go through each feed and see if we find the IP or block
        for f in feeds:

            ip_found = f.check_ip(ip, options=options)
            output = "[*] {}: {}".format(f.name, ip_found)

            if ip_found == "Found":
                find_count += 1
                cprint(output,RED)
                continue

            if options.show_good:
                cprint(output)

        if find_count == 0:
            cprint("[*] Not found on any defined lists.", GREEN)
        else:
            cprint("[*] Found on {}/{} lists.".format(find_count,len(feeds)), RED)
        print("[-]")

if __name__ == '__main__':
    main()
