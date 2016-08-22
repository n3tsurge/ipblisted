#
# ipblisted - A python tool to check an IP against black lists
# Author: Brian Carroll
# Created: 2016-07-18
# Modified: 2016-07-18
# Version: 0.8
#

import os
import re
import csv
import sys
import time
import json
import urllib
import requests
import datetime
import threading
import collections
import dns.resolver
import requests_cache
from Queue import Queue
from requests.auth import HTTPProxyAuth
from requests import exceptions as rexp
from optparse import OptionParser as op
from netaddr import IPSet, IPNetwork, IPAddress

# Color Codes
RED = 31
BLUE = 34
GREEN = 33


class FeedThread(threading.Thread):
    '''
    A wrapper class making the Feed object thread friendly
    '''
    def __init__(self, ip, options, q, oq):
        self.q = q
        self.ip = ip
        self.oq = oq
        self.options = options
        threading.Thread.__init__(self)

    def run(self):
        while True:
            if not self.q.empty():
                feed = self.q.get()
                result = {"name": feed.name, "found": feed.check_ip(self.ip,self.options)}
                self.oq.put(result)
            else:
		break
        return
	     
    
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


def load_feeds(skip=None):
    '''
    Reads in the JSON formatted feeds and builds objects for each feed
    '''

    data = json.loads(open('feeds.json', 'r').read())["feeds"]
    feeds = [Feed(f) for f in data]

    # Skip DNSBL type feeds if the user wants to
    if skip["skip_dnsbl"]:
        cprint("[!] Skipping DNS based blacklist checks", BLUE)
        feeds = [f for f in feeds if f.type != "dns"]
    
    # Skip list based feeds if the user wants to
    if skip["skip_bl"]:
        cprint("[!] Skipping list based blacklist checks", BLUE)
        feeds = [f for f in feeds if f.type != "list"]
    
    return feeds


def cprint(text, color_code=39):
    '''
    Prints things in pretty colors, because colors are cool
    '''
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        print(text)
    else:
        print('\x1b[%dm%s\x1b[0m') % (color_code, text)


def convert_results(results, ip, outfile, outformat="csv"):
    '''
    Converts the results to an outfile that the user declared
    :param results: The array of dictionary results
    :param outfile: The name of the file the user wishes to write to
    :param outformat: The format the user wants to write in
    '''

    # Get a current timestamp because it will be used in output rows to dictate when the check
    # was run against the result
    current_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if outformat == "csv":

        # Pivot the result
        new_result = {result.get('name'): result.get('found') for result in results}

        # Add a field for the IP address
        new_result["ip"] = ip

        # Add a field for the date the IP was last scanned
        new_result["scan_date"] = current_date

        # Add a field for the number of lists the IP shows up on
        new_result["lists_on"] = len([result for result in results if result.get('found') == "Found"])
        
        field_names = [field for field in new_result]

        # Move IP and Scan Date to the front of the header
        field_names.insert(0, field_names.pop(field_names.index('ip')))
        field_names.insert(1, field_names.pop(field_names.index('scan_date')))
        field_names.insert(2, field_names.pop(field_names.index('lists_on')))

        # Check if the file already exists, if not created it
        # If it does, open it in append mode
        if not file_exists(outfile):
            fh = open(outfile, 'wb')
        else:
            fh = open(outfile, 'a')

        # Declare the dictionary writer
        writer = csv.DictWriter(fh, delimiter=',', fieldnames=field_names)

        # If the file was opened in write binary mode, add the CSV header
        if fh.mode == 'wb':
            writer.writeheader()
        
        writer.writerow(new_result)

        fh.close()


def file_exists(filename):
    '''
    Checks to see if a file already exists
    '''

    try:
        file = open(filename)
        return True
    except Exception as e:
        return False
    return False


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
    parser.add_option('--cache-timeout', default=60*60*12, action="store", dest="cache_timeout", help="Number of seconds before cache results are to expire (Default: 12 hours)")
    parser.add_option('--threads', default=5, action="store", dest="threads", help="Sets the number of feed search threads")
    parser.add_option('--infile', default=None, action="store", dest="infile", help="A newline separated list of IP addresses")
    parser.add_option('--ip', action="store", dest="ip")
    parser.add_option('-f', '--format', action="store", dest="format", help="Set the output format for an outfile", default="csv")
    parser.add_option('-o', '--outfile', action="store", dest="outfile", help="Where to write the results", default=None)
    (options, args) = parser.parse_args()

    if options.format:
        allowed_formats = ['csv', 'xls', 'xlsx', 'txt']
        if not options.format in allowed_formats:
            cprint("[!] Invalid format \"{}\".  Please select a valid format {}".format(options.format, ', '.join(allowed_formats)), RED)
            sys.exit(1)

    if options.outfile:
        print("[*] Results will be saved to {} in {} format".format(options.outfile, options.format))

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
        elif len(options.ip.split(',')) > 0:
            ips += [ip for ip in options.ip.split(',') if ip != '']  # Handles when user does ,%20 
        else:
            ips += [options.ip]

    # If the user supplied a file load these as well
    if options.infile:
        ips += [ip for ip in file(options.infile).read().split('\n') if ip != '']

    # Check if the user set their credentials when using a proxy
    if options.proxy:
        if options.proxy_user is None or options.proxy_pass is None:
            cprint("[!] Warning, no proxy credentials supplied.  Authenticated proxies may not work.", BLUE)
        else:
            options.proxy_pass = urllib.quote(options.proxy_pass)

    # Initialize a queue for the feeds to go in
    fq = Queue()

    # Load in all the feeds from the feed configuration file
    feeds = load_feeds({"skip_bl": options.skip_bl, "skip_dnsbl": options.skip_dnsbl})

    # Establish the requests cache
    if not options.no_cache:
        requests_cache.install_cache('ipblisted', expire_after=int(options.cache_timeout))

        # If the user wants to manually clear the cache, do it now
        if options.clear_cache:
            requests_cache.clear()

    # If there are no feeds set, just exit the program
    if len(feeds) == 0:
        cprint("[!] No feeds were defined, please define them in feeds.json or don't skip them all.", RED)
        sys.exit(1)

    feed_results = []

    # Loop through each IP and find it
    print("[*] Checking {} IP addresses against {} lists".format(len(ips), len(feeds)))
    for ip in ips:

        print("[*] Searching Blacklist feeds for IP {ip}".format(ip=ip))

        # Build the feed requests queue
        oq = Queue()

        # Create a queue of all the feeds we want to check
        [fq.put(f) for f in feeds]
	qsize = fq.qsize()

        # Start up our threads and start checking the feeds
	threads = [FeedThread(ip, options, fq, oq) for i in range(0,options.threads)]
        [t.start() for t in threads]
        [t.join() for t in threads]

        # Set the number of lists we have found to 0
        find_count = 0

        # Go through each feed and see if we find the IP or block
        results = [r for r in oq.queue]

        if options.outfile:
            convert_results(results, ip, options.outfile)

        # Print out if the IP was found in any of the feeds
        for result in results:

            output = "[*] {name}: {found}".format(**result)

            if result["found"] == "Found":
                find_count += 1
                cprint(output,RED)
                continue

            if options.show_good:
                cprint(output)

        if find_count == 0:
            cprint("[*] Not found on any defined lists.", GREEN)
        else:
            cprint("[*] Found on {}/{} lists.".format(find_count,qsize), RED)
        print("[-]")


if __name__ == '__main__':
    main()
