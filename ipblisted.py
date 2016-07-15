import os
import re
import sys
import json
import urllib
import requests
from requests.auth import HTTPProxyAuth
from requests import exceptions as rexp
from optparse import OptionParser as op

RED = '31'
BLUE = '34'
GREEN = '33'

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
        '''
        Checks a given IP against the blacklist
        :param self:
        :param ip: The IP address that we want to look for
        :param options: The OptParse options from the main() function
        :return Found|No Result:
        '''
        if hasattr(self, "disabled") and self.disabled:
            cprint("[!] Skipping feed \"{}\" as it is disabled in the feed config.".format(self.name), BLUE)
        settings = {"url": self.url}
        if options.proxy:
            settings["proxies"] = {"http": options.proxy, "https": options.proxy}
            settings["auth"]  = HTTPProxyAuth(options.proxy_user, urllib.quote(options.proxy_pass))
        try:
            result = requests.get(**settings)
            if result.status_code == 200:
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
    parser.add_option('--ip', action="store", dest="ip")
    (options, args) = parser.parse_args()

    if options.ip is None:
        print("[!] You must supply an IP address")
        sys.exit(1)

    if options.proxy:
        if options.proxy_user is None or options.proxy_pass is None:
            print("[!] Warning, no proxy credentials supplied.  Authenticated proxies may not work.")
        else:
            options.proxy_pass = urllib.quote(options.proxy_pass)

    # Load in all the feeds from the feed configuration file
    feeds = load_feeds()

    find_count = 0

    print("[*] Searching Blacklist feeds for IP {ip}".format(ip=options.ip))

    for f in feeds:
        ip_found = f.check_ip(options.ip, options=options)
        output = "[*] {}: {}".format(f.name, ip_found)
        if ip_found == "Found":
            find_count += 1
            cprint(output,RED)
        if options.show_good:
            cprint(output)

    if find_count == 0:
        cprint("[*] Not found on any defined lists.", GREEN)
    else:
        cprint("[*] Found on {}/{} lists.".format(find_count,len(feeds)), RED)

if __name__ == '__main__':
    main()    
