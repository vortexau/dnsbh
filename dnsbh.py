#!/usr/bin/env python

import hashlib
import urllib
import re
import os.path
from datetime import date

d = date.today()

bindzones = "/etc/bind/blockeddns.zones"
bindhosts = "/etc/bind/blockeddns.hosts"
bhdest = "/var/cache/dnsbh/"

total = 0;
urls = set()
# Some sourced from https://intel.criticalstack.com/feeds
# Others from Adblock Pro and uBlock Origin Chrome plugins
sources = [
    "https://hosts-file.net/download/hosts.txt",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt",
    "http://www.malwaredomainlist.com/hostslist/hosts.txt",
    "http://malwaredomains.lehigh.edu/files/immortal_domains.txt",
    "http://mirror1.malwaredomains.com/files/justdomains",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt",
    "https://raw.githubusercontent.com/Dawsey21/Lists/master/main-blacklist.txt"
]

for source in sources:
    print source
 
    hashname = hashlib.sha256(source)

    bhname = d.isoformat() + "-" + hashname.hexdigest()
    bhcache = bhdest + bhname

    if(os.path.isfile(bhcache)): 
        print "File already cached. Skipping download..."
    else:
        zones = urllib.URLopener()
        print "Retrieving " + source + ", saving to " + bhcache
        zones.retrieve(source, bhcache)

    # Grab the content of the downloaded/cached file

    with open(bhcache) as f:
        lines = f.read().splitlines()
        count = len(lines)
        total = total + count
        print "Found " + str(count) + " domains. Adding..."
        for line in lines:
            if re.match("^127.0.0.1\s\s", line):
                line = re.sub('127.0.0.1  ', '', line)
            if re.match("^localhost", line):
                continue
            if re.match("^\#+", line):
                continue
            if len(line) is 0:
                continue 

            urls.add(str.lower(line.strip()))

allcount = len(urls)

# Record format for BIND file is:
# zone "amazon.co.uk.security-check.ga"  {type master; file "/etc/namedb/blockeddomain.hosts";}; 

zones = set()
for url in urls:
    rec = "zone \"" + url + "\" {type master; file \"" + bindhosts + "\";}; \n"
    zones.add(rec)

print "Writing zonefile";
with open(bindzones, 'w+') as f:
    for zone in zones:
        f.write(zone)

print "Zone file " + bindzones + " written" 

print "Totals"
print "Domains: " + str(allcount) + " total"
print "All " + str(total) + " "
print "Dupes " + str(total - allcount) + " total"
print "Zone File entries: " + str(len(zones)) + " total"
