# GoLang-stuff
A collection of Go tools I make while I learn a little about GoLang.  
Mostly Work-In-Progress and tinkering with blue-team, threat intelligence things  

bgpview.io Tools
----------------
* ipasn.go lists BGP Autonomous System Numbers and info about an IP address
* asn.go lists IPv4 and IPv6 Prefixes (subnets) advertised as part of a given ASN

HPFeeds Tools
-------------
* hpfeeds-client.go is a reworked version of a broken, un-maintained HPFeeds implementation in go. I needed an easy way to just get the JSON Payload out of my Honeypot network. You can watch my MHN instance with it like this:
```
go run hpfeeds-client.go seckc-community fk6QgrnyvwbWSxCIwL5SIc2oARC4DXx46 mhn.h-i-r.net 10000 cowrie.sessions
```
or compile it first:
```
go build hpfeeds-client.go
./hpfeeds-client seckc-community fk6QgrnyvwbWSxCIwL5SIc2oARC4DXx46 mhn.h-i-r.net 10000 cowrie.sessions
```
You can also pass the output directly to formatting and query tools like `jq` or save the json for use later.  `jq '.peerIP,.urls'` for example, will list the attacking IP addresses and any payload URLs that the honeypot reported to HPFeeds

VirusTotal Tools
----------------
Before using these tools, you must register with VirusTotal, acquire an API key and export it in the VTAPI environment variable, such as in your .bashrc or .zshrc file.   
`export VTAPI=dab2_THIS_IS_AN_EXAMPLE_API_KEY_-_CHANGEME_e8e0496bcfce5e91f0000`  
* vthash.go is a command-line tool to gather the list of detections from VirusTotal for a given file or file hash. This allows security analysts to quickly size up an unknown file they have run across to see if it's been detected previously without firing up a web browser or uploading it.
* vtdomain.go is a command-line tool to fetch information about a domain name from VirusTotal. Work-In-Progress, using the newer VirusTotal API v3.  More details are available in the API, and I'll add parsing of those as I iterate.
* vtip.go queries IP address reputation and hostnames through VirusTotal's API. It will iterate through a configurable number of pages of passive DNS data (10 by default). Note that this tool can use a lot of your daily API request allocation, so tune the "maxpages" variable to suit your situation if you find the number of queries it makes to be too much.
