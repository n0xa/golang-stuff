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
* vthash.go is a command-line tool to gather the list of detections from VirusTotal for a given file or file hash. This allows security analysts to quickly size up an unknown file they have run across to see if it's been detected previously without firing up a web browser or uploading it.
