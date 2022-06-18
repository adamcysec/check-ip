# check-ip.py

## Synopsis
Reputation check an ip on services: [shodan](https://www.shodan.io/), [whois](https://www.arin.net/), [abuseIPDB](https://www.abuseipdb.com/).

## Description
Pass this tool one or more ips to check if it has been reported for malicious activity.

### Services:
**AbuseIPDB**
- checks the abuse score and returns the top 5 report comments for known bad activity.

**Whois**
- returns the age of the registration date.

**shodan**
- returns the open ports for the host.

## Setup
All you need to do is replace the file contents of `ipabuse_key.txt` with your AbuseIPDB private api key and replace the file contents of `shodan_key.txt` with your Shodan private api key. 

## Usage
**Parameter -ip**
- type : str
- one or more ips in csv format

**Parameter -f, --file**
- type : str
- the file path of your txt with one ip per line

**Example 1**

`py lookup-ip.py -ip "8.8.8.8"`

- look up on ip

**Example 2**

`py lookup-ip.py -ip "8.8.8.8, 8.8.4.4"`

- look up 2 or more ips in csv format

**Example 3**

`py lookup-ip.py -f ./ips.txt`

- look up all ips in a txt
- one ip per line

**Example Output**
```
Check: 8.8.8.8

SHODAN:
https://www.shodan.io/host/8.8.8.8
Open Port: 53 - dns-tcp
Open Port: 53 - dns-udp
Open Port: 443 - https

WHOIS:
https://search.arin.net/rdap/?query=8.8.8.8
Entry name: LVLT-GOGL-8-8-8
Registrant name: Google LLC
Days old: 3,017

IPABUSE:
https://www.abuseipdb.com/check/8.8.8.8
Abuse Score: 0
ISP: Google LLC
Domain: google.com
Host Name: ['dns.google']
---------------------------------------------------------------------

Check: 8.8.4.4

SHODAN:
https://www.shodan.io/host/8.8.4.4
Open Port: 53 - dns-tcp
Open Port: 53 - dns-udp
Open Port: 443 - https

WHOIS:
https://search.arin.net/rdap/?query=8.8.4.4
Entry name: LVLT-GOGL-8-8-4
Registrant name: Google LLC
Days old: 3,017

IPABUSE:
https://www.abuseipdb.com/check/8.8.4.4
Abuse Score: 0
ISP: Google LLC
Domain: google.com
Host Name: ['dns.google']
---------------------------------------------------------------------
```
