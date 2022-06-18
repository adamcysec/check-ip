# check-ip.py

## Synopsis
Reputation check an ip on services: [shodan](https://www.shodan.io/), [whois](https://www.arin.net/), [abuseIPDB](https://www.abuseipdb.com/).

## Description
Pass this tool one or more ips to check if it has been reported for malicious activity.

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
