try:
    import shodan
except:
    print("ERROR: shodan failed to import\nrun pip install shodan")

try:
    import whoisit
except:
    print("ERROR: shodan failed to import\nrun pip install whoisit")

import argparse
import textwrap
from datetime import datetime
import requests

def get_args():
    parser = argparse.ArgumentParser(
        description="Check ip for bad reputation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        py lookup-ip.py -ip "8.8.8.8"
        py lookup-ip.py -ip "8.8.8.8, 8.8.4.4"
        py lookup-ip.py -f ./ips.txt
        ''')
    )

    parser.add_argument('-ip', action='store', type=str, required=False, help="one or more ips to lookup in csv format")
    parser.add_argument('-f', '--file', action='store', type=str, required=False, help="file containing one or more ips per line")

    args = parser.parse_args()

    args_dict = vars(args)

    return args_dict

def main():
    args = get_args()
    ip_file_path = args['file']
    
    # read in ips
    if ip_file_path:
        ip_lookups = read_ip_file(ip_file_path)
    else:
        ips = args['ip']
        ip_lookups = parse_ips(ips) # return a list of ips to lookup

    # perform ip checks
    for ip in ip_lookups:
        shodan_actions(ip)
        whois_actions(ip)
        ipabuse_actions(ip)

def parse_ips(ips):
    """parse the commandline ips supplied

    parameters:
    -----------
    ips : str
        one or more ips in csv format

    returns:
    --------
    list_ips : list
        contains ips to use with shodan
    """

    list_ips = []

    parts = ips.split(',')
    for part in parts:
        ip = part.strip()
        list_ips.append(ip)
    
    return list_ips

def read_ip_file(ip_file_path):
    """read ips from txt file

    parameters:
    -----------
    ip_file_path : str
        file path to txt with one or more ips

    returns:
    --------
    ip_list : list
        contains ips to lookup in shodan
    """

    ip_list = []

    with open(ip_file_path) as f:
        lines = f.readlines()
        
        for line in lines:
            ip = line.strip()
            ip_list.append(ip)
    
    return ip_list

def read_api_key(keyName):
        """read the api_key.txt file in the current directory

        parameters:
        ----------
        keyName : str
            the file name to open

        returns:
        -------
        api_key : str
            the shodan api key
        """

        try:
            # windows compatible
            f = open(f'.//{keyName}')
        except:
            # linux compatible
            f = open(f'./{keyName}')

        line = f.read()
        api_key = line.strip()
            
        return api_key

def whois_actions(ip):
    """Get whois information about the given ip

    query whois and print the information.

    parameters:
    -----------
    ip : str
        ipv4 address
    """
    whoisit.bootstrap()

    # query whois
    results = whoisit.ip(ip)
        
    # get days old
    reg_date = results['registration_date']
    if reg_date:
        tz_info = reg_date.tzinfo
        days_old = (datetime.now(tz_info) - reg_date).days
    else:
        days_old = 'N/A'
        
    # get entry name
    name = results['name']

    # get registrant
    try:
        reg_name = results['entities']['registrant'][0]['name']
    except:
        try:
            reg_name = results['entities']['registrant'][0]['handle']
        except:
            reg_name = results['entities']['administrative'][0]['name']
    
    # display info
    print("\nWHOIS:")
    print(f"https://search.arin.net/rdap/?query={ip}")
    print(f"Entry name: {name}")
    print(f"Registrant name: {reg_name}")
    if type(days_old) == str:
        print(f"Days old: {days_old}")
    else:
        print(f"Days old: {days_old:,}")

def shodan_actions(ip):
    """Get shodan information about the given ip

    query shodan and print the information

    parameters:
    -----------
    ip : str
        ipv4 address
    """
    
    # read shodan api key to authenticate
    api_key = read_api_key('shodan_key.txt')
    shodanObj = shodan.Shodan(api_key)
    
    def lookup_ips(shodanObj, ip):
        """query ip in shodan

        parameters:
        -----------
        shodanObj : shodan
            shodan api obj
        ips : list
            contains ips to lookup in shodan
        
        returns:
        --------
        hostObjs : list
            one or more shodan host json objs
        """
        hostObjs = []

        try:
            host = shodanObj.host(ip)
            hostObjs.append(host)
        except:
            print("SHODAN: IP not found")

        return hostObjs

    # look up ips
    hosts = lookup_ips(shodanObj, ip)
    
    if len(hosts) > 0:
        # print shodan url for hosts found in shodan
        print("\nSHODAN:")
        for host in hosts:
            ipAdress = host['ip_str']
            print(f"https://www.shodan.io/host/{ipAdress}")

            # display open ports
            for data in host['data']:
                port = data['port']
                try:
                    service = data['product']
                except:
                    service = data['_shodan']['module']
                print(f"Open Port: {port} - {service}")

def ipabuse_actions(ip):
    """Get ipabuse information about the given ip

    query ipabuse and print the information

    parameters:
    -----------
    ip : str
        ipv4 address
    """
    
    api_key = read_api_key('ipabuse_key.txt')
    
    # query check endpoint
    headers={"Key" : api_key, "Accept" : "application/json"}

    param = {'ipAddress' : ip, 'maxAgeInDays' : 90}
    url = 'https://api.abuseipdb.com/api/v2/check'
    r = requests.get(url, params=param, headers=headers)
    checkpoint_results = r.json()['data']
    abuse_score = checkpoint_results['abuseConfidenceScore']
    isp_name = checkpoint_results['isp']
    domain_name = checkpoint_results['domain']
    host_name = checkpoint_results['hostnames']
    lastReport_date = checkpoint_results['lastReportedAt']
    dt = datetime.strptime(lastReport_date, '%Y-%m-%dT%H:%M:%S%z')

    tz_info = dt.tzinfo
    days_old = (datetime.now(tz_info) - dt).days
    
    print("\nIPABUSE:")
    print(f"https://www.abuseipdb.com/check/{ip}")
    print(f"Abuse Score: {abuse_score}")
    print(f"ISP: {isp_name}")
    print(f"Domain: {domain_name}")
    print(f"Host Name: {host_name}")

    # query reports endpoint
    if abuse_score > 0:
        # display last report time
        if days_old == 0:
            hours_old = round((datetime.now(tz_info) - dt).seconds / 60 / 60)
            
            if hours_old == 0:
                seconds_old = round((datetime.now(tz_info) - dt).seconds / 60)
                print(f"Last Report: {seconds_old} seconds ago")
            else:
                print(f"Last Report: {hours_old} hours ago")
        else:
            print(f"Last Report: {days_old} days ago")
        
        # query reports endpoint
        param = {'ipAddress' : ip, 'page' : 1, 'perPage' : 5}
        url = 'https://api.abuseipdb.com/api/v2/reports'
        r = requests.get(url, params=param, headers=headers)
        report_results = r.json()['data']
        reports = report_results['results']
        print("IpAbuse Reports:")
        # print top 5 comments
        for index, report in enumerate(reports, start=1):
            print(f"\t{index}.{report['comment']}")

if __name__ == "__main__" :
    main()