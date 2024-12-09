from IP import IP_Scan
from Url import url_scan
from Domain import Domain_scan
from Hostname import Hostname_scan
import argparse
   
parser = argparse.ArgumentParser(description='OTX CLI')
parser.add_argument('-i','--ip',help='8.8.8.8',required=False)
parser.add_argument('-d','--domain',help='google.com',required=False)
parser.add_argument('-u','--url',help=' http://www.alienvault.com',required=False)
parser.add_argument('-ho','--hostname',help='www.alienvault.com',required=False)

args = vars(parser.parse_args())

if args['ip']:
    # result = otx.get_indicator_details_full(IndicatorTypes.IPv4,args['ip'])
    # write_to_file(result, "null.json")
    IP = IP_Scan(args['ip'])
    IP.IP()
    IP.IP_Malware()
    IP.IP_url_list()
    IP.IP_passive_dns()

if args['domain']:
    # Domain = Domain_scan(args['domain'])
    # Domain.Domain_Genral_null()
    Domain = Domain_scan(args['domain'])
    Domain.Domain_Genral_null()
    Domain.Domain_Malware()
    Domain.Domain_passive_dns()
    Domain.Domain_url_list()
    Domain.Domain_Validation()

if args['hostname']:
    # result = otx.get_indicator_details_full(IndicatorTypes.HOSTNAME,args['hostname'])
    # write_to_file(result, "tx.json")
    Hostname = Hostname_scan(args['hostname'])
    Hostname.Hostname_Genral_null()
    Hostname.Hostname_Malware()
    Hostname.Hostname_passive_dns()
    Hostname.Hostname_url_list()
    Hostname.Hostname_Validation()

if args['url']:
    # result = otx.get_indicator_details_full(IndicatorTypes.URL,args['url'])
    # write_to_file(result, "tx.json")
    url = url_scan(args['url'])
    url.url_Genral_null()
    url.url_url_list()
    url.url_Validation()
