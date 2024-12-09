from OTXv2 import OTXv2
import IndicatorTypes
from Utils import write_to_file
import os 

class IP_Scan():
    def __init__(self,ip):
        API_KEY = os.getenv("OTX_API_KEY")
        otx = OTXv2(API_KEY)
        self.OTX = otx
        self.ip = ip
        self.result = self.OTX.get_indicator_details_full(IndicatorTypes.IPv4, ip)

    def IP(self):
        result=self.result
        Domain = result['general']['whois']
        Reputation = result['general']['reputation']
        type_title = result['general']['type_title']
        access_type = result['general']['base_indicator']['access_type']
        asn = result['general']['asn']
        continent_code = result['general']['continent_code']
        country_code3 = result['general']['country_code3']
        latitude = result['general']['latitude']
        longitude = result['general']['longitude']
        country_name = result['general']['country_name']
        area_code = result['general']['area_code']
        flag_url = result['general']['flag_url']
        accuracy_radius = result['general']['accuracy_radius']
        flag_title = result['general']['flag_title']

        result = [{
            'General_null' : [
                {'Domain':Domain},
                {'Reputation':Reputation},
                {'access_type':access_type},
                {'type_title':type_title},
                {'asn':asn},
                {'continent_code':continent_code},
                {'country_code3':country_code3},
                {'latitude':latitude},
                {'longitude':longitude},
                {'country_name':country_name},
                {'area_code':area_code},
                {'flag_url':flag_url},
                {'accuracy_radius':accuracy_radius},
                {'flag_title':flag_title},
            ]}]
        write_to_file(result, f"{self.ip}_null.json")

    def IP_Malware(self):
        result = self.result
        Malware_null = result['malware']['null']
        Malware_List = []  

        for Malware in Malware_null:
            Hash = Malware['hash']
            Date = Malware['date']

            Detection = []
            for AV_name, detection in Malware['detections'].items():
                Detection.append({AV_name: detection})

            Malware_OBJ = {
                'Hash': Hash,
                'Date': Date,
                'Detections': Detection,
            }

            Malware_List.append(Malware_OBJ)

        final_result = {
            'Malware_null': Malware_List
        }

        write_to_file(final_result, f"{self.ip}_Malware.json")
        
    def IP_url_list(self):
        result = self.result
        url_list_null = result['url_list']['url_list']
        url_list_List = []  

        for url_list in url_list_null:
            url = url_list['url']
            Date = url_list['date']
            domain = url_list['domain']
            hostname = url_list['hostname']
            encoded = url_list['encoded']

            url_list_OBJ = {
                'url': url,
                'Date': Date,
                'domain': domain,
                'hostname': hostname,
                'encoded': encoded,
            }

            url_list_List.append(url_list_OBJ)

        final_result = {
            'url_list_null': url_list_List
        }

        write_to_file(final_result, f"{self.ip}_url_list.json")

    def IP_passive_dns(self):
        result = self.result
        passive_dns_null = result['passive_dns']['passive_dns']
        passive_dns_List = []  

        for passive_dns in passive_dns_null:
            address = passive_dns['address']
            first = passive_dns['first']
            last = passive_dns['last']
            record_type = passive_dns['record_type']
            indicator_link = passive_dns['indicator_link']
            flag_url = passive_dns['flag_url']
            flag_title = passive_dns['flag_title']
            asset_type = passive_dns['asset_type']
            asn = passive_dns['asn']
            hostname = passive_dns['hostname']

            passive_dns_OBJ = {
                'address': address,
                'first': first,
                'last': last,
                'hostname': hostname,
                'record_type': record_type,
                'indicator_link': indicator_link,
                'flag_url': flag_url,
                'flag_title': flag_title,
                'asset_type': asset_type,
                'asset_type': asset_type,
            }

            passive_dns_List.append(passive_dns_OBJ)

        final_result = {
            'passive_dns_null': passive_dns_List
        }

        write_to_file(final_result, f"{self.ip}_passive_dns.json")