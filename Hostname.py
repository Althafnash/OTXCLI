from OTXv2 import OTXv2
import IndicatorTypes
from Utils import write_to_file
import os

class Hostname_scan():
    def __init__(self, Hostname):
        API_KEY = os.getenv("OTX_API_KEY")
        otx = OTXv2(API_KEY)
        self.OTX = otx
        self.Hostname = Hostname
        self.result = self.OTX.get_indicator_details_full(IndicatorTypes.HOSTNAME, Hostname)

    def Hostname_Genral_null(self):
        results = self.result
        whois = results['general']['whois']
        alexa = results['general']['alexa']
        indicator = results['general']['indicator']
        type = results['general']['type']
        type_title = results['general']['type_title']

        result = [{
            'HostnameGnereal_null': [
                {'Whois': whois},
                {'alexa': alexa},
                {'indicator': indicator},
                {'type': type},
                {'type_title': type_title},
            ]
        }]

        write_to_file(result, f"{self.Hostname}_Hostnamenull.json")

    def Hostname_Validation(self):
        result = self.result
        Validation_null = result['general']['validation']
        validate_List = []

        for validate in Validation_null:
            source = validate['source']
            message = validate['message']
            name = validate['name']

            Validate_OBJ = {
                'Source': source,
                'message': message,
                'name': name,
            }

            validate_List.append(Validate_OBJ)

        final_result = {
            'Hostname_Validate_null': validate_List  
        }

        write_to_file(final_result, f'{self.Hostname}_HostnameValidation.json')

    def Hostname_Malware(self):
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
            'Hostname_Malware_null': Malware_List  
        }

        write_to_file(final_result, f'{self.Hostname}_HostnameMalware.json')

    def Hostname_url_list(self):
        result = self.result
        url_list_null = result['url_list']['url_list']
        url_list_List = []

        for url_list in url_list_null:
            url = url_list['url']
            Date = url_list['date']
            Hostname = url_list['Hostname']
            hostname = url_list['hostname']
            encoded = url_list['encoded']

            url_list_OBJ = {
                'url': url,
                'Date': Date,
                'Hostname': Hostname,
                'hostname': hostname,
                'encoded': encoded,
            }

            url_list_List.append(url_list_OBJ)

        final_result = {
            'url_list_null': url_list_List
        }

        write_to_file(final_result, f"{self.Hostname}_Hostnameurl_list.json")

    def Hostname_passive_dns(self):
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
                'asn': asn,  
            }

            passive_dns_List.append(passive_dns_OBJ)

        final_result = {
            'passive_dns_null': passive_dns_List
        }

        write_to_file(final_result, f"{self.Hostname}_Hostnamepassive_dns.json")
