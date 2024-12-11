import argparse
from .IP import IP_Scan
from .Url import Url_Scan
from .Domain import Domain_scan
from .Hostname import Hostname_scan


class OTXCLI_App:
    def __init__(self):
        """Initialize the CLI for OTX scans."""
        self.parser = argparse.ArgumentParser(description="OTX CLI - Threat Intelligence Tool")
        self.parser.add_argument("-i", "--ip", help="Scan an IP address, e.g., 8.8.8.8", required=False)
        self.parser.add_argument("-d", "--domain", help="Scan a domain, e.g., google.com", required=False)
        self.parser.add_argument("-u", "--url", help="Scan a URL, e.g., http://www.example.com", required=False)
        self.parser.add_argument("-ho", "--hostname", help="Scan a hostname, e.g., www.example.com", required=False)
        self.args = vars(self.parser.parse_args())

    def process_ip(self, ip):
        """Perform a scan for the provided IP address."""
        try:
            ip_scan = IP_Scan(ip)
            ip_scan.IP()
            ip_scan.IP_Malware()
            ip_scan.IP_url_list()
            ip_scan.IP_passive_dns()
        except Exception as e:
            print(f"Error processing IP scan: {e}")

    def process_domain(self, domain):
        """Perform a scan for the provided domain."""
        try:
            domain_scan = Domain_scan(domain)
            domain_scan.Domain_Genral_null()
            domain_scan.Domain_Malware()
            domain_scan.Domain_passive_dns()
            domain_scan.Domain_url_list()
            domain_scan.Domain_Validation()
        except Exception as e:
            print(f"Error processing domain scan: {e}")

    def process_hostname(self, hostname):
        """Perform a scan for the provided hostname."""
        try:
            hostname_scan = Hostname_scan(hostname)
            hostname_scan.Hostname_Genral_null()
            hostname_scan.Hostname_Malware()
            hostname_scan.Hostname_passive_dns()
            hostname_scan.Hostname_url_list()
            hostname_scan.Hostname_Validation()
        except Exception as e:
            print(f"Error processing hostname scan: {e}")

    def process_url(self, url):
        """Perform a scan for the provided URL."""
        try:
            url_scan = Url_Scan(url)
            url_scan.url_Genral_null()
            url_scan.url_url_list()
            url_scan.url_Validation()
        except Exception as e:
            print(f"Error processing URL scan: {e}")

    def run(self):
        """Run the CLI tool based on provided arguments."""
        if self.args["ip"]:
            self.process_ip(self.args["ip"])
        if self.args["domain"]:
            self.process_domain(self.args["domain"])
        if self.args["hostname"]:
            self.process_hostname(self.args["hostname"])
        if self.args["url"]:
            self.process_url(self.args["url"])

