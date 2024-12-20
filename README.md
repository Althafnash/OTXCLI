# OTXCLI 

OTXCLI is a Python-based command-line tool that interfaces with the AlienVault OTX API to gather and process threat intelligence data. This tool retrieves detailed information about IPs, domains, URLs, and other indicators, and stores the results in JSON files for further analysis.

# Features

- Fetch detailed information about
    - IP addresses
    - Domains
    - URLs
    - Hostnames
    - MD5 hashes
    - Pulses (search for specific threat intelligence)
- Save the results in structured JSON files for easy processing and integration.
- Retrieve and process malware data associated with IPs

# Prerequisites

- Python 3.7+
- An API key for AlienVault OTX (sign up here if you don’t have one).

# INTALLATION 

- Download from pip

- Requirments 
    - Python 
    - install python package
        - argparse  
        - OTXv2
        - os 
        - json 
    - OTX API key 

# Usage
## Get IP information 
- -i, 
- --ip	
- Fetch information about an IP address	python OTX.py -i 8.8.8.8
## Get domain information 
- -d, 
- --domain	
- Fetch information about a domain	python OTX.py -d google.com
## Get URL information 
- -u, 
- --url	
- Fetch information about a URL	python OTX.py -u http://example.com
## Get Hostname information 
- -ho, 
- --hostname	
- Fetch information about a hostname	python OTX.py -ho www.example.com

### github 
[text](https://github.com/Althafnash/OTXCLI.git)