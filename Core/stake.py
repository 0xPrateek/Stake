import requests
from bs4 import BeautifulSoup
import argparse
import sys
import Modules.Logo as Logo
import Modules.colors as colors
import Modules.Enumration as enumeration

def format_url(url):

    if url.startswith('www.'):
        url=url.replace('www.','http://')
    return url

def enum_subdomain(domain,brute):

    colors.success("Starting subdomain Enumration for {}".format(domain), "green")

    try:
        r = requests.get(domain)
    except:
        colors.error("Please enter correct URL")
        sys.exit(0)

    return "File path"


def takeover_scan(file_path):

    print("File path for scan is ",file_path)


if __name__ == "__main__":
    try:
        Logo.banner()
        
        parser = argparse.ArgumentParser()

        parser.add_argument('-d','--domain',help = " Domain to Stake.",required = True)
        parser.add_argument('-c','--custom',help = "Use custom subdomain list.",default = False)
        parser.add_argument('-e','--enumerate',help = 'Enumerate subdomains.',default = True,action = 'store_true')
        parser.add_argument('-a','--all',help = 'Perform all types of scan for subdomain including Brute-force.',action = 'store_true')
        parser.add_argument('-s','--save',help = 'Save result in text file.',action = 'store_true')

        args = parser.parse_args()

        if args.domain:
            root_url = args.domain
            root_url = format_url(root_url)

        if args.custom != False:

            path = args.custom
            takeover_scan(path)

        elif args.enumerate:

            brute = args.all
            enum_file = enum_subdomain(root_url,brute)

            takeover_scan(enum_file)

    except KeyboardInterrupt:
        colors.error("User Interrupted the Process. Exiting...")
        sys.exit(0)