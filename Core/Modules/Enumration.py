from bs4 import BeautifulSoup
from urllib.parse import quote,unquote
import requests,sys,time
#import Modules.colors
import re
import argparse
import json

def final_subs(all_sub):

    unique = []

    for sub in all_sub:
        sub = str(sub)
        start = int(sub.find('/'))+1
        if sub[start:] not in unique:
            if not sub[start:].startswith("www."):
                unique.append(sub[start:])
    return unique

def scan_certificates(domain):

    subdomains = []
    base_url = "https://crt.sh/atom?q=%25."
    data  = requests.get(base_url+str(domain)).text
    soup_data = BeautifulSoup(data,"lxml")
    summary_tags = soup_data.findAll("summary")
    for summary in summary_tags:
        text = summary.getText()
        end = text.index("<br>")
        sub = text[:end]
        subdomains.append(sub)

    return subdomains

def scan_virusTotal(domain):

    subdomains = []
    url = "https://www.virustotal.com/ui/domains/{}/subdomains".format(domain)
    next = True

    while next:
      data = requests.get(url).text
      soup = BeautifulSoup(data,"lxml")
      json_data = json.loads(data)
      link_attribute = json_data['links']
      attributes = link_attribute.items()
      main_attributes = json_data['data']
      if "next" not in str(attributes):
          next = False
      for link in attributes:
          if link[0] == "next":
              next = True
              url = link[1]
              if "limit" in str(url):
                  url=url[:len(url)-2] + "40"
      for key in main_attributes:
          key_list = key.items()
          for keyword in key_list:
              if keyword[0] == "id":
                  subdomains.append(keyword[1])

    return subdomains


def modify_subdomains(list_sub,domain):

    new_sub_list = []
    for subdomain in list_sub:
        subdomain = str(subdomain)
        index = subdomain.find(domain)
        new_sub_list.append(subdomain[:index+len(domain)])

    return new_sub_list


def modifyLINK(url):
    n=len(url)
    list1=[]
    for ch in url:
        if ch=="&":
            break
        else:
            list1.append(ch)
    ret=''.join(list1)
    return ret

def scan_google(search):
    subdomains_google=[]
    m_search="site:*."+search
    print(m_search)
    count=0
    while (count<=50):
        count=str(count)
        m_search=str(m_search)
        search_url="https://google.com/search?q="+m_search+"&start="+count
        requested_page=requests.get(search_url).text
        soup=BeautifulSoup(requested_page,'html.parser')
        count=int(count)
        if "Our systems have detected unusual traffic from your computer network" in soup.get_text() or "In order to show you the most relevant results, we have omitted some entries " in soup.get_text():
            print("----------------END---------------------")
            break
        h3_tags=soup.findAll("h3")
        for h3 in h3_tags:
            a_tag=h3.find("a")
            link=a_tag.get("href")
            link=link[7:]
            if link.startswith("http"):
                searchlink=modifyLINK(link)
                res=unquote(searchlink)
                subdomains_google.append(res)
                #("\033[1;37m--> \033[1;32m",res,end=" \n")
        count+=10
    return subdomains_google


def scan_bing(domain):
    query="inurl:*."+domain+" site:"+domain
    count=0
    subdomains_bing=[]
    list1=[]
    firstpage=[]
    while(count!=100):
        count=str(count)
        search_url = "http://www.bing.com/search?q=" + query +"&first=" + count
        data=requests.get(search_url).text
        soup=BeautifulSoup(data,'html.parser')
        count=int(count)
        if(data!=None):
            websites=soup.findAll("h2")
            for web in websites:
                a_tag=web.find("a")
                if a_tag != None:
                    list1.append(a_tag.get("href"))
        else:
            pass

        subdomains_bing.append(list1)
        if count==0:
            firstpage=list1
        if firstpage==list1 and count!=0:
            break
        count+=10

    return subdomains_bing

def start_enumration(domain):
    pass

if __name__== "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-d','--domain',required=True)
    args = parser.parse_args()

    if args.domain:
        root_url = str(args.domain)
        print("[~] Enumrating domains for ",root_url,"\n")

        print("[+] Scanning google...")
        google_sub=scan_google(root_url)

        print("[+] Scanning bing... ")
        bing_sub=scan_bing(root_url)

        print("[+] Enumrating domains from certificates...")
        sub_crt = scan_certificates(root_url)

        print("[=] Enumrating domain from virusTotal...")
        sub_virus = scan_virusTotal(root_url)

        print(len(google_sub)," ",len(bing_sub)," ",len(sub_crt)," ",len(sub_virus))

        print("[+] Modifiying domains..")
        modify_subdomains(google_sub,root_url)
        modify_subdomains(bing_sub,root_url)

        print("[+] Deleting duplicate domains..")
        subdomains = final_subs(google_sub+bing_sub+sub_crt+sub_virus)


        for sub in subdomains:
            print("--> ",sub,end="\n")
