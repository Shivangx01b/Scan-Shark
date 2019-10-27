#!/usr/bin/env python

import argparse
import json
import re
import os
from os import path
from googlesearch import search
import sys
import threading
from time import sleep
import pycurl
from bs4 import BeautifulSoup


banner = '''
 _____                   _____ _                _    
/  ___|                 /  ___| |              | |   
\ `--.  ___ __ _ _ __   \ `--.| |__   __ _ _ __| | __
 `--. \/ __/ _` | '_ \   `--. \ '_ \ / _` | '__| |/ /
/\__/ / (_| (_| | | | | /\__/ / | | | (_| | |  |   < 
\____/ \___\__,_|_| |_| \____/|_| |_|\__,_|_|  |_|\_\
                                                    
                                            BY -> Shivang     
''' 
print "\033[31m" +  banner.decode('utf-8') 

parser = argparse.ArgumentParser()
parser.add_argument("-ip", help="IP Address")
parser.add_argument("-o",help="Path where you want to save the dumps")
parser.add_argument("-protocol",help="Define protocol to scan Example ->  -protocol tcp or -protocol both")

args = parser.parse_args()

ip = None
if args.ip != None:
    ip = args.ip
else:
    print  "\033[93m" + "[-] IP Address is required"
    print  "\033[93m" + "[-] Use flag -h to check help"
    sys.exit()
o = None
if args.o != None:
    if not path.exists(args.o):
        print  "\033[93m" + "[-] Path does not exists"
        print  "\033[93m" + "[-] Use flag -h to check help"
        sys.exit()
    else:
        o = args.o
else:
    print  "\033[93m" + "[-] Path is  needed to save the contents"
    sys.exit()

protocol = None
if args.protocol != None:
    if args.protocol  in ("tcp", "udp" ,"both"):
          protocol = args.protocol
    else:
         print "\033[93m" +  "[-] Protocol must be tcp, udp or both"
         print "\033[93m" + "[-] Use flag -h for check help"
else:
   print "\033[93m" + "[-] Protocol is missing"
   print "\033[93m" + "[-] Use flag -h to check help"


class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    CYAN  = '\033[36m'
    YELLOW = '\033[93m'
    RED = '\033[31m'

class ContentCallback:
        def __init__(self):
                self.contents = ''

        def content_callback(self, buf):
                self.contents = self.contents + buf


def google_tcp_search(file1,o):
  with open('{}/nmap_tcp_scan.txt'.format(o)) as open_tcp:
      open_tcp1 = open_tcp.read()
      print bcolors.YELLOW + '[*] TCP Scan Results :'
      print bcolors.OKGREEN + str(open_tcp1)
  print bcolors.OKBLUE +"\n[>>>] Doing Google Search From TCP Port Scan Results"
  with open("{}".format(str(o) + '/' + str(file1) + '.txt')) as test1:
    commands = dict(re.findall(r'(\S+)\s+(.+)', test1.read()))
    r1 =  (json.dumps(commands,indent=3,sort_keys=True))
    r2 = json.loads(r1)
    for port_range in range(1, 65535):
      if str(str(port_range) + '/tcp')  in r2:
        query1 = ' '.join(r2["{}/tcp".format(port_range)].split()[2:])
        query = str(query1) +  ' ' + 'exploit' 
        if len(query1) != 0:
          print bcolors.RED + "\n[+] Looking for {}".format(query)
          r3 = []
          for result2 in search(query, tld="com", num=20, start=0, stop=25, pause=2):
            r3.append(str(result2))
          print bcolors.YELLOW + "\n[+] Results:"
          for output2 in r3:
            print bcolors.OKGREEN +  output2
  exploitdb_tcp_search(file1,o)
          

  
def google_udp_search(file2,o):
  with open('{}/nmap_udp_scan.txt'.format(o)) as open_udp:
    open_udp1 = open_udp.read()
    print bcolors.YELLOW + '[*] UDP Scan Results :'
    print bcolors.OKGREEN + str(open_udp1)
  print bcolors.OKBLUE +"\n[>>>] Doing Google Search From UDP Scan Results"
  with open("{}".format(str(o) + '/' + str(file2) + '.txt')) as test2:
    commands = dict(re.findall(r'(\S+)\s+(.+)', test2.read()))
    r4 =  (json.dumps(commands,indent=3,sort_keys=True))
    r5 = json.loads(r4)
    for port_range in range(1, 65535):
      if str(str(port_range) + '/udp')  in r5:
        query2 = ' '.join(r5["{}/udp".format(port_range)].split()[2:])
        query = str(query2) +  ' ' + 'exploit'  
        if len(query2) != 0:
          print bcolors.RED + "\n[+] Looking for {}".format(query)
          r6 = []
          for result3 in search(query, tld="com", num=20, start=0, stop=25, pause=2):
            r6.append(str(result3))
          print bcolors.YELLOW + "\n[+] Results:"
          for output3 in r6:
            print  bcolors.OKGREEN + output3
  exploitdb_udp_search(file2,o)
           

def exploitdb_tcp_search(file1,o):
   with open('{}/nmap_tcp_scan.txt'.format(o)) as open_tcp2:
      open_tcp3 = open_tcp2.read()
   print bcolors.OKBLUE +"\n[>>>] Checking Exploitdb from TCP Scan Results"
   with open("{}".format(str(o) + '/' + str(file1) + '.txt')) as test3:
    commands = dict(re.findall(r'(\S+)\s+(.+)', test3.read()))
    r7 =  (json.dumps(commands,indent=3,sort_keys=True))
    r8 = json.loads(r7)
    for port_range in range(1, 65535):
      if str(str(port_range) + '/tcp')  in r8:
        query3 = ' '.join(r8["{}/tcp".format(port_range)].split()[2:])
        query = str(query3) +  ' ' + 'site:https://www.exploit-db.com' 
        if len(query3) != 0:
          print bcolors.RED + "\n[+] Looking for {}".format(query3)
          r9 = []
          for result4 in search(query, tld="com", num=20, start=0, stop=25, pause=2):
            r9.append(str(result4))
          print bcolors.YELLOW + "\n[+] Results:"
          for output4 in r9:
            if "https://www.exploit-db.com/exploits" in output4:
              print bcolors.OKGREEN + "URL:" + ' ' + output4
              t = ContentCallback()
              curlObj = pycurl.Curl()
              curlObj.setopt(curlObj.URL, '{}'.format(output4))
              curlObj.setopt(curlObj.WRITEFUNCTION, t.content_callback)
              curlObj.perform()
              curlObj.close()
              soup = BeautifulSoup(t.contents,'lxml')
              desc = soup.find("meta", property="og:title")
              print bcolors.RED + "Title:" + ' ' + desc["content"] if desc else "Cannot find the description for the exploit"
              author = soup.find("meta", property="article:author")
              print bcolors.YELLOW + "Author:" + ' ' +  author["content"] if author else "No author name found"
              publish = soup.find("meta", property="article:published_time") 
              print bcolors.OKBLUE + "Publish Date:" + ' ' +  publish["content"] if publish else "Cannot find the published date"

   print bcolors.CYAN + "[+] Searching Finished"


def exploitdb_udp_search(file2,o):
   with open('{}/nmap_udp_scan.txt'.format(o)) as open_udp2:
      open_udp3 = open_udp2.read()
   print bcolors.OKBLUE +"\n[>>>] Checking Exploitdb from UDP Scan Results"
   with open("{}".format(str(o) + '/' + str(file2) + '.txt')) as test4:
    commands = dict(re.findall(r'(\S+)\s+(.+)', test4.read()))
    r10 =  (json.dumps(commands,indent=3,sort_keys=True))
    r11 = json.loads(r10)
    for port_range in range(1, 65535):
      if str(str(port_range) + '/udp')  in r11:
        query4 = ' '.join(r11["{}/udp".format(port_range)].split()[2:])
        query = str(query4) +  ' ' + 'site:https://www.exploit-db.com' 
        if len(query4) != 0:
          print bcolors.RED + "\n[+] Looking for {}".format(query4)
          r12 = []
          for result5 in search(query, tld="com", num=20, start=0, stop=25, pause=2):
            r12.append(str(result5))
          print bcolors.YELLOW + "\n[+] Results:"
          for output5 in r12:
            if "https://www.exploit-db.com/exploits" in output5:
              print bcolors.OKGREEN + "URL:" + ' ' + output5
              u = ContentCallback()
              curlObj = pycurl.Curl()
              curlObj.setopt(curlObj.URL, '{}'.format(output5))
              curlObj.setopt(curlObj.WRITEFUNCTION, u.content_callback)
              curlObj.perform()
              curlObj.close()
              soup = BeautifulSoup(u.contents,'lxml')
              desc = soup.find("meta", property="og:title")
              print bcolors.RED + "Title:" + ' ' + desc["content"] if desc else "Cannot find the description for the exploit"
              author = soup.find("meta", property="article:author")
              print bcolors.YELLOW + "Author:" + ' ' +  author["content"] if author else "No author name found"
              publish = soup.find("meta", property="article:published_time") 
              print bcolors.OKBLUE + "Publish Date:" + ' ' +  publish["content"] if publish else "Cannot find the published date"

   print bcolors.CYAN + "[+] Searching Finished"



def scanner(ip,protocol):
    if protocol == 'tcp':
        tcp_scan(ip,o)

    if protocol == 'udp':
        udp_scan(ip,o)

    if protocol == 'both':
        print bcolors.YELLOW +"[+] Running both TCP and UDP scan!"
        t1 = threading.Thread(target=tcp_scan, args=[ip,o])
        t2 = threading.Thread(target=udp_scan, args=[ip,o])
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
def tcp_scan(ip,o):
    cmd1 = "nmap -sC -sV  --max-retries=10000 -Pn {}".format(ip)
    run1 = os.popen(cmd1 + '>{}/nmap_tcp_scan.txt'.format(o))
    file1 = 'nmap_tcp_scan'
    print  bcolors.OKGREEN + "[+] TCP Scan Started" 
    print  bcolors.CYAN + '[*] Saving file as {}.txt in {}'.format(file1,o)
    
    
def udp_scan(ip,o):
    cmd2 = "nmap -sC -sV -sU -p- --max-retries=10000 -Pn {}".format(ip) 
    run2 = os.popen(cmd2 + '>{}/nmap_udp_scan.txt'.format(o))
    file2 = 'nmap_udp_scan'
    print bcolors.OKGREEN + "[+] UDP Scan Started"
    print bcolors.CYAN + '[*] Saving files as {}.txt in {}'.format(file2,o)
       
if __name__=="__main__":
  check  = ['nmap_tcp_scan.txt','nmap_udp_scan.txt']
  for a in check:
    if path.exists("{}/{}".format(o,a)) == True:
      os.remove("{}/{}".format(o,a))
      print bcolors.YELLOW + "Removed privious {}".format(a)
  scanner(ip,protocol)
  if path.exists("{}/nmap_tcp_scan.txt".format(o)) and path.exists("{}/nmap_udp_scan.txt".format(o)) == True:
    print bcolors.OKBLUE + "[+] Doing Google search from both TCP and UDP results"
    google_tcp_search("nmap_tcp_scan",o)
    google_udp_search("nmap_udp_scan",o)
    sys.exit()
  for b in check:
    if path.exists("{}/{}".format(o,b)) == True:
      if b == "nmap_tcp_scan.txt":
        google_tcp_search("nmap_tcp_scan",o)
      elif b == "nmap_udp_scan.txt":
        google_udp_search("nmap_udp_scan",o)
      else:
        sys.exit()






