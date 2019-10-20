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
parser.add_argument("-protocol",help="Define protocol to scan Example ->  -protocol tcp ")
parser.add_argument("-both",help="Scan both tcp and udp with full range of ports. IT's usage is -both FULL") 

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

both = None
if args.both != None:
     both = args.both

protocol = None
if args.protocol != None:
    protocol = args.protocol

both = None
if args.both != None:
     both = args.both
    
class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    CYAN  = '\033[36m'
    YELLOW = '\033[93m'
    RED = '\033[31m'

def google_tcp_search(file1,o):
  with open('nmap_tcp_scan.txt') as open_tcp:
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
          for result2 in search(query, tld="co.in", num=20, start=0, stop=25, pause=2):
            r3.append(str(result2))
          print bcolors.YELLOW + "\n[+] Results:"
          for output2 in r3:
            print bcolors.OKGREEN +  output2
          print bcolors.CYAN + "[+] Searching Finished"

def google_udp_search(file2,o):
  with open('nmap_udp_scan.txt') as open_udp:
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
          for result3 in search(query, tld="co.in", num=20, start=0, stop=25, pause=2):
            r6.append(str(result3))
          print bcolors.YELLOW + "\n[+] Results:"
          for output3 in r6:
            print  bcolors.OKGREEN + output3
          print bcolors.CYAN + "[+] Searching Finished"

def scanner(ip,protocol,both):
    if protocol == 'tcp':
        tcp_scan(ip,o)

    if protocol == 'udp':
        udp_scan(ip,o)

    if both == 'FULL':
        print bcolors.YELLOW +"[+] Running both TCP and UDP scan!"
        t1 = threading.Thread(target=tcp_scan, args=[ip,o])
        t2 = threading.Thread(target=udp_scan, args=[ip,o])
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
def tcp_scan(ip,o):
    cmd1 = "nmap -sC -sV -p- --max-retries=1000 -Pn {}".format(ip)
    run1 = os.popen(cmd1 + '>{}/nmap_tcp_scan.txt'.format(o))
    file1 = 'nmap_tcp_scan'
    print  bcolors.OKGREEN + "[+] TCP Scan Started" 
    print  bcolors.CYAN + '[*] Saving file as {}.txt in {}'.format(file1,o)
    
    
def udp_scan(ip,o):
    cmd2 = "nmap -sC -sV -sU -p- --max-retries=1000 -Pn {}".format(ip) 
    run2 = os.popen(cmd2 + '>{}/nmap_udp_scan.txt'.format(o))
    file2 = 'nmap_udp_scan'
    print bcolors.OKGREEN + "[+] UDP Scan Started"
    print bcolors.CYAN + '[*] Saving files as {}.txt in {}'.format(file2,o)
       
if __name__=="__main__":
  check  = ['nmap_tcp_scan.txt','nmap_udp_scan.txt']
  for a in check:
    if path.exists("{}".format(a)) == True:
      os.remove("{}".format(a))
      print bcolors.YELLOW + "Removed privious {}".format(a)
  scanner(ip,protocol,both)
  if path.exists("nmap_tcp_scan.txt") and path.exists("nmap_udp_scan.txt") == True:
    print bcolors.OKBLUE + "[+] Doing Google search from both TCP and UDP results"
    google_tcp_search("nmap_tcp_scan",o)
    google_udp_search("nmap_udp_scan",o)
    sys.exit()
  for b in check:
    if path.exists("{}".format(b)) == True:
      if b == "nmap_tcp_scan.txt":
        google_tcp_search("nmap_tcp_scan",o)
      elif b == "nmap_udp_scan.txt":
        google_udp_search("nmap_udp_scan",o)
      else:
        sys.exit()






