#!/usr/bin/env python
# -*- coding:utf-8 -*-
#allisnone 20200403


#base on python3
#if you request https website, you need to add ASWG CA to following file:
#/root/.pyenv/versions/3.5.5/lib/python3.5/site-packages/certifi/cacert.pem
#ulimit –n 2000
import argparse
import re
import os
import csv
import string,sys,time
import requests
from requests_toolbelt.adapters import source
from requests_ntlm import HttpNtlmAuth
import random

def get_random_ip_or_user(start,end,prefix='172.16.90.',type='ip'):
    if type=='ip' and max(start,end)>255:
        end = 255
    i = random.randint(start,end)
    return prefix + str(i)

def get_random_ips_users(start,end,num,prefix='172.16.90.',type='ip'):
    if type=='ip' and max(start,end)>255:
        end = 255
    sequences = []
    for i in range(start,end+1):
        sequences.append(prefix+str(i))
    if num> len(sequences):
        num = len(sequences)
    choices = random.sample(sequences,num)
    return choices

def initial_requests_session(ip,header,proxy,proxy_pass='se2:Firewall1',verify=False,auth=None):
    s = requests.Session()
    new_adapter = source.SourceAddressAdapter(ip)
    s.mount('http://', new_adapter)
    s.mount('https://', new_adapter)
    #s.auth = ('user', 'pass')  
    #s.auth = HttpNtlmAuth('domain\\username','password')
    s.headers = {'User-Agent':'zrequest-v1.1'}
    #s.headers.update({'via': 'aswg33-1'})  
    #s.proxies = {'http': 'http://localhost:8888', 'https': 'http://localhost:8888'}
    s.verify = False
    #s.verify='/path-to/charles-ssl-proxying-certificate.pem'
    r = s.get('https://www.baidu.com')
    r =s.get("http://ntlm_protected_site.com",auth=HttpNtlmAuth('domain\\username','password'))
    print(r.text)
    return s

print(get_random_ip_or_user(start=1,end=30))
print(get_random_ips_users(start=1,end=30,num=35))   

initial_requests_session(ip='192.168.3.3')