#!/usr/bin/env python
# -*- coding:utf-8 -*-
#allisnone 20200403
#https://github.com/urllib3/urllib3/issues/1434
#https://github.com/dopstar/requests-ntlm2
#https://github.com/requests/requests-ntlm

#base on python3
#if you request https website, you need to add ASWG CA to following file:
#/root/.pyenv/versions/3.5.5/lib/python3.5/site-packages/certifi/cacert.pem
#ulimit –n 2000
#pip install requests_ntlm
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

def initial_requests_session(ip,header=None,proxy=None,user='skyguardgx\\se1',password = 'Firewall1',verify=False,auth=None,retries=1):
    s = requests.Session()
    #new_adapter = source.SourceAddressAdapter(ip,max_retries=retries)
    new_adapter = source.SourceAddressAdapter(ip)#,max_retries=retries)
    s.mount('http://', new_adapter)
    s.mount('https://', new_adapter)
    #s.auth = ('user', 'pass')  
    #s.auth = HttpNtlmAuth(user,password)
    s.headers = {'User-Agent':'zrequest-v1.1'}
    #s.headers.update({'via': 'aswg33-1'})  
    s.proxies = {'http': 'http://172.17.33.23:8080', 'https': 'http://172.17.33.23:8080'}
    #s.verify = False
    s.verify='rootCA.cer'
    r = s.get('https://www.baidu.com')
    r =s.get("http://ntlm_protected_site.com")
    print(r.text)
    return s

#curl
#curl -k  --interface eth0:2 --proxy-user ts1:Firewall1 --proxy-ntlm  -x  172.17.33.23:8080 https://www.baidu.com
#curl --cacert rootCA.cer  --interface eth0:8 --proxy-user ts1:Firewall1 --proxy-ntlm  -x  172.17.33.23:8080 https://www.baidu.com
print(get_random_ip_or_user(start=2,end=254))
print(get_random_ips_users(start=1,end=30,num=35))   

ip = get_random_ip_or_user(start=2,end=254)
user = get_random_ip_or_user(start=1,end=2,prefix='ts',type='user')

ntlm_user='skyguardgx\\' + user
print(ntlm_user)
print('ip=',ip)
initial_requests_session(ip=ip,user=ntlm_user)