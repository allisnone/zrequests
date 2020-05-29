#!/usr/bin/env python
# -*- coding:utf-8 -*-
#allisnone 20200403


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
    new_adapter = source.SourceAddressAdapter(ip,max_retries=retries)
    s.mount('http://', new_adapter)
    s.mount('https://', new_adapter)
    #s.auth = ('user', 'pass')  
    s.auth = HttpNtlmAuth(user,password)
    s.headers = {'User-Agent':'zrequest-v1.1'}
    #s.headers.update({'via': 'aswg33-1'})  
    s.proxies = {'http': 'http://172.17.33.23:8080', 'https': 'http://172.17.33.23:8080'}
    s.verify = False
    #s.verify='/path-to/charles-ssl-proxying-certificate.pem'
    r = s.get('https://www.baidu.com')
    r =s.get("http://ntlm_protected_site.com")
    print(r.text)
    return s

def get_urls_from_file(from_file='url16000.txt',url_index=0,spliter=',',pre_www='www.'):
    """
    用于url分类测试，测试文件中存放大量的url地址
    :param from_file: str 
    :return: list， URL_list（Generator）
    """
    txtfile = open(from_file, 'r')#'encoding='utf-8')
    url_list = txtfile.readlines()
    for i in range(0,len(url_list)):
        url_list[i] = url_list[i].replace('\n','')
        #print(url_list[i])
        if url_index>0:
            url_var = url_list[i].split(spliter)[url_index].replace(' ','')
            if pre_www not in url_var:
                url_var = pre_www + url_var
            url_list[i] = url_var
        protocol_header = url_list[i][:9].lower()
        if "http://" in protocol_header or "https://" in protocol_header or "ftp://" in protocol_header:
            pass 
        else: #无协议头部，默认加http协议
            url_list[i] = "https://" + url_list[i]
    return url_list 

print(get_random_ip_or_user(start=2,end=254))
print(get_random_ips_users(start=1,end=30,num=35))   

ip = get_random_ip_or_user(start=2,end=254)
user = get_random_ip_or_user(start=1,end=2,prefix='ts',type='user')
ntlm_user='skyguardgx\\' + user
print(ntlm_user)
initial_requests_session(ip='172.16.0.105',user=ntlm_user)