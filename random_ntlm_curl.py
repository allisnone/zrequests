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
import subprocess
import zthreads

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


def curl_request(url,user,eth,proxy='172.17.33.23:8080',cert='rootCA.cer'):
    curl_cmd = 'curl --cacert {0} --interface {1} --proxy-user {2}:Firewall1 --proxy-ntlm  -x  {3} {4}'.format(
        cert,eth,user,proxy,url)
    subp = subprocess.Popen(curl_cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)#,encoding="utf-8")
    try:
        subp.wait(2)  #等待超时
    except Exception as e:
        print('curl_request_timeout, error: ',e)
        return
    if subp.poll() == 0:
        print(subp.communicate()[1])
    else:
        print("curl_request-失败: ",curl_cmd)
    return


def callback():
    return

#curl
#curl -k  --interface eth0:2 --proxy-user ts1:Firewall1 --proxy-ntlm  -x  172.17.33.23:8080 https://www.baidu.com
#curl --cacert rootCA.cer  --interface eth0:8 --proxy-user ts1:Firewall1 --proxy-ntlm  -x  172.17.33.23:8080 https://www.baidu.com
#print(get_random_ip_or_user(start=2,end=254))
#print(get_random_ips_users(start=1,end=30,num=35))   
url = 'https://www.baidu.com'

from zthreads.threadpools.threadpools import Threadpools
thread_pool = Threadpools(50)
for i in range(100):
    ip = get_random_ip_or_user(start=2,end=254)
    user = get_random_ip_or_user(start=1,end=99,prefix='df64user',type='user')
    eth = get_random_ip_or_user(start=2,end=254,prefix='eth0:',type='user')
    print('ip_i{0}={1}'.format(i,ip))
    print('eth=',eth)
    print('user=',user)
    #thread_pool.put(curl_request, (url,user,eth,), callback)
    
    curl_request(url,user,eth,proxy='172.17.33.23:8080',cert='rootCA.cer')

time.sleep(3)
print("-" * 50)    

thread_pool.close()  
#initial_requests_session(ip=ip,user=ntlm_user)