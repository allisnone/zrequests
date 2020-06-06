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
#from requests_ntlm import HttpNtlmAuth
import random
import subprocess
#import zthreads

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



def popen_curl_request(url,user,eth,proxy='172.17.33.23:8080',cert='rootCA.cer'):
    curl_cmd = 'curl --cacert {0} --interface {1} --proxy-user {2}:Firewall1 --proxy-ntlm  -x  {3} {4} &'.format(
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

def system_curl_request(url,user,eth,proxy='172.17.33.23:8080',cert='rootCA.cer'):
    curl_cmd = 'curl -I --cacert {0} --interface {1} --proxy-user {2}:Firewall1 --proxy-ntlm  -x  {3} {4} &'.format(
        cert,eth,user,proxy,url)
    try:
        os_p = os.system(curl_cmd)
        print('curl_cmd=',curl_cmd)
    except Exception as e:
        print('curl_request_timeout: {0}, error: {1}, url={2}, user={3}'.format(curl_cmd,e,url,user))
    return

def get_urls_from_file(from_file='url16000.txt',url_index=-1,spliter=',',pre_www='www.'):
    """
    用于url分类测试，测试文件中存放大量的url地址
    :param from_file: str 
    :return: list， URL_list（Generator）
    """
    txtfile = open(from_file, 'r',encoding='utf-8')
    url_list = txtfile.readlines()
    for i in range(0,len(url_list)):
        url_list[i] = url_list[i].replace('\n','')
       # print(url_list[i])
        if url_index>=0:
            url_var = url_list[i].split(spliter)[url_index].replace(' ','')
            #print('url_var=',url_var)
            protocol_header = url_var[:9].lower()
            if pre_www not in url_var and not ("http://" in protocol_header or "https://" in protocol_header or "ftp://" in protocol_header):
                url_var = pre_www + url_var
            url_list[i] = url_var
        protocol_header = url_list[i][:9].lower()
        #print('protocol_header=',protocol_header)
        if "http://" in protocol_header or "https://" in protocol_header or "ftp://" in protocol_header:
            pass 
        else: #无协议头部，默认加http协议
            url_list[i] = "https://" + url_list[i]
    return url_list 


def get_eth_user_index(sequence=0,user_start=30,user_num=10,eth_start=0,eth_num=254):
    """
    inet 172.18.1.1/16 brd 172.18.255.255 scope global secondary eth0:0
    inet 172.18.1.254/16 brd 172.18.255.255 scope global secondary eth0:253
    sequence: start with 0
    eth_num: eth sequence start with 0
    """
    user_index = sequence % user_num + user_start
    eth_index = sequence % eth_num + eth_start
    """
    user_index = sequence
    if sequence>user_num: #循环，复用，取余
        user_index = sequence % user_num + user_start
    eth_index = sequence
    if eth_index>eth_num: #循环，复用，取余
        eth_index = eth_index % eth_num + eth_start
    """
    return user_index,eth_index

def callback():
    return

#curl
#curl -k  --interface eth0:2 --proxy-user ts1:Firewall1 --proxy-ntlm  -x  172.17.33.23:8080 https://www.baidu.com
#curl --cacert rootCA.cer  --interface eth0:8 --proxy-user ts1:Firewall1 --proxy-ntlm  -x  172.17.33.23:8080 https://www.baidu.com
#print(get_random_ip_or_user(start=2,end=254))
#print(get_random_ips_users(start=1,end=30,num=35))   
#i = 436
#user_index,eth_index = get_eth_user_index(sequence=i,user_start=30,user_end=99,eth_num=254)
#print(user_index,eth_index)

#"""
  
urls = get_urls_from_file(from_file='hwurls_top10w.txt',url_index=0,spliter=',',pre_www='www.')
#print('urls=',urls)
#url = 'https://www.baidu.com'
print('urls_len=',len(urls))

urls = urls[:300]
print('urls_len=',len(urls))
#from zthreads.threadpools.threadpools import Threadpools
#thread_pool = Threadpools(5)
i = 0
user_start=300
user_num=253
sub_eth_start = 0
eth_num=253
ip_prefix = '172.18.1.'
for url in urls:
    url = 'https://www.baidu.com'
    user_index,eth_index = get_eth_user_index(sequence=i,user_start=user_start,user_num=user_num,eth_start=sub_eth_start,eth_num=eth_num)
    print('i={0}: user_index={1}, eth_index={2}'.format(i,user_index,eth_index))
    
    #ip = get_random_ip_or_user(start=2,end=254)
    ip = '172.18.1.' + str(eth_index + 1)
    #user = get_random_ip_or_user(start=1,end=99,prefix='df64user',type='user')
    user = 'userg'+str(user_index)
    #eth = get_random_ip_or_user(start=2,end=253,prefix='eth0:',type='user')
    eth = 'eth0:'+str(eth_index)
    print('ip_{0}={1}'.format(i,ip))
    print('eth=',eth)
    print('user=',user)
    #thread_pool.put(system_curl_request, (url,user,eth,), callback)
    #popen_curl_request(url,user,eth,proxy='172.17.33.23:8080',cert='rootCA.cer')
    system_curl_request(url,user,eth,proxy='172.17.33.23:8080',cert='rootCA.cer')
    i = i + 1
    print("-" * 50)  
    #j = j + 1
#"""
    
time.sleep(3)
print('Finished all url requests!!!')
#print("-" * 50)    

#thread_pool.close()  
#initial_requests_session(ip=ip,user=ntlm_user)
