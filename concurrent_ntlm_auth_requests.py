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
import string,sys,time,datetime
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

def system_curl_request(url,user,eth,proxy='172.17.33.23:8080',cert='rootCA.cer',is_http=False,debug=False):
    """
    -I: header request
    -k: skip ssl
    --no-keepalive, keepalive=close
    """
    curl_cmd = ''
    debug = False
    if is_http:
        basic_cmd = 'curl  -I --no-keepalive  --interface {0} --proxy-user {1}:Firewall1 --proxy-ntlm  -x  {2} {3} &'
        if debug:
            pass
        else:
            basic_cmd = basic_cmd[:-1] + ' > /dev/ull 2>&1 &'
        curl_cmd = basic_cmd.format(eth,user,proxy,url)
    else:
        basic_cmd = 'curl  -I --cacert {0} --interface {1} --proxy-user {2}:Firewall1 --proxy-ntlm  -x  {3} {4} &'
        if debug:
            pass
        else:
            basic_cmd = basic_cmd[:-1] + ' > /dev/ull 2>&1 &'
        curl_cmd = basic_cmd.format(cert,eth,user,proxy,url)
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


def urls_resquests(urls, proxy='172.17.33.23:8080',user_start=300,user_num=253,sub_eth_start = 0, eth_num=253, 
    ip_prefix = '172.18.1.', cert='rootCA.cer',is_same_url=False, is_http=False,debug=False):
    """
    one ip/eth<--> one user
    """
    i = 0
    #count = max(len(urls),user_num,eth_num)
    #for url in urls:
    for i in range(max(user_num,eth_num)):
        url = ''
        if is_same_url:
            if is_http:
                url = 'http://172.16.0.1'   #use the same url for request test
            else:
                url = 'https://www.baidu.com'
        user_index = i % user_num + user_start
        eth_index = i % eth_num + sub_eth_start
        
        #ip = get_random_ip_or_user(start=2,end=254)
        
        #ip = ip_prefix + str(eth_index + 1)
        
        #user = get_random_ip_or_user(start=1,end=99,prefix='df64user',type='user')
        user = 'userg'+str(user_index)
        #eth = get_random_ip_or_user(start=2,end=253,prefix='eth0:',type='user')
        eth = 'eth0:'+str(eth_index)
        """ For debug
        print('i={0}: user_index={1}, eth_index={2}'.format(i,user_index,eth_index))
        print('ip_{0}={1}'.format(i,ip))
        print('eth=',eth)
        print('user=',user)
        print("-" * 50)
        """
        #thread_pool.put(system_curl_request, (url,user,eth,), callback)
        #popen_curl_request(url,user,eth,proxy='172.17.33.23:8080',cert='rootCA.cer')
        #system_curl_request(url,user,eth,proxy='172.17.33.23:8080',cert='rootCA.cer')
        system_curl_request(url,user,eth,proxy=proxy,cert=cert,is_http=is_http,debug=debug)
        #i = i + 1
    return
        
        
#"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='该Python3脚本用于ASWG做并发认证测试。\n 1、使用方法示例:\n python concurrent_ntlm_auth_requests.py -s 17:45:00 -r 2 -t 120 -p 172.17.33.23:8080') 
    parser.add_argument('-r','--round', type=int, default=1,help='认证并发测试的测试次数，默认1轮测试即停止')
    parser.add_argument('-s','--starttime', type=str, default='',help='首次认证并发测试的时间，如  16:20:60')
    parser.add_argument('-t','--auth-cache-timeout', type=int, default=600,help='认证缓存过期时间，默认600秒')
    parser.add_argument('-p','--aswg-proxy', type=str, default='172.17.33.23:8080',help='ASWG proxy')
    parser.add_argument('-i','--ip-prefix', type=str, default='172.18.1.',help='客户端IP前缀，默认只支持C段；其他方式自行适配')
    parser.add_argument('-u','--is-same-url', type=bool, default=True,help='是否使用相同URL测试')
    parser.add_argument('-u1','--is-http', type=bool, default=True,help='当指定使用相同URL时，指定是http还是https请求')
    parser.add_argument('-f','--url-file', type=str, default='hwurls_top10w.txt',help='urls来源文件')
    parser.add_argument('-f1','--url-index', type=int, default=0,help='urls来源文件中字段序号，默认从0开始')
    parser.add_argument('-a0','--start-user-index', type=int, default=0,help='auth 用户的序号，默认从0开始')
    parser.add_argument('-a1','--user-num', type=int, default=1275,help='auth 用户数量')
    parser.add_argument('-e0','--start-eth0-index', type=int, default=0,help='开始的子网卡序号，默认从0开始')
    parser.add_argument('-e1','--sub-eth0-num', type=int, default=1275,help='子网卡接口数量，每个接口一个IP地址')
    parser.add_argument('-d','--is-debug', type=bool, default=False,help='是否开启curl的打印日志')
    args = parser.parse_args()
    max_round = args.round
    first_schedule_time = args.starttime
    now = datetime.datetime.now()
    now_str = now.strftime("%H:%M:%S")
    if first_schedule_time:
        if len(first_schedule_time)==8 and len(first_schedule_time.split(':'))==3 and first_schedule_time > now_str:
            pass
        else:
            print('-s或者--starttime 格式不对，请输入大于当前时间字符串，如：16:20:60 ')
            sys.exit()
    else:
        nexttime = now + datetime.timedelta(seconds=60)
        first_schedule_time = nexttime.strftime("%H:%M:%S")
        
    auth_cache_timeout = args.auth_cache_timeout
    proxy = args.aswg_proxy
    ip_prefix = args.ip_prefix
    is_same_url = args.is_same_url
    is_same_url = True
    url_file = args.url_file
    url_index = args.url_index
    start_user_index = args.start_user_index
    user_num = args.user_num
    start_eth0_index = args.start_eth0_index
    sub_eth0_num = args.sub_eth0_num
    is_debug = args.is_debug
    urls = get_urls_from_file(from_file=url_file,url_index=url_index,spliter=',',pre_www='www.')
    #print('urls=',urls)
    #url = 'https://www.baidu.com'
    print('urls_len=',len(urls))
    
    #urls = urls[:300]
    print('urls_len=',len(urls))
    #from zthreads.threadpools.threadpools import Threadpools
    #thread_pool = Threadpools(5)
    i = 0
    #unique_users = 1275
    user_start = start_user_index
    user_num = user_num
    sub_eth_start = start_eth0_index
    eth_num  = sub_eth0_num
    cert = 'rootCA.cer'
    is_http = True
    #first_schedule_time = "16:45:00"
    #auth_cache_timeout = 60
    #max_round = 2
    print('max_round={0}, first_schedule_time={1}, auth_cache_timeout={2}'.format(max_round,first_schedule_time,auth_cache_timeout))
    round_num = 0
    while True:
        #time_now = time.strftime("%H:%M:%S", time.localtime())
        now = datetime.datetime.now()
        time_now = now.strftime("%H:%M:%S")
        if time_now == first_schedule_time: 
            print('This_schedule_time={0}, round={1}'.format(first_schedule_time,round_num))
            start_time =  time.time()
            urls_resquests(urls, proxy=proxy,user_start=user_start,user_num=user_num,sub_eth_start=sub_eth_start, eth_num=eth_num, 
                ip_prefix=ip_prefix, cert=cert,is_same_url=is_same_url, is_http=is_http,debug=is_debug)
            total_sending_time_seconds =  time.time() - start_time   
            print('total_sending_time_seconds={0}. Finished all url requests for round_{1}!!!'.format(total_sending_time_seconds,round_num))
            round_num = round_num + 1
            if round_num  >= max_round:
                print("-" * 50)
                print('Finished all test with {0} rounds!!!'.format(max_round))
                break
            else:
                print("-" * 50)
                print('Please make sure clear cache before the next schedule time!!!')
                #now = datetime.datetime.now()
                #date_str = now.strftime("%Y-%m-%d ")
                #last_schedule_time_str = date_str + first_schedule_time
                last_schedule_time = datetime.datetime.strptime(now.strftime("%Y-%m-%d ") + first_schedule_time,'%Y-%m-%d %H:%M:%S')
                nexttime = last_schedule_time + datetime.timedelta(seconds=auth_cache_timeout+60) # delay 60 seconds
                first_schedule_time = nexttime.strftime("%H:%M:%S")
                print('Next_schedule_time={0}...'.format(first_schedule_time))
            #time.sleep(sleep_time)
        else:
            #print('time_now=',time_now)
            pass
   
    
    #thread_pool.close()  
    #initial_requests_session(ip=ip,user=ntlm_user)
