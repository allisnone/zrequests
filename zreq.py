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
import random

from multiprocessing import Pool
import logging
from logging.handlers import TimedRotatingFileHandler
import datetime
#requests.packages.urllib3.disable_warnings()
from requests.packages.urllib3.exceptions import SubjectAltNameWarning
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#PY_VERSION = sys.version_info.major
if sys.version_info.major==3:
    from urllib.parse import quote as quote
else:
    from urllib import quote as quote

def initial_logger(logfile='all.log',errorfile='error.log',logname='mylogger'):
    logger = logging.getLogger(logname)
    logger.setLevel(logging.DEBUG)
    if sys.version_info.major==3: 
        rf_handler = TimedRotatingFileHandler(logfile, when='midnight', interval=1, backupCount=7, atTime=datetime.time(0, 0, 0, 0))
    else:
        rf_handler = TimedRotatingFileHandler(logfile, when='midnight', interval=1, backupCount=7)
    rf_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    #f_handler = logging.FileHandler(errorfile)
    #f_handler.setLevel(logging.ERROR)
    #f_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s[:%(lineno)d] - %(message)s"))
    logger.addHandler(rf_handler)
    #logger.addHandler(f_handler)
    return logger
#sys.getrecursionlimit(100000000)
sys.setrecursionlimit(100000000)
logger = initial_logger(logfile='aswgRequest.log',errorfile='aswgRequest_error.log',logname='aswgRequest')

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
    

def set_proxy(url, proxy='',user_pass='se2:Firewall1'):
    """
    根据URL设置使用HTTP或者HTTPS的代理
    :param url: str type , dest url
    :param proxy: str type, <proxy_IP>:<proxy_port>, like  172.18.230.23:8080
    user_pass, like <username>:<password>, 'yangfashouxian:Firewall1'
    """
    if not proxy:
        return {}
    proxy_url = proxy
    if user_pass:
        if ':' in user_pass:
            proxy_url = '{}@'.format(user_pass) + proxy_url
        else:
            print('Invalid proxy user and password!!!')
    #aswg_proxy = 'http://' + proxy
    #if "https://" in url:
    #    return {'https': aswg_proxy}
    return {'http': 'http://' + proxy_url, 'https':'http://' + proxy_url} 
 
def get_urls_from_web(base_url,proxy={}):#,logger=None):
    """
    用于病毒测试，模拟下载病毒文件 
    如'http://172.16.0.1/upload/VirusSamples/'
    :param base_url: str，  通常是用于存放病毒文件的某个url目录
    :param proxy: dict， proxy的字典类型
    :return: list， URL_list（Generator）
    """
    global logger
    result = ''
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
        }
        r = requests.get(base_url, headers=headers, proxies=proxy, verify=False)
        result = r.text
    except Exception as e:
        logger.error('get_urls_from_web: {0}-{1}'.format(base_url,e))
    if result:
        #logger.info('result={0}'.format(result))
        # pattern = re.compile(r"alt=\"\[(?!DIR|ICO).*?<a href=.*?>(.*?)</a>", re.S)
        #pattern = re.compile(r"<a href=.*?>(.*?)</a>", re.S)
        pattern = re.compile(r"<a href=\"(.*?)\">.*?</a>", re.S)
        fn = re.findall(pattern, result)
        #logger.info('result_fn={0}'.format(fn))
        return list(set([base_url + i for i in fn]))
    else:
        return []

def get_urls_from_file0(from_file='url16000.txt'):
    """
    用于url分类测试，测试文件中存放大量的url地址
    :param from_file: str 
    :return: list， URL_list（Generator）
    """
    txtfile = open(from_file, 'r')#'encoding='utf-8')
    url_list = txtfile.readlines()
    for i in range(0,len(url_list)):
        url_list[i] = url_list[i].replace('\n','')
        protocol_header = url_list[i][:9].lower()
        if "http://" in protocol_header or "https://" in protocol_header or "ftp://" in protocol_header:
            pass 
        else: #无协议头部，默认加http协议
            url_list[i] = "http://" + url_list[i]
    return url_list

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
            url_list[i] = "http://" + url_list[i]
    return url_list    
    
def encode_url(url):
    """
    处理包含中文字符串/空格的URL编码问题
    :param url:
    :return:
    """
    return quote(url, safe=string.printable).replace(' ', '%20')


def write2csv(data,file='result.csv'):#,logger=None):
    try:
        if sys.version_info.major==3:
            with open(file, 'a', encoding='utf-8', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(data)
                csvfile.close()
        else:
            with open(file, 'a') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(data)
                csvfile.close()
    except Exception as e:
        if logger:
            logger.error('write2csv-data: {0}, file: {1}, {2}'.format(data, file,e))
        else:
            print(e)

def write_datas_2csv(datas,file='result.csv'):#,logger=None):
    try:
        with open(file, 'a', encoding='utf-8', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for data in datas:
                writer.writerow(data)
            csvfile.close()
    except Exception as e:
        if logger:
            logger.error('write_datas_2csv: {0}, file: {1}, {2}'.format(datas, file,e))
        else:
            print(e)
        
def filter_results_2csv(data,file='result.csv'):
    #filter url result, only keep the block url or 200 ok url
    try:
        with open(file, 'a', encoding='utf-8', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(data)
    except Exception as e:
        print(e)

def http_request(url,proxy='',block_info='访问的URL中含有安全风险',encoding='utf-8',verify=False,retry_once=False,timeout=(30,60)):
    """
    下载文件，分析是否被SWG阻断
    :param url:
    :return: callback
    """
    #block_info = '访问的URL中含有安全风险'
    pid,ppid = os.getpid(),os.getppid()
    global logger
    headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)'
        }
    #if True:
    try:
        r = requests.get(encode_url(url), headers=headers,proxies=set_proxy(url, proxy),timeout=timeout,verify=verify)
        block_type = ''
        if r.status_code==403:
            r.encoding = encoding
            if block_info in r.text: #标准阻断
                block_type = '403block'
            else: #其他403阻断
                block_type = "403other"
        elif r.status_code==200:#200ok 放行
            block_type = "pass"
        elif r.status_code==502:#DNS resolve failure
            block_type = "dns_failed"
        else:#403，200 以外的待定
            block_type = "unknown"
        logger.info('request-url: {0}, http_code: {1}, action: {2}, pid-{3}, ppid-{4}'.format(url, r.status_code,block_type,pid,ppid))
        return [url, url.split('/')[-1], r.status_code, block_type,pid,ppid]
    #except:
    #else:
    except Exception as e:
        if retry_once:#try to guess http or https
            if "https://" in url:
                url = url.replace('https://','http://')
                logger.info('request-url: one more try, replace https request to http: {0}'.format(url))
            elif "http://" in url:
                url = url.replace('http://','https://')
                logger.info('request-url: one more try, replace http request to https: {0}'.format(url))
            else:
                pass
            http_request(url,proxy,block_info,encoding,retry_once=False)
        logger.error('request-url-exception: {0}, ERROR: {1} '.format(url, e))
        return [url, url.split('/')[-1], 0, e,pid,ppid]
    
def request_results(url,proxy='',file='result.csv',type='url'):#,logger=None):
    #print('ppid:{0}-pid:{1}'.format(os.getpid(),os.getppid()))
    block_info='访问的URL中含有安全风险'
    if type=='virus':
        block_info = '病毒'
    #print('type:',type(url))
    if isinstance(url, str) or isinstance(url,unicode):
        #print('url-1=',url)
        result = http_request(url, proxy,block_info=block_info)
        if file:#should give filename
            write2csv(result, file)
    elif isinstance(url, list):#several datas once write
        results = []
        #print('url-2=',url)
        for u in url:
            result = http_request(u, proxy,block_info=block_info) 
            if result:
                results.append(result)
            else:
                logger.error('No result for sub-request-url: {0}'.format(u))
        if results and file:#should give filename
            write_datas_2csv(results, file)
        else:
            logger.error('No any results for request-url set: {0}'.format(url))
    else:
        logger.error('Invalid request-url type: {0}, url: {1}'.format(type(url),url))
    return

def urls_exception(urls,except_url_file='',url_index=1,spliter=',',pre_www='www.'):
    #urls_exception = get_urls_from_file(except_url_file,url_index,spliter,pre_www)    
    return list(set(urls).difference(set(get_urls_from_file(except_url_file,url_index,spliter,pre_www))))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='该Python3脚本用于ASWG做URL分类测试和病毒测试。\n 1、URL测试使用方法:\n python aswgRequest.py -t url -f ulrs.txt -p 172.18.230.23:8080 -o urls_result.csv \n 2、病毒测试：  python aswgRequest.py -t virus -u http://www.sogaoqing.com/upload/VirusSamples/ -p 172.18.230.23:8080 -o virus_result.csv') 
    parser.add_argument('-t','--type', type=str, default='url',help='默认为url分类测试，从文件读取url地址；当设置为virus时，将模拟从某个web服务器特定目录下载所有文件。')
    parser.add_argument('-p','--proxy', type=str, default = '',help='默认不适用aswp代理，需指定代理时，<proxy_IP>:<proxy_port> 例如：72.18.230.23:8080') 
    parser.add_argument('-f','--url-file', type=str, default= 'urls.txt',help='默认为urls.txt， 指定包含需要测试url的文件，每行一条url。')
    parser.add_argument('-u','--url-base', type=str, default= '',help='默认为空，用于模拟下载病毒测试，指定url目录，如： http://172.16.0.1/upload/VirusSamples/')
    parser.add_argument('-o','--out-put', type=str, default='',help='默认为result.csv，测试结果保存为csv文件。')
    parser.add_argument('-c','--cpu-num', type=str, default=1,help='默认为cpu数为系统cpu核心数，输入整数')
    parser.add_argument('-l','--log-file', type=str, default='aswgRequest',help='脚本输出的日志文件')
    parser.add_argument('-w','--write-per-num', type=int, default=1,help='每次写多少个result，默认是1，并发中减少文件读写')
    parser.add_argument('-e','--except-file', type=str, default='',help='url排除文件，通常是上一次运行过的结果，不期望重复请求')
    parser.add_argument('-i','--index-url-file', type=int, default=0,help='提取每行url的序号，默认取第0列，逗号分隔')
    parser.add_argument('-j','--index-except-file', type=int, default=0,help='url排除文件中，提取每行url的序号，默认取第0列，逗号分隔')
    args = parser.parse_args()
    type = args.type
    proxy = args.proxy
    url_file = args.url_file
    result_file = args.out_put
    url_base = args.url_base
    cpu_num = int(args.cpu_num)
    log_file = args.log_file
    write_per_num = args.write_per_num
    except_url_file = args.except_file
    index_url_file = args.index_url_file
    index_except_file = args.index_except_file
    logfile = '{0}_{1}_all.log'.format(log_file,type)
    errorfile = '{0}_{1}_error.log'.format(log_file,type)
    #logger = initial_logger(logfile,errorfile,logname=log_file)
    logger.info('---------------------开始 {}测试-------------------------------------------'.format(type))
    #date_str = time.strftime('%Y%m%d%H%M',time.localtime(time.time()))
    logger.info('ASWG Proxy 为: {0}，开启线程数:{1}'.format(proxy,cpu_num))
    #record_result_file = True
    if  result_file:
        if os.path.exists(result_file):
            os.remove(result_file)
            logger.info('remove existing file: {0}'.format(result_file))
    else:
        logger.info('Will not record result file!!!'.format())
    urls = []
    if type=='url' or type=='aseg':
        urls = get_urls_from_file(from_file=url_file,url_index=index_url_file,spliter=',',pre_www='www.')
        if except_url_file:
            urls = urls_exception(urls, except_url_file, url_index=index_except_file, spliter=',', pre_www='www.') 
        print(len(urls))
        #sys.exit()
    elif type=='virus':
        if url_base:
            urls = get_urls_from_web(url_base)
        else:
            logger.error('缺少指定URL下载目录，脚本退出！！！')
            sys.exit()
    else:
        logger.error('测试类型错误，脚本退出！！！')
        sys.exit()
    if urls:
        logger.info('urls={0}'.format(urls))
        logger.info('待测试URL总数为：{} '.format(len(urls)))
    else:
        logger.error('获取url失败，脚本退出！！！')
        sys.exit()
    pool = Pool()
    if cpu_num>1:
        pool = Pool(cpu_num)
    else:
        pass
    #weilin modifiy at 20190705AM
    if 'aseg' == type:
        MAX_URL_LEN = 3900
        xURL=''
        for url in urls:
            if len(xURL) + len(url) > MAX_URL_LEN and '' != xURL:
                xURL += ']'
                pool.apply_async(request_results, (xURL, '',result_file,type))
                #print('xURL A : ', xURL)
                xURL = ''
            if '' == xURL:
                #xURL = 'http://172.17.200.102:8000/urlcats/batchlookup?batchlookup=[{\"url\":"' + url + '"}'
                #xURL = 'http://{0}/urlcats/batchlookup?batchlookup=[{\"url\":\"{1}\"}'.format(proxy,url)
                xURL = 'http://'+ proxy + '/urlcats/batchlookup?batchlookup=[{\"url\":"' + url + '"}'
            else:
                xURL += ',{\"url\":"' + url + '"}'
            if len(xURL) > MAX_URL_LEN:
                xURL += ']'
                pool.apply_async(request_results, (xURL, '',result_file,type))
                #print('xURL B : ', xURL)
                xURL = ''
        if '' != xURL:
            xURL += ']'
            pool.apply_async(request_results, (xURL, '',result_file,type))
            #print('xURL C : ', xURL)
            xURL = ''

    else:
        #first request for auth buffer
        test_url = 'https://www.baidu.com'
        #test_url = 'http://www.sohu.com'
        test_result = http_request(test_url,proxy=proxy,block_info='访问的URL中含有安全风险',encoding='utf-8',verify=False,retry_once=False,timeout=(30,60))
        print('test_result=',test_result)
        print('Waiting 10 seconds to form auth buffer...')
        time.sleep(10)
        if write_per_num==1:
            pass
        elif write_per_num>1:
            if len(urls)>=cpu_num*3:
                urls = [urls[i:i+write_per_num]for i in range(0,len(urls),write_per_num)]
        else:
            pass
        logger.info('urls='%urls)
        for url in urls:
            #pool.apply_async(http_request, (url, proxy), callback=write2csv)
            pool.apply_async(request_results, (url, proxy,result_file,type))
    pool.close()
    pool.join()
    logger.info('---------------------{0}测试完成-------------------------------------------'.format(type) )
    logger.info('测试结果位于：{} '.format(result_file ))
    sys.exit()
    #需要踏平的坑
    """设置 ulimit -n 10240--否则大规模 读写文件/请求会出现  Errno 99 错误"""
    """ASWG URL测试使用方法"""
    #python aswgRequest.py -t url -f urls.txt -p 172.18.230.23:8080 -o urls_result.csv -c 512 -l aswgRequest
    #python aswgRequest.py -t url -f urls.txt -p 172.18.200.240:8080 -o urls_result.csv -c 512 -l aswgRequest
    #python aswgRequest.py –t <请求类型为url> -f <url文件来源>  -p <swg代理IP:端口> -o  <日志输出>  -c <并发进程数> -l <日志文件名>
    """ASWG 病毒测试使用方法，模拟http下载病毒"""
    #python aswgRequest.py -t virus -u http://www.sogaoqing.com/upload/VirusSamples/ -p 172.18.230.23:8080 -o virus_result.csv
    #python aswgRequest.py –t <请求类型为virus> -f <url文件目录>  -p <swg代理IP:端口> -o  <日志输出>  -c <并发进程数> -l <日志文件名>
    """ASEG URL测试使用方法"""
    #1）/etc/trafficserver/records.config ,第23行去掉ip-in=127.0.0.1
    #CONFIG proxy.config.http.server_ports STRING 8000:ipv4:proto=http
    #2）修改ASEG配置文件 vi /etc/trafficserver/remap.config  ，改为管理口eth0的IP：添加两行
    #map http://aseg-eth0-ip:8000/urlcats/ http://{urlcats}
    #map http://aseg-eth0-ip:8000/urlcats/ http://{urlcats}
    #3）/etc/init.d/trafficsever restart
    #4)Linux 客户端运行脚本
    #python aswgRequest.py -t aseg -f urls.txt -p 172.17.31.26:8000 -o urls_result.csv -c 512 
    #python aswgRequest.py –t <请求类型为aseg> -f <url文件来源>  -p <aseg-eth0-ip:端口8000> -o  <日志输出>  -c <并发进程数> -l <日志文件名>
    

