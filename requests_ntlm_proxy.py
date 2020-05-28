#!/usr/bin/env python
# -*- coding:utf-8 -*-
#allisnone 20200403
#https://github.com/requests/requests-ntlm/issues/104

import requests
from requests_ntlm import HttpNtlmAuth
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

user = 'WORKGROUP\user' # or '.\user'
password = '1234'

http_proxy  = 'http://127.0.0.1:8080'
proxy_dict = {'http': http_proxy, 'https': http_proxy}

retries = Retry(total=10,
                read=5,
                connect=6,
                #these options don't seem to help
                #backoff_factor=1,
                #method_whitelist=(['HEAD', 'TRACE', 'GET', 'POST', 'CONNECT', 'OPTIONS', 'DELETE']), 
                #status_forcelist=[500, 502, 503, 504, 403, 407]
                )

session = requests.Session()
session.verify = False
session.mount('http://', HTTPAdapter(max_retries=retries))
session.mount('https://', HTTPAdapter(max_retries=retries))

session.proxies = proxy_dict
session.auth = HttpNtlmAuth(user, password)

#this works: HTTP GET
r = session.get('http://neverssl.com/')
print(r.text)

#HTTPS CONNECT fails!
r2 = session.get('https://www.google.com')
print(r2.text)