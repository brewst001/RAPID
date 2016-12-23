import re
import json

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from robobrowser import RoboBrowser

import requests

import dateutil.parser

# from pivoteer.models import ExternalSessions
# from core.utilities import discover_type


ip = "201.238.223.235"  # "89.34.111.119" #"185.25.50.117"
# ip = "95.215.44.38"
# current_hosts = ['95.215.44.38', '185.86.151.180', '89.34.111.119', '185.25.50.117']
# current_hosts = ['us-update.com', 'sky.otzo.com', 'www.us-update.com', 'r.ddns.me', 'singin.loginto.me', 'salesmarkting.co.vu', 'info.intarspace.co.vu', 'sales.intarspace.co.vu']

agent = 'Mozilla/5.0 (Windows NT 5.1; rv:23.0) Gecko/20100101 Firefox/23.0'
browser = RoboBrowser(user_agent=agent, parser='html5lib')

results = []

url_param = ip.replace(".", "/")
url = "https://www.robtex.com/en/advisory/ip/" + url_param + "/shared.html"
# url = "https://www.robtex.com/en/advisory/ip/" + ip + "/shared.html"
print("url: ", url)
browser.open(url)
print("browser: ", browser)

response = browser.response
print("response: ", response)

parser = browser.parsed
print("parser: ", parser)

search = parser.find("span", {"id": "shared_ma"})
print("search: ", search)

if search is not None:
    # count = self.extract_string(search.text, "(", " shown")
    # if int(count) <= 50:

    # for result in search.parent.parent.find("ol", {"class": "xbul"}).findChildren('li'):
    for result in search.parent.parent.parent.find("ol", {"class": "xbul"}).findChildren('li'):
        result_value = result.text

        if ' ' in result_value:
            result_value = re.sub(' ', '.', result_value)
            results.append(result_value)

        else:
            results.append(result_value)

    # else:
    #    results.append("%s domains identified" % str(count))

    print("results: ", results)
