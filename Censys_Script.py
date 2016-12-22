import sys
import json
import requests
import re
import smtplib
import time
from censys.ipv4 import CensysIPv4
from censys.certificates import CensysCertificates
from email.mime.text import MIMEText

# Loads Censys.io API Keys

API_URL = "https://www.censys.io/api/v1/search/ipv4"
# UID = "2155b2e5-84c0-4f2a-8dbf-514aa35d162e"
# SECRET = "wUfjS3lGgaQaPQ3Mt1s8NxTalDRRZMZe"
UID = 'e013909c-bdec-4c17-a997-74955b73ac89'
SECRET = 'y4nlaUAD9Netlvlc2mcZnhdhohVInAww'

# Establishes Certificate values to query for and associated IPs that are already tracked

# cert_values = {
# "443.https.tls.certificate.parsed.fingerprint_sha1:a1833c32d5f61d6ef9d1bb0133585112069d770e":
# ['95.215.46.27','192.95.12.5', '176.31.96.178','5.56.133.42','204.145.94.227','130.255.184.196','45.32.129.185','23.227.196.217','80.255.3.93', '167.114.214.63', '80.255.10.236', '5.56.133.170', '131.72.136.165', '94.242.224.172', '46.183.216.209', '81.17.30.29', '176.31.112.10', '172.245.45.27', '213.251.187.145','104.156.245.207','45.32.91.1','109.236.93.138']
# ,"443.https.tls.certificate.parsed.fingerprint_sha1:25ef05857d3da5653279f20cf4f6e965c22641d4":
# ['69.12.73.174','66.55.143.126','131.72.138.33']
# }

# cert_values = {
# "443.https.tls.certificate.parsed.fingerprint_sha1:84093410ab1f8ed64454572680b0ce2563480c12":[]
# }
# cert_values = {
# "443.https.tls.certificate.parsed.fingerprint_sha1:e851c0263b6ef7a35ba47a7b722607836e398887":[]
# }

cert_values = {
    "443.https.tls.certificate.parsed.fingerprint_sha1:a1833c32d5f61d6ef9d1bb0133585112069d770e": ['95.215.46.27',
                                                                                                   '95.215.44.38']
}

# def find_values(id, json_repr):
#     print("entering find values")
#     results = []

#     def _decode_dict(a_dict):
#         try: results.append(a_dict[id])
#         except KeyError: pass
#         print("a_dict: ",a_dict)
#         return a_dict

#     json.loads(json_repr, object_hook=_decode_dict)  # return value ignored
#     print ("findvalues.results: ", results);
#     return results


# Establishes empty lists for future results output





# certificates = CensysCertificates(api_id=UID, api_secret=SECRET)
# fields = ["443.https.tls.certificate.parsed.fingerprint_sha1"]

# print("certificates:", certificates)

# for c in certificates.search("parsed.fingerprint_sha1:a1833c32d5f61d6ef9d1bb0133585112069d770e"):
#    print ("c: ",c)

new_ip = {}
ip = []

# Queries certificate data for associated IP addresses
for key in cert_values:
    data = {}
    data["query"] = key
    data["fields"] = ip
    value = key
    print("key: ", key)  # LNguyen
    print("ip:", ip)  # LNguyen
    print("data:", data)

    ## Using CensysIPv4 REST API call to get the associated IPs
    censysapi = CensysIPv4(api_id=UID, api_secret=SECRET)
    print("censysapi: ", censysapi.search(query=key, fields=[]))
    print("certvalue key1: ", sorted(cert_values[key]))
    tmpids = []
    for result in censysapi.search(query=key, fields=[]):
        # print("result: ",result['ip'])
        tmpids.append(result['ip'])
        print("certvalue key2: ", sorted(cert_values[key]))
    print("censys api results: ", tmpids)

    # time.sleep(3.5)
    # Using Request.post call to get the associated IPs
    # search = requests.post(API_URL, data=data, auth=(UID, SECRET))
    search = requests.post(API_URL, data=json.dumps(data), auth=(UID, SECRET))

    if search.status_code == 200:
        results = search.json()
        print("results: ", results)

        parsed_json = json.dumps(results)
        print("parsed_json: ", parsed_json)

        resp = json.loads(parsed_json)
        parent = resp['results']

        # f = open('test.html','w')
        # f.write(results)
        # f.close()

        # commented out by LNguyen
        # id_all = re.findall('(?<=\'ip\':\\su\')(\d*.\d*.\d*.\d*)(?=\')',str(results))

        print('')
        print("Cert value of:", key, "returned the following IPs:")
        print('')
        # for x in id_all:
        #     print (x)
        id_all = []
        for item in parent:
            # print("item:",item['ip'])
            print(item['ip'])
            id_all.append(item['ip'])

        # Checks IP addresses returned against known IP addresses
        print("id_all: ", id_all)
        print("certvalue key3: ", sorted(cert_values[key]))
        print("sorted id_all: ", sorted(id_all))
        if sorted(cert_values[key]) == sorted(id_all):
            print('')
            print("All returned IPs associated with this cert are already tracked")
            print('')

        if sorted(cert_values[key]) != sorted(id_all):
            new = set(cert_values[key]).symmetric_difference(id_all)
            print("newset: ", set(new))
            print("certset: ", set(cert_values[key]))
            unknown_ips = list(set(new) - set(cert_values[key]))
            print("unknown ips: ", unknown_ips)
            if unknown_ips:
                print('')
                print("Previously unknown IP(s) identified with this cert value:")
                new_ip[value] = unknown_ips
                print("new_ip: ", new_ip)
                for x in new_ip:
                    print(x)
                    print(new_ip[x])

    if search.status_code != 200:
        print("error occurred: %s" % search.json()["error"])
        sys.exit(1)

print('')
if len(new_ip) > 0:
    print('The following new IPs were identified')
    print(new_ip)

# Formats information in order to email

filedate = time.strftime('%Y-%m-%d')

testfile = open('testfile.txt', 'w')
testfile.write('Censys.io Alert for ')
testfile.write(str(filedate) + '\n\n')
if len(new_ip) > 0:
    testfile.write('*The following new IP associations were identified:\n\n')
    testfile.write('\n\n')
    testfile.write('----------------------------------------------------------------\n')
    for key in new_ip:
        # print("key:", key)
        testfile.write(str(key) + ':\n\n')
        # print("new_ip_key:", new_ip[key])
        id1 = new_ip[key]
        # print("id1:", id1)
        id = re.findall('(?<=\')(\d*.\d*.\d*.\d*)(?=\')', str(id1))
        # print("id:", id)
        for x in id:
            # print("x:",x)
            testfile.write('-' + x + '\n')
        testfile.write('\n')
        testfile.close()

if len(new_ip) == 0:
    testfile.write('*There are no new IP associations for the certificate values being monitored')
    testfile.write('\n\n')
    testfile.write('----------------------------------------------------------------\n')
    testfile.write('A total of 2 certificate values are being monitored. Mapping is listed below: \n\n')

    testfile.write('APT 28\n')
    testfile.write('9f53a40996b24585e5c639e5d403c01c5fadc9e9\n')
    testfile.write('25ef05857d3da5653279f20cf4f6e965c22641d4\n')

    testfile.close()

# Sends information to email account

# commented out by LNguyen
# fp = open('testfile.txt', 'rb')
# msg = MIMEText(fp.read())
# fp.close()

with open('testfile.txt') as fp:
    msg = MIMEText(fp.read())
msg['Subject'] = 'Censys.io Alert for %s' % (filedate)
msg['From'] = 'nguylt1222@gmail.com'  # Replace with your sender email address
recipients = ['nguylt1222@gmail.com']  # Replace with your recipient email addresses here
msg['To'] = ", ".join(recipients)

username = 'nguylt1222@gmail.com'  # Replace with your sender email address
password = 'Nhucham1'  # Replace with your sender email password

server = smtplib.SMTP('smtp.gmail.com:587')
server.ehlo()
server.starttls()

server.login(username, password)

server.sendmail(msg['From'], recipients, msg.as_string())
server.quit()

