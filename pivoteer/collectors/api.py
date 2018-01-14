import logging
import requests
import json


class PassiveTotal(object):

    base_url = "https://api.passivetotal.org"

    headers = { 'Content-Type': 'application/json' }

    api_versions = {"v2": "/v2",
                    "current": "/current"}

    GET_resources = {"metadata": "/metadata",
                     "passive": "/dns/passive",
                     "subdomains": "/subdomains",
                     "tags": "/user/tags",
                     "watch_status": "/watching",
                     "compromise_status": "/ever_compromised",
                     "dynamic_status": "/dynamic",
                     "sinkhole_status": "/sinkhole",
                     "classification": "/classification",
                     "ssl_cert_by_ip": "/ssl_certificate/ip_address",
                     "ssl_cert_by_hash": "/ssl_certificate/hash"}

    POST_resources = {"set_dynamic_status": "/dynamic",
                      "set_watch_status": "/watching",
                      "set_compromise_status": "/ever_compromised",
                      "add_tag": "/user/tag/add",
                      "remove_tag": "/user/tag/remove",
                      "set_classification": "/classification",
                      "set_sinkhole_status": "/sinkhole"}

    def __init__(self, api_username, api_key, api_version=None):

        self.__key = api_key
        self.__username = api_username

        if api_version:
            try:
                self.api_version = self.api_versions[api_version]
            except KeyError:
                logging.warning("Unrecognized API version, defaulting to v2")
                self.api_version = self.api_versions["v2"]
        else:
            self.api_version = self.api_versions["v1"]

    def retrieve_data(self, query, resource):

        if self.__key:
            try:

                data = '{"query": "' + query + '"}'

                data_encode = data.encode('ascii')
                api_call = self.GET_resources[resource]
                url = self.base_url + self.api_version + api_call

                response = requests.get(url, headers=self.headers, data=data_encode, auth=(self._PassiveTotal__username, self._PassiveTotal__key))
                json_response = json.loads(response.content.decode('utf-8'))

                records = json_response['results']
                results = []

                for entry in records:
                    if entry['resolveType'] == 'domain':
                       results.append({
                           'date': entry['collected'],
                           'firstseen': entry['firstSeen'],
                           'lastseen': entry['lastSeen'],
                           'ip': entry['value'],
                           'domain': entry['resolve'],
                           'ip_location': {}
                       })

                    elif entry['resolveType'] == 'ip':
                       results.append({
                            'date': entry['collected'],
                            'firstseen': entry['firstSeen'],
                            'lastseen': entry['lastSeen'],
                            'ip': entry['resolve'],
                            'domain': entry['value'],
                            'ip_location': {}
                       })

                return results

            except KeyError:
                logging.warning("Unrecognized API resource or malformed query")

        return []

    def submit_data(self, query, resource):

        if self.__key:
            try:
                api_call = self.POST_resources[resource]
                url = self.base_url + self.api_version + api_call
                params = {"api_key": self.__key, "query": query}
                response = requests.post(url, params=params)
                json_response = json.loads(response.content)
                return json_response

            except KeyError:
                logging.warning("Unrecognized API resource or malformed query")

        return []


class RobtexAPI(object):

    def __init__(self):
        object.__init__(self)

    def ip_query(self, query):
        results = []

        #data = '{"query": "' + query + '"}'

        api_path = "https://freeapi.robtex.com/ipquery/" + query

        response = requests.get(api_path)
        logging.debug("response status:" + response.ok)
        if response.ok:
            try:
                dataset = json.loads(response.text)
                for entry in dataset['pas']:
                    pas = entry['o'].encode('utf-8')
                    results.append(pas)

                return results

            except ValueError:
                logging.warning("Robtex api call failed".format(response.text))
                #print [json.loads(entry) for entry in response.text.split("\r\n") if entry is not '']


        else:
            return []
            # print information about the error
            logging.warning("{} error retrieving {}: {}".format(response.status_code,
                                                      api_path, response.text))

