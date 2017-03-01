# Important: This module is NOT implemented with support for Python 2.x

import unittest
import json
import requests
import os
import logging
import tldextract
import pythonwhois
import dns.resolver
import geoip2.database
import censys.base
import core.google
import pycountry
import urllib.request
from ipwhois import IPWhois
from collections import OrderedDict
from ipwhois.ipwhois import IPDefinedError
from censys.ipv4 import CensysIPv4
from censys.certificates import CensysCertificates
from django.conf import settings

logger = logging.getLogger(__name__)
current_directory = os.path.dirname(__file__)


class LookupException(Exception):
    """
    An exception used to indicate an error performing a lookup.
    """

    def __init__(self, message, cause=None):
        """
        Create a new exception with the given message.

        The message is required.  A cause may also optionally be provided.  This allows you to easily preserve the
        original cause of the exception, if available.   Instances have two read-only members readily available:
            message: A detail message
            cause: The exception that caused this exception (may be None)

        Note that in Python 3, you can easily indicate a causal exception:
        try:
            ...
        except SomeException as e:
            raise LookupException(message, e) from e

        In Python 2 it's not quite as easy:
        try:
            ...
        except SomeException as e:
            trace = sys.exc_info()[2]
            raise LookupException(message, e, trace)

        :param message: The detail message for this exception
        :param cause: The exception that caused this exception, or None (the default)
        """
        super(LookupException, self).__init__()
        self._message = message
        self._cause = cause

    @property
    def message(self):
        return self._message

    @property
    def cause(self):
        return self._cause


def get_country_code(name):
    """
    Convert the name of a country to the ISO-3166 country code.

    The name should be a long value (e.g. "United States") such as the value in the "country" key of the dictionary
    returned by 'geolocate_ip.'  In this example, this function would return 'US.'

    :param name: The country name
    :return: The country code (a two-character string)
    :raises KeyError: If 'name' is not a valid country name
    """
    # Known "Gotchas":
    #   - "Slovakia" vs. "Slovak Republic": This is why we do the 'opts' approach with name and official name
    #   - "Russia" vs. "Russian Federation": This is why we do the 'contains' approach
    #   - "Vietnam" vs. "Viet Nam": The actual name is the latter.  You're just out of luck on this one.
    code = None
    for country in pycountry.countries:
        opts = [country.name]
        try:
            opts.append(country.official_name)
        except AttributeError:
            # There is no official name for this country
            pass
        if name in opts:
            code = country.alpha2
        else:
            for opt in opts:
                if name in opt:
                    code = country.alpha2
                    break
        if code is not None:
            break
    logger.debug("Country code for '%s' is '%s'", name, code)
    if code is None:
        msg = "No code available for country '%s'" % name
        logger.warn(msg)
        raise KeyError(msg)
    return code


def geolocate_ip(ip):
    geolocation_database = os.path.join(current_directory, 'GeoLite2-City.mmdb')
    reader = geoip2.database.Reader(geolocation_database)

    try:
        response = reader.city(ip)

        # Geo-location results - city, state / province, country
        results = OrderedDict({"city": response.city.name,
                               "province": response.subdivisions.most_specific.name,
                               "country": response.country.name})
        return results

    except ValueError:
        logger.debug("Invalid IP address passed")

    except geoip2.errors.AddressNotFoundError:
        logger.debug("IP address not found in database")

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)

    return OrderedDict({"city": "", "province": "", "country": ""})


def resolve_domain(domain):
    """
    Resolve a domain to a list of IP addresses.

    This method will use the Google public DNS servers to perform the resolution.  If successful, a list of IP addresses
    is returned.  If an error occurs, a LookupException is thrown.
    :param domain:
    :return:
    """

    # Set resolver to Google openDNS servers
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    errmsg = "Error resolving domain '%s': " % domain
    answer = []

    try:
        query_answer = resolver.query(qname=domain)
        answer = [raw_data.address for raw_data in query_answer]
        return answer

    except dns.resolver.NXDOMAIN as e:
        errmsg += "NX Domain"
        logger.exception(errmsg)
        return answer
       # raise LookupException(errmsg, e) from e

    except dns.resolver.Timeout as e:
        errmsg += "Query Timeout"
        logger.exception(errmsg)
        return answer
       # raise LookupException(errmsg, e) from e

    except dns.resolver.NoAnswer as e:
        errmsg += "No Answer"
        logger.exception(errmsg)
        return answer
       # raise LookupException(errmsg, e) from e

    except dns.resolver.NoNameservers as e:
        errmsg += "No Name Server"
        logger.exception(errmsg)
        return answer
       # raise LookupException(errmsg, e) from e

    except Exception as e:
        errmsg += "Unexpected error"
        logger.exception(errmsg)
        return answer
       # raise LookupException(errmsg, e) from e


def lookup_domain_whois(domain):
    # Extract base domain name for lookup
    ext = tldextract.extract(domain)
    delimiter = "."
    sequence = (ext.domain, ext.tld)
    domain_name = delimiter.join(sequence)

    try:
        # Retrieve parsed record
        record = pythonwhois.get_whois(domain_name)
        record.pop("raw", None)
        record['domain_name'] = domain_name
        return record

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)

    return None


def lookup_ip_whois(ip):
    try:
        # Retrieve parsed record
        record = IPWhois(ip).lookup()
        record.pop("raw", None)
        record.pop("raw_referral", None)
        return record

    except ValueError:
        logger.debug("Invalid IP address passed")

    except IPDefinedError:
        logger.debug("Private-use network IP address passed")

    except Exception as unexpected_error:
        logger.error("Unexpected error %s" % unexpected_error)

    return None


# See docs: https://developers.google.com/safe-browsing/lookup_guide#HTTPGETRequest
def lookup_google_safe_browsing(domain):
    url = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=" + settings.GOOGLE_SAFEBROWSING_API_CLIENT + "&key=" + settings.GOOGLE_SAFEBROWSING_API_KEY + "&appver=1.5.2&pver=3.1&url=" + domain
    response = urllib.request.urlopen(url)

    # We only get a request body when Google thinks the indicator is malicious. There are a few different values it might return.
    if response.status == 200:
        body = response.read().decode("utf-8")

    elif response.status == 400:
        logger.error("Bad request to Google SafeBrowsing API. Indicator:")
        logger.error(domain)
        body = "Bad Request to API"

    elif response.status == 401:
        logger.error("Bad API key for Google SafeBrowsing API.")
        body = "Bad Request to API"

    elif response.status == 503:
        logger.error(
            "Google SafeSearch API is unresponsive. Potentially too many requests coming from our application, or their service is down.")
        body = "SafeBrowsing API offline or throttling our requests"

    # There is no body when the API thinks this inidcator is safe.
    else:
        body = "OK"

    return (response.status, body)


def lookup_ip_censys_https(ip):
    api_id = settings.CENSYS_API_ID
    api_secret = settings.CENSYS_API_SECRET

    try:
        ip_data = CensysIPv4(api_id=api_id, api_secret=api_secret).view(ip)
        return ip_data['443']['https']['tls']['certificate']['parsed']
    except KeyError:
        return {'status': 404, 'message': "No HTTPS certificate data was found for IP " + ip}
    except censys.base.CensysException as ce:
        return {'status': ce.status_code, 'message': ce.message}


# def lookup_ip_censys_https_new(ip):
#     # api_id = settings.CENSYS_API_ID
#     # api_secret = settings.CENSYS_API_SECRET
#     api_id = 'e013909c-bdec-4c17-a997-74955b73ac89'
#     api_secret = 'y4nlaUAD9Netlvlc2mcZnhdhohVInAww'
#
#     try:
#         print("enteringg lookup_ip_censys_https: ", ip)
#         test = 'a1833c32d5f61d6ef9d1bb0133585112069d770e'
#         ip_data = CensysIPv4(api_id=api_id, api_secret=api_secret).view(test)
#         print("ip_data_test:", ip_data)
#
#         parsed_json = json.dumps(ip_data)
#         resp = json.loads(parsed_json)
#         # print("resp: ", resp)
#         sha256 = resp['25']['smtp']['starttls']['tls']['certificate']['parsed']['fingerprint_sha256']
#         print("sha256: ", sha256)
#
#         data = {}
#         # data["query"] = 'fingerprint_sha256:e2890192ca76ed2bc429b1b68f4c2909b88c9c2a535692e63d97677d7a429e74'
#         # data["query"] = '443.https.tls.certificate.parsed.fingerprint_sha1:a1833c32d5f61d6ef9d1bb0133585112069d770e'
#         data["query"] = '443.https.tls.certificate.parsed.fingerprint_sha1:a1833c32d5f61d6ef9d1bb0133585112069d770e'
#         data["fields"] = []
#         # value = sha256
#         print("data:", data)
#
#         # works okay
#         # cc = CensysCertificates(api_id=api_id, api_secret=api_secret)
#         #    print ("ccview: ",cc.view("e2890192ca76ed2bc429b1b68f4c2909b88c9c2a535692e63d97677d7a429e74 "))
#         # generator = cc.search(data)
#
#         #    print ("generator: ",generator)
#
#
#         # print("cc:",cc.view('a1833c32d5f61d6ef9d1bb0133585112069d770e'))
#         # fields = ["443.https.tls.certificate.parsed.fingerprint_sha1"]
#         # query = '443.https.tls.certificate.parsed.fingerprint_sha1:a1833c32d5f61d6ef9d1bb0133585112069d770e'
#
#         # for cert in generator:
#         #     print ("cert:", cert["parsed.subject_dn"])
#         # print("cert:", cert['443.https.tls.certificate.parsed.fingerprint_sha1'])
#         #  print ("cert: ",cert["443.https.tls.certificate.parsed.fingerprint_sha1"])
#         # generator = cc.search(sha256)
#         # generator = cc.search('fingerprint_sha256')
#         # print("generator:",generator)
#         # for record in generator:
#         #    print("record:",record['fingerprint_sha256'])
#
#
#
#
#         # API_URL = "https://censys.io/ipv4?q=a1833c32d5f61d6ef9d1bb0133585112069d770"
#         API_URL = "https://www.censys.io/api/v1/search/ipv4"
#         # data = "e2890192ca76ed2bc429b1b68f4c2909b88c9c2a535692e63d97677d7a4"
#
#         # time.sleep(3.5)
#         search = requests.post(API_URL, data=json.dumps(data), auth=(api_id, api_secret))
#
#         # search = requests.post(API_URL, auth=(api_id, api_secret))
#         #  print("search: ", search)
#
#         if search.status_code == 200:
#             results = search.json()
#             print("results: ", results)
#             parsed_test = json.dumps(results)
#             #     print("parsed_test: ", parsed_test)
#             resp = json.loads(parsed_test)
#             print("resp:", resp)
#             parent = resp['results']
#
#         id_all = []
#         for item in parent:
#             print("item ip: ", item['ip'])
#             id_all.append(item['ip'])
#
#             # cert_data = search_ip_for_certificate(sha256)
#             # cert_data = CensysIPv4(api_id=api_id, api_secret=api_secret).view(sha256)
#             #    print("cert_data:", cert_data)
#
#         return ip_data
#         # return ip_data['443']['https']['tls']['certificate']['parsed'] commented out by LNguyen
#     except KeyError:
#         return {'status': 404, 'message': "No HTTPS certificate data was found for IP " + ip}
#     except censys.base.CensysException as ce:
#         return {'status': ce.status_code, 'message': ce.message}


def google_for_indicator(indicator, limit=10, domain=None):
    """
    Find the top 'limit' Google search results for 'indicator' (excluding those from 'domain').

    Note: The domain will be wrapped in quotes before being submitted to Google.  It should therefore NOT be so wrapped
    when passed to this function.

    This method will also filter any results to ensure that none of the URLs returned actually point to the given domain
    (or any subdomain thereof).   In this manner, if you search for "domain.com," results such as
    "http://domain.com/page.html" and "http://sub.domain.com/file.pdf" will NOT be included in the results.

    :param indicator: The indicator value for which to search.  This should NOT be wrapped in quotation marks.
    :param limit: The maximum number of search results to return (optional, default: 10)
    :param domain: A domain from which results should be excluded
    :return: A list containing the URLs of the search results, in the order returned by Google
    """
    logger.debug("Searching Google for indicator '%s' (limit: %d)", indicator, limit)
    parameter = "\"" + indicator + "\""

    if domain is None:
        sifter = core.google.KeepSifter()
    else:
        sifter = core.google.DomainSifter(domain)
    result = list()
    try:
        for info in core.google.search(parameter, limit=limit, sifter=sifter):
            result.append(info.to_dict())
    except Exception:
        # Something went wrong, most likely when querying Google.  There's nothing we can really do about it, so we will
        # log the error and return an empty list
        logger.exception("Unexpected error performing Google search")
        result = list()
    if logger.isEnabledFor(logging.INFO):
        msg = "Found top %d/%d search result(s) for indicator '%s':" % (len(result), limit, indicator)
        rank = 0
        for info in result:
            rank += 1
            url = info["url"]
            msg += "\n\t%d - %s" % (rank, url)
        logger.info(msg)
    return result


def lookup_certs_censys(other, count):
    """Search the Censys.io API for any certificates that contain the search string

        Args:
            other (str): The string to search for in certificates (named other referencing
                the 'other' indicator type
            count (int): The maximum number of records to retrieve

        Returns (dict):
            Returns a dictionary that contains the following keys:
                records (list): A list of the certificates that matched this search string
                total (int): The total number of certificates that match this search
                count (int): The number of records being returned by this search
            If an error occurs while accessing the api, the dictionary will have the following keys:
                status (int): The status code of the error
                message (str): The error message
    """
    api_id = settings.CENSYS_API_ID
    api_secret = settings.CENSYS_API_SECRET

    try:
        cc = CensysCertificates(api_id=api_id, api_secret=api_secret)
        generator = cc.search(other)
        i = 0
        results = {'records': []}
        for record in generator:
            if i == 0:
                results['total'] = generator.gi_frame.f_locals['payload']['metadata']['count']
            for sha256 in record['parsed.fingerprint_sha256']:
                results['records'].append(cc.view(sha256))
                i += 1
            if i >= count:
                break
        results['count'] = i
        return results
    except censys.base.CensysException as ce:
        return {'status': ce.status_code, 'message': ce.message}


def search_ip_for_certificate(value):
    """
    A generator that uses the Census IPv4 API to identify all currently resolving IP addresses for a certificate value.

    :param value: The certificate value for which to search
    :return: The IP addresses
    :raises LookupException: If there was an error performing the lookup
    """
    try:
       # print("entering search_ip_for_certificate...",value)
        api = CensysIPv4(api_id=settings.CENSYS_API_ID, api_secret=settings.CENSYS_API_SECRET)
       # print("api: ", api)
        logger.info("Searching for certificate value: %s", value)
        total = 0

        for result in api.search(query=_escape_censys_value(value), fields=["ip"]):
            total += 1
            if total > 100:
                break
            else:
                yield result["ip"]
        logger.info("Found %d total result(s) for certificate value: %s", total, value)
        #print("IPtotal:",total)
    except censys.base.CensysRateLimitExceededException as e:
        msg = "Censys rate limit exceeded"
        logger.exception(msg)
        result = None
        yield result
        #raise LookupException(msg, e) from e
    except censys.base.CensysUnauthorizedException as e:
        msg = "Censys authorization failed"
        logger.exception(msg)
        result = None
        yield result
        #raise LookupException(msg, e) from e
    except censys.base.CensysNotFoundException as e:
        msg = "Certificate fragment not found in Censys: %s" % value
        logger.exception(msg)
        result = None
        yield result
        #raise LookupException(msg, e) from e
    except Exception as e:
        msg = "Unknown error searching for certificate: %s" % value
        logger.exception(msg)
        result= None
        yield result
       # raise LookupException(msg, e) from e


def accumulate_ip_for_certificate(value):
    """
    A convenience function that wraps the results of 'search_ip_for_certificate' into a Python list.

    :param value: The certificate value for which to search
    :return: The list of IP addresses
    :raises LookupException: If there was an error performing the lookup
    """
    results = list(search_ip_for_certificate(value))
    #print("API results:",results)
    logger.info("Found %d total result(s) for certificate search value: %s", len(results), value)
    return results


def _escape_censys_value(value):
    """Escapes necessary characters for a censys search
    """
    escape_strings = ["+", "-", "=", "&", "|", ">", "<", "!", "(", ")",
                      "{", "}", "[", "]", "^", "\"", "~", "*", "?", ":", "\\", "/"]
    escape_dict = {}
    for escape_string in escape_strings:
        escape_dict[escape_string] = "\\" + escape_string
    return value.translate(str.maketrans(escape_dict))
