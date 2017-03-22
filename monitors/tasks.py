"""
Celery tasks for the Monitoring portion of RAPID.
"""

import abc
import datetime

import logging

import core.lookups
import core.tasks

from celery.schedules import crontab
from celery.task import PeriodicTask
from django.contrib.auth import get_user_model

from .models import CertificateMonitor, DomainMonitor, IpMonitor, IndicatorAlert, CertificateSubscription, DomainSubscription, IpSubscription
from pivoteer.models import IndicatorRecord
from pivoteer.records import RecordSource, RecordType
from pivoteer.collectors.scrape import RobtexScraper
from profiles.models import Profile

LOGGER = logging.getLogger(None)
"""The logger for this module"""
# Note: Logging doesn't appear to work properly unless we get the root logger

User = get_user_model()
"""The current user"""

ActiveUsers = Profile.objects.filter(is_active=True)
"""List of active users"""

GEOLOCATION_KEY = "geo_location"
"""The key used in JSON for the geo-location of an IP address"""

COUNTRY_KEY = "country"
"""
The key used in JSON for the location.  This key serves double duty, being used both within the geo-location for the
full country name (e.g. "United States") and within certificate monitors for the resolved country code (e.g. "US").
"""

IP_KEY = "ip"
"""The key used in JSON for an IP address"""

DOMAIN_KEY = "domain"
"""The key used in JSON for a domain name"""

__scraper = RobtexScraper()
"""The scraper used to resolve domain names for IP addresses"""


def get_domains_for_ip(ip):
    """
    Get the list of domains associated with an IP address.
    :param ip:
    :return:
    """

    return __scraper.run(ip)


def enclose_periods_in_braces(value):
    """
    Perform sanitization by enclosing any periods in square braces.

    Example: "domain.com" becomes "domain[.]com"

    :param value: The value to be sanitized
    :return: The sanitized value
    """
    return value.replace('.', '[.]')


class IndicatorLookupSubTask:
    """
    An abstract base class that informs the IndicatorMonitoring periodic task how to retrieve and process indicator
    lookups.

    This class is only suitable for monitors that are a subclass of IndicatorLookupBase.  Subclasses MUST provide the
    following methods:
        - get_value: Given an IndicatorLookupBase retrieved from the database, return the indicator value
        - get_lookup_type: Get the IndicatorLookupBase type (i.e. subclass) that should be retrieved from the database
        - get_type_name: Get a human-readable name for the indicator type of this sub-task (e.g. "Domain").  You should
          capitalize this value.
        - resolve_hosts: Given an indicator value, resolve it to a list of hosts.  This method should return either a
          list of hosts (if successful) or an error string (if unsuccessful).
        - create_record: Given an indicator value, one of its resolved hosts, and a date, create and return an
          IndicatorRecord instance

    Subclasses MAY also elect to override the following methods:
        - sanitize_value: Sanitizes an indicator value of this type.  (For example, a domain indicator "foo.com" might
          be sanitized as "foo[.]com.")  The default implementation for this method will simply return the value
          unmodified.
        - list_hosts: Create a human-readable list of hosts, optionally in a sanitized format.  (See the documentation
          of this method for more information.)
        - update_lookup: Update the lookup object.  Please refer to method documentation for a description of the
          default implementation.
    """
   # print("entering tasks.IndicatorLookupSubTask...")
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_indicator_value(self, lookup):
        """
        Given an IndicatorLookupBase instance (of the type defined by 'get_lookup_type'), return the indicator value.

        :param lookup: The lookup instance
        :return: The indicator value
        """
        raise NotImplementedError("IndicatorLookupSubTask subclass must implement 'get_value'")

    def sanitize_value(self, lookup, value):
        """
        Sanitize an indicator value.

        The default implementation returns the value unmodified.

        :param lookup: The lookup currently being processed
        :param value: The indicator value
        :return: The sanitized indicator value
        """
        return value

    def list_hosts(self, lookup, hosts=None, sanitized=False):
        """
        Return a list of the last hosts in a lookup.

        If 'sanitized' is True, this should return a sanitized version of the hosts.

        The default implementation returns the hosts unmodified if 'sanitized' is False and with hosts run through
        'encode_periods_in_braces' if 'sanitized' is True.

        :param lookup: The lookup being processed
        :param hosts: The hosts to be listed, or None to use the last hosts recorded in the lookup
        :param sanitized: True if the rsults should be sanitized, otherwise false
        :return:
        """
        hosts = hosts or lookup.last_hosts
        if type(hosts) is not list:
            return None
        result=list()
        for host in hosts:
            result.append(host)
        return result
        #return [enclose_periods_in_braces(host) for host in hosts] if sanitized else list(hosts)

    @abc.abstractmethod
    def get_lookup_type(self):
        """
        Get the lookup type for this sub-task.

        :return: The lookup type, which should be a class (NOT instance) that is a subclass of IndicatorLookupBase
        """
        raise NotImplementedError("IndicatorLookupSubTask subclass must implement 'get_lookup_type'")

    @abc.abstractmethod
    def get_type_name(self):
        """
        Get a human-readable name for indicator types handled by this sub-task.

        :return: The human-readable type name
        """
        raise NotImplementedError("IndicatorLookupSubTask subclass must implement 'get_type_name'")

    @abc.abstractmethod
    def get_owners(self,indicator):
        """
            Get a list of subscription owners for indicator types handled by this sub-task.

            :return: The list of subscription owners for the lookup type
            """
        raise NotImplementedError("IndicatorLookupSubTask subclass must implement 'get_owners'")

    @abc.abstractmethod
    def resolve_hosts(self, value):
        """
        Given an indicator value, return a list of resolved hosts for it.

        If successful, this method should return a list of hosts.  IF THIS METHOD RETURNS A LIST, IT IS ASSUMED TO HAVE
        BEEN SUCCESSFUL AND RETURNED HOSTS.  If unsuccessful, a single string should be returned which is a description
        of the error.

        :param value: The indicator value
        :return: The list of resolved hosts, or an error string
        """
        raise NotImplementedError("IndicatorLookupSubTask subclass must implement 'resolve_hosts'")

    @abc.abstractmethod
    def create_records(self, lookup, date=None):
        """
        Create any indicator records necessary.

        This method should only be called AFTER a call to 'update_lookup.'
        :param lookup: The lookup being processed
        :param date: The date to be associated with any indicator records, or None to use the current date
        :return: This method returns no values
        """
        raise NotImplementedError("IndicatorLookupSubTask subclass must implement 'create_records'")

    def update_lookup(self, lookup, current_time, hosts):
        """
        Update the lookup object.

        This method should NOT actually save the lookup object!

        This method is used to update a lookup with a new lookup time and the list of resolved hosts.  The default
        implementation saves 'hosts' as 'lookup.last_hosts' and updates the 'next_lookup' according to the time
        :param lookup: The IndicatorLookupBase to be updated
        :param current_time: The current time
        :param hosts: This parameter could hold two values.  If the host resolution was successful, this will be a list
        of resolved hosts.  If the resolution was unsuccessful, this will be an error message (a string)
        :return: The updated lookup
        """
       # print("running tasks.update_lookup")
        if type(hosts) is list:
            lookup.last_hosts = list(hosts)
        lookup.next_lookup = current_time + datetime.timedelta(hours=lookup.lookup_interval)

        return lookup

    def _save_record(self, record):
        """
        Save an IndicatorRecord.

        This is a convenience method for use by subclasses in their 'create_records' methods to do the actual save with
        exception handling.  (Exceptions are logged, but otherwise ignored.)

        :param record: The IndicatorRecord instance to be saved
        :return: This method returns no values
        """
        try:
           # print("running tasks._save_record")
            record.save()
        except:
            LOGGER.exception("Error saving %s indicator record", self.get_type_name)


class DomainLookupSubTask(IndicatorLookupSubTask):
    """
    A IndicatorLookupSubTask implementation for domains that uses DNS to resolve IP hosts.

    This lookup sub-task creates Host Record (HR) indicator records with a source of DNS (DNS Query).
    """

    def get_indicator_value(self, lookup):
        return lookup.domain_name

    def sanitize_value(self, lookup, value):
        return enclose_periods_in_braces(value)

    def get_lookup_type(self):
        return DomainMonitor

    def get_type_name(self):
        return "Domain"

    def get_owners(self,indicator):
       # print("entering DomainLookup.get_owners")
        owners = []
        for owner in DomainSubscription.objects.filter(domain_name=indicator, owner=ActiveUsers):
            owners.append(owner.owner)
        return owners


    def resolve_hosts(self, value):
        try:
            #print("running Domain.resolve_hosts")
            return core.lookups.resolve_domain(value)
        except core.lookups.LookupException as e:
            LOGGER.error("Domain resolution failed for domain '%s': %s", value, e.message)
            return e.message

    def create_records(self, lookup, date=None):
        #print("running tasks.DomainLookupSubTask.create_records")
        domain = self.get_indicator_value(lookup)
        if type(lookup.last_hosts) is list:
            for ip in lookup.last_hosts:
                location = core.lookups.geolocate_ip(ip)
                info = {GEOLOCATION_KEY: location,
                        IP_KEY: ip,
                        DOMAIN_KEY: domain}
                record = IndicatorRecord(record_type=RecordType.HR.name,
                                         info_source=RecordSource.DNS.name,
                                         info_date=date,
                                         info=info)
                #print("saves the Domain record to the Pivoteer_IndicatorRecord table")
                self._save_record(record)


    def save_lookup(self, indicator, lookup, date):
        #print("updates the Domain record in the Monitors_DomainMonitor table")
        lookup.save()

class IpLookupSubTask(IndicatorLookupSubTask):
    """
    A IndicatorLookupSubTask implementation for IP addresses that uses Robetex to resolve domain hosts.

    This lookup sub-task creates Host Record (HR) indicator records with a source of REX (Robotex).
    """

    def get_indicator_value(self, lookup):
        return lookup.ip_address

    def sanitize_value(self, lookup, value):
        return enclose_periods_in_braces(value)

    def get_lookup_type(self):
        return IpMonitor

    def get_type_name(self):
        return "IP"

    def get_owners(self,indicator):
       # print("entering IPLookup.get_owners")
        owners = []
        for owner in IpSubscription.objects.filter(ip_address=indicator, owner=ActiveUsers):
            owners.append(owner.owner)
        return owners


    def resolve_hosts(self, value):
        #print("running IPLookup.resolve_hosts")
        return get_domains_for_ip(value)

    def create_records(self, lookup, date=None):
       # print("running tasks.IPLookupSubTask.create_records")
        ip = self.get_indicator_value(lookup)
        if type(lookup.last_hosts) is list:
            for domain in lookup.last_hosts:
                location = core.lookups.geolocate_ip(ip)
                info = {GEOLOCATION_KEY: location,
                        IP_KEY: ip,
                        DOMAIN_KEY: domain}
                record = IndicatorRecord(record_type=RecordType.HR.name,
                                         info_source=RecordSource.DNS.name,
                                         info_date=date,
                                         info=info)
                #print("saves the IP record to the Pivoteer_IndicatorRecord table")
                self._save_record(record)


    def save_lookup(self, indicator, lookup, date):
        #print("updates the IP record in the Monitors_IPMonitor table")
        lookup.save()


class CertificateLookupSubTask(IndicatorLookupSubTask):
    """
    A IndicatorLookupSubTask implementation for Certificate indicators that uses Censys to resolve IP hosts.

    The IpLookupSubTask resolves IP values to domain hosts.   This class extends that class in order to leverage this
    functionality to take the resolved IP hosts and then resolve those in turn to domain hosts.
    """
    #print("running tasks.CertificateLookupSubTask")

    def get_indicator_value(self, lookup):
        return lookup.certificate_value

    def get_lookup_type(self):
        return CertificateMonitor

    def get_type_name(self):
        return "Certificate"

    def get_owners(self,indicator):
        #print("entering CertificateLookup.get_owners")

        owners = []
        for owner in CertificateSubscription.objects.filter(certificate=indicator, owner=ActiveUsers):
            owners.append(owner.owner)
        return owners

    def resolve_hosts(self, value):
        try:
            return core.lookups.accumulate_ip_for_certificate(value)
        except core.lookups.LookupException as e:
            LOGGER.error("Certificate search failed for fragment '%s': %s", value, e.message)
            return e.message

    def list_hosts(self, lookup, hosts=None, sanitized=False):
        #print("running tasks.CertificateLookupSubTask.list_hosts")
        hosts = hosts or lookup.last_hosts
        if type(hosts) is not list:
            return None
        result = list()
        for host in hosts:
            # If there is no resolution saved for this IP, log a warning and include what we can
            if host not in lookup.resolutions:
                LOGGER.warn("Certificate host '%s' has no resolution information", host)
                description = "%s (No Resolution Information Available)" % host
                result.append(description)
                continue
            # Otherwise there IS resolution saved
            info = lookup.resolutions[host]
            ip = enclose_periods_in_braces(host) if sanitized else host
            location = info[GEOLOCATION_KEY]
            domains = [enclose_periods_in_braces(domain) if sanitized else domain for domain in info[DOMAIN_KEY]]
           # description = "%s (%s) - %s" % (ip, location, domains)
            description = "%s" % (host)
            result.append(description)
        return result

    def create_records(self, lookup, date=None):
        #print("entering CertificateLookupTask.create_records")

        if lookup.resolutions is None:
           # print("lookup.resolutions is none", lookup.resolutions)
            return
        else:
            for ip in lookup.resolutions:
                resolution = lookup.resolutions[ip]
                location = resolution[GEOLOCATION_KEY]
                for domain in resolution[DOMAIN_KEY]:
                    info = {GEOLOCATION_KEY: location,
                            IP_KEY: ip,
                            DOMAIN_KEY: domain}
                    record = IndicatorRecord(record_type=RecordType.HR.name,
                                             info_source=RecordSource.DNS.name,
                                             info_date=date,
                                             info=info)
                    #print("saving the certificate records to the Pivoteer_IndicatorRecord table")
                    self._save_record(record)
                    LOGGER.debug("Created host record: %s", info)

    def save_lookup(self, indicator,lookup, date):
       # print("updates the Certificate record in the Monitors_CertificateMonitor table")
             # Replace lookup.save with custom save to save results in Certificate Monitor table by certificate value
        CertificateMonitor.objects.filter(certificate_value=indicator).update(last_hosts=lookup.last_hosts,
                                                                              resolutions=lookup.resolutions,
                                                                              next_lookup=lookup.next_lookup,
                                                                              modified=date)


    def update_lookup(self, lookup, current_time, hosts):

        #print("running tasks.CertificateLookupSubTask.update_lookup")
        # First, we perform all of the common update functions.
        super(CertificateLookupSubTask, self).update_lookup(lookup, current_time, hosts)

        # If host resolution failed (i.e. 'hosts' is not a list), there is nothing else to do
        if type(hosts) is not list:
            LOGGER.debug("Cannot update lookup resolutions because host lookup failed")
           # print("Cannot update lookup resolutions because host lookup failed")
            return lookup

        # Reset the resolutions dictionary and then rebuild it using the current hosts
        lookup.resolutions = dict()

        # Iterate over all resolved hosts (all of which are IP addresses)
        for ip in hosts:
            LOGGER.debug("Processing certificate fragment '%s' resolved IP: %s",
                         self.get_indicator_value(lookup),
                         ip)
            # Make sure we have an entry for this IP
            if ip not in lookup.resolutions:
                lookup.resolutions[ip] = dict()
            resolution = lookup.resolutions[ip]

            # Geo-Location/Country
            try:
                location = core.lookups.geolocate_ip(ip)
                country = location[COUNTRY_KEY]
            except:
                LOGGER.exception("Location lookup failed for IP: %s", ip)
                location = "(Location Lookup Failed)"
                country = location
            resolution[GEOLOCATION_KEY] = location
            LOGGER.debug("Geo-location of IP '%s': %s", ip, location)

            try:
                code = core.lookups.get_country_code(country)
            except KeyError:
                LOGGER.warn("No country code available for '%s' (using full name instead)", country)
                code = country
            resolution[COUNTRY_KEY] = code
            LOGGER.debug("Country code of IP '%s': %s", ip, code)
            # Domains
            #print("get domain for ip: ", ip)
            domains = get_domains_for_ip(ip)
            #print("domains:", domains)
            resolution[DOMAIN_KEY] = domains
            LOGGER.debug("Resolved domains of IP '%s': %s", ip, domains)
            #print("resolution: ", resolution)
            #print("lookup.resolution:", lookup.resolutions)

        return lookup



class Update_Users(PeriodicTask):
    run_every = crontab()

    def run(self, **kwargs):
       print("Updating users alert flag...")
       fname = Profile.objects.filter(id=185)[0].email
       print("fname:",fname)
       last_login = Profile.objects.filter(id=185)[0].last_login
       print("lastlogin:",last_login)
       current_time = datetime.datetime.utcnow()
       print("current_time",current_time)
       #delta = current_time - last_login
       #print("date difference:", delta.days)
       expdate = current_time - datetime.timedelta(days=90)
       print("expdate:",expdate)
       Profile.objects.filter(last_login__lte = expdate).update(alerts=False)


class IndicatorMonitoring(PeriodicTask):
    """
    Monitor indicators as a periodic task.

    This class is designed for handling monitoring tasks defined in the database by a subclass of IndicatorLookupBase.
    Adding a new type is pretty easy:
        1. Create a new *Monitor class in monitors/models.py by subclassing IndicatorLookupBase.  Make sure it's
           imported in this module.
        2. Create a new subclass of IndicatorLookupSubTask for your new monitor.  (Remember to make sure of the existing
           functions in core/lookups.py if possible!)
        3. Add an instance of this subclass to the 'SUBTASKS' member of this class
    """
    #print("entering tasks.IndicatorMonitoring")

   # SUBTASKS = [DomainLookupSubTask(), IpLookupSubTask(), CertificateLookupSubTask()]
    SUBTASKS = [CertificateLookupSubTask(), DomainLookupSubTask(), IpLookupSubTask()]

    run_every = crontab()

    def run(self, **kwargs):
        """
        Run this task.

        This method will call 'monitor_lookups' for every sub-task defined in the 'SUBTASKS' member.

        :param kwargs: Additional keyword arguments (this parameter is ignored)
        :return: This method returns no values
        """
        print("running IndicatorMonitoring.run")
        LOGGER.debug("Running monitor lookups...")
        for subtask in IndicatorMonitoring.SUBTASKS:
             self.do_indicator_lookups(subtask)

        LOGGER.debug("Monitor lookups complete.")

    @staticmethod
    def get_lookups(lookup_type, current_time):
        """
        Get the list of lookups from the database to be processed.

        :param lookup_type: The lookup type, which should be a type (class) that is a subclass of IndicatorLookupBase
        :param current_time: The current time (as a string)
        :return: A list of lookups
        """

       # return lookup_type.objects.filter(next_lookup__lte=current_time)
       # return lookup_type.objects.filter()  # gets the list of lookups without respect to the time-- use this for testing

        return lookup_type.objects.filter(next_lookup__lte=current_time)

    def do_indicator_lookups(self, subtask):
        """
        Process all lookups for a sub-task.

        :param subtask: The sub-task that defines how to retrieve and process lookups.
        :return: This method returns no values
        """
        print("running tasks.do_indicator_lookups")
        type_name = subtask.get_type_name()
        lookup_type = subtask.get_lookup_type()
        print("lookuptype:",lookup_type)
        LOGGER.debug("Running monitor lookups for %s indicators...", type_name)

        # Time values
        start_timestamp = datetime.datetime.utcnow()
        minute_timestamp = start_timestamp.strftime('%Y-%m-%d %H:%M')
        current_time = datetime.datetime.strptime(minute_timestamp, '%Y-%m-%d %H:%M')

        # Retrieve the lookups (monitors) from the database and iterate over them...
        lookups = self.get_lookups(lookup_type=lookup_type,
                                   current_time=current_time)
       # print("lookups:",lookups)
        if LOGGER.isEnabledFor(logging.INFO) and len(lookups) > 0:
            LOGGER.info("Found %d %s lookups to be processed...", len(lookups), type_name)
        for lookup in lookups:

            indicator = subtask.get_indicator_value(lookup)

            print("indicator:", indicator)

            #print("calling get_owners...")
            owner = subtask.get_owners(indicator)
            print("ownerlist:", owner)

            LOGGER.info("Processing lookup from %s for %s '%s'", owner, type_name, indicator)

            # Get the historical list of hosts.  (For some monitors, if this is the first time they've run, there are none.)
            last_hosts = list() if lookup.last_hosts is None else list(lookup.last_hosts)
            #print("historical last hosts: ", last_hosts)  # ['95.215.44.38', '185.86.151.180', '89.238.132.210', '89.34.111.119', '185.25.50.117']
            LOGGER.debug("Previous lookup hosts: %s", last_hosts)

            # Do a lookup for any new hosts.  Note that this returns a list of resolved hosts if successful and an error message
            # string if unsuccessful.
            #print("calling subtask.resolve_hosts...")
            current_hosts = subtask.resolve_hosts(indicator)
            #print("new current hosts lookup: ",current_hosts)  # ['95.215.44.38', '89.238.132.210', '89.34.111.119', '185.25.50.117']
            LOGGER.debug("New lookup hosts: %s", current_hosts)
            print("current hosts length:",len(current_hosts))
            print("last hosts length:", len(last_hosts))


            #print("last_hostsp:",last_hosts)
            #print("current_hostsp:",current_hosts)

            # If there is no new hosts information, then no need to do any comparison.  Set new_hosts and missing_hosts to empty set
            if not current_hosts:
                new_hosts = []
                missing_hosts = []

                #Set the current hosts to the historical list if it exists
                if len(last_hosts) > 0:
                    current_hosts = last_hosts


            #Else if there is new hosts information, then compare it to the historical data
            else:
                # Compare the historical host list to the list of new hosts and added any original hosts entries to the new hosts list
                if len(last_hosts) > 0:
                    missing_hosts = list(set(last_hosts).difference(current_hosts))  # get any missing hosts from the historical list that dropped off
                    delta_hosts = list(set(current_hosts).difference(last_hosts)) #get the delta items that are not from the historical list and are new hosts only
                    new_hosts = delta_hosts
                    #print("missing_hosts:",missing_hosts)
                    #print("delta_hosts:",delta_hosts)
                    current_hosts.extend(missing_hosts)


                # If there is no historical host information then no comparison is needed.
                # Just set new_hosts to the current host information and continue on.
                #if not last_hosts:
                else:
                    print("This is an initial search and no historical data exists for current indicator")
                    LOGGER.debug("Initial search for %s '%s'", type_name, indicator)
                    new_hosts = current_hosts
                    missing_hosts = []

            #print("last_hostsx:",last_hosts)
            #print("missing_hostsx:", missing_hosts)
            #print("new_hostsx:", new_hosts)
            #print("current_hostsx:",current_hosts)


            # Update and re-save the lookup with updated hosts info
            #print("calling subtask.update_lookup")
            lookup = subtask.update_lookup(lookup=lookup, current_time=current_time, hosts=current_hosts)

            #print("calling lookup.save()...")
            subtask.save_lookup(indicator,lookup,current_time)
            # lookup.save()
            # Added by LNguyen 1/13/2017
            # Replace lookup.save with custom save to save results in Certificate Monitor table by certificate value
            #CertificateMonitor.objects.filter(certificate_value=indicator).update(last_hosts=lookup.last_hosts,resolutions=lookup.resolutions,next_lookup=lookup.next_lookup)
            LOGGER.info("Next lookup time will be %s", lookup.next_lookup)

            # If resolving hosts returned a string, it is an error message.  We need to create an alert, and then
            # processing is done for this lookup and we can continue to the next.
            if type(current_hosts) == str:
                #alert_text = current_hosts
                alert_text = 'Resolved hosts returned a string: ' + current_hosts
                self.create_alert(indicator, alert_text, owner)
                LOGGER.error("Alert created for %s '%s' from %s: %s", type_name, indicator, owner, alert_text)
                continue

            # Otherwise, this should actually be a list of hosts.  We need to save Pivoteer IndicatorRecords in the
            # database for each.
            #print("calling routine to save Pivoteer_IndicatorRecords for lookup task...")
            subtask.create_records(lookup=lookup, date=current_time)


            #print("last_hosts: ", last_hosts)
            #print("new_Hosts: ", new_hosts)
            #print("missing_hosts: ", missing_hosts)

            if not missing_hosts and not new_hosts:
                print("No host changes detected")
                LOGGER.info("No host changes detected for %s '%s'", type_name, indicator)
            # if LOGGER.isEnabledFor(logging.INFO):
            #     if 0 < len(missing_hosts):
            #         LOGGER.info("Detected %d missing host(s) for %s '%s': %s",
            #                     len(missing_hosts),
            #                     lookup_type,
            #                     indicator,
            #                     missing_hosts)
            #     if 0 < len(new_hosts):
            #         LOGGER.info("Detected %d new host(s) for %s '%s': %s",
            #                     len(new_hosts),
            #                     lookup_type,
            #                     indicator,
            #                     new_hosts)

            # If we got here, it means that there are new hosts, or removed hosts, or both.  We will send only one
            # email, but we will send separate alerts for new hosts and removed hosts as applicable.  The email should
            # contained sanitized values, but the alert(s) should use unsanitized values.
            sanitized_value = subtask.sanitize_value(lookup, indicator)

            #recipients = [owner]  commented out by LNguyen on 1/19/2017 since owner is already a list of user emails
            recipients = owner
            subject = "Host Changes for %s Value: %s" % (type_name, sanitized_value)
            body = """
            %s lookup performed at %s has detected changes in the resolution of tracked %s value '%s':\n\n
            """ % (type_name, current_time, type_name, sanitized_value)

            NeedToAlert = False

            if last_hosts:
                # alert_text = 'Removed hosts: %s' % ', '.join(subtask.list_hosts(lookup, hosts=missing_hosts))
                # self.create_alert(indicator=indicator, alert_text=alert_text, owner=owner)
                body += "Previously known IP(s) were identified with this cert value: \n%s\n\n" % subtask.list_hosts(
                    lookup, hosts=last_hosts, sanitized=True)
            # if missing_hosts:
            #     alert_text = 'Removed hosts: %s' % ', '.join(subtask.list_hosts(lookup, hosts=missing_hosts))
            #    # self.create_alert(indicator=indicator, alert_text=alert_text, recipients=owner)
            #     body += "The following previous IP associations are missing from the database: %s\n\n" % subtask.list_hosts(
            #         lookup, hosts=missing_hosts, sanitized=True)
            #     NeedToAlert = True
            if new_hosts:
                alert_text = "Added hosts: %s" % ", ".join(subtask.list_hosts(lookup, hosts=new_hosts))
               # self.create_alert(indicator=indicator, alert_text=alert_text, recipients=owner)
                # body += "\tAdded hosts: %s\n" % subtask.list_hosts(lookup, hosts=new_hosts, sanitized=True)
                body += "The following new IPs were identified: \n%s\n\n" % subtask.list_hosts(lookup, hosts=new_hosts,
                                                                                               sanitized=True)
                NeedToAlert = True

            #Update logic to send email alert if there are missing hosts or new hosts added
            if NeedToAlert:
               self.create_alert(indicator=indicator, alert_text=alert_text, recipients=owner)
               print("sending email...")
             #  print("body:", body)
               print("recipients:", recipients)
               self.send_email(indicator, subject, body, recipients)

    @staticmethod
    def create_alert(indicator, alert_text, recipients):
        """
        Create and save a new IndicatorAlert.

        :param indicator: The indicator value for which the alert is being created
        :param alert_text: The text of the alert
        :param owner: The recipient of the alert
        :return: This method returns no values
        """
        try:
            print("running IndicatorMonitoring.create_alert")
            #print("recipients:",recipients)
            for owner in recipients:
                #print("recipientowner:",owner)
                new_alert = IndicatorAlert(indicator=indicator, message=alert_text, recipient=owner)
                new_alert.save()
                LOGGER.info("Created alert to %s for indicator '%s':\n%s", owner, indicator, alert_text)
        except:
            LOGGER.exception("Error saving alert to %s for indicator '%s': %s", owner, indicator, alert_text)

    @staticmethod
    def send_email(indicator, subject, body, recipients):
        """
        Send an email.

        This is a helper method intended to try to send an email and to create an alert if sending the email fails.

        :param indicator: The indicator for which an email is to be sent
        :param subject: The email subject
        :param body: The body text of the email
        :param recipients: The list of owners to which emails should be sent.  (This should be a list of actual objects,
        not just email strings, where the objects each correspond to the 'owner' member of an IndicatorLookupBase
        instance.)
        :return: This method returns no values
        """
        emails = []
        #for owners in recipients:
        #    print("owner in list: ", owners)
        emails = [owners.email for owners in recipients]
            #emails.append(list(owners))
        #emails = [owner.email for owner in recipients]
        try:
            print("entering tasks.send_emails: ")
            core.tasks.deliver_email(subject=subject, body=body, recipients=emails)
            LOGGER.debug("Sent email to %s:\n%s\n\n%s", emails, subject, body)
        except Exception:
            LOGGER.exception("Error sending email to %s", emails)
            message = "Error sending alert email to '%s'.  Please consult server log." % emails
            IndicatorMonitoring.create_alert(indicator, message, recipients)
            #for owner in recipients:
            #    message = "Error sending alert email to '%s'.  Please consult server log." % owner.email
            #    IndicatorMonitoring.create_alert(indicator, message, owner)
