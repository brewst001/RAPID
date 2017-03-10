import logging
import re
import datetime  # added by LNguyen
from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from core.utilities import time_jump
from core.utilities import discover_type
from .models import CertificateMonitor, DomainMonitor, IpMonitor, CertificateSubscription, DomainSubscription, IpSubscription
from .tasks import GEOLOCATION_KEY, DOMAIN_KEY, IP_KEY

import collections  #added by LNguyen on 10jan2017

LOGGER = logging.getLogger(__name__)
"""The logger for this module"""

User = get_user_model()

PENDING = "(Pending)"
"""A string used to indicate that a monitor has been submitted but not yet run"""


class MonitorSubmission(forms.Form):
    indicators = forms.CharField(label='Indicator Submission', widget=forms.TextInput())

    def __init__(self, *args, **kwargs):
        super(MonitorSubmission, self).__init__(*args, **kwargs)
        self.valid_domains = []
        self.valid_ips = []

    def clean_indicators(self):
        submission = self.cleaned_data.get('indicators')
        indicator_list = re.split(r'[,;|\n\r ]+', submission)

        for indicator in indicator_list:
            indicator = re.sub(r'[,\';"|\n\r ]+', '', indicator).strip().lower()
           # indicator = indicator.rstrip().lower()
            indicator_type = discover_type(indicator)

            if indicator_type == "domain":
                self.valid_domains.append(indicator)

            if indicator_type == "ip":
                self.valid_ips.append(indicator)

            if indicator_type == "other":
                LOGGER.warn("Discarding attempt to add '%s' as an IP or Domain to be monitored", indicator)
                raise ValidationError("%s is not a valid IP or Domain" % indicator)


    def save_submission(self, request):

        request.success = True
        request.msg = "Indicator has been added for submission"

        current_user = User.objects.get(email__exact=request.user)
        lookup_time = time_jump(minutes=2)
        set_interval = 24


        for domain in self.valid_domains:

            try:
                current_owner = DomainSubscription.objects.get(domain_name=domain).owner
            except DomainSubscription.DoesNotExist:
                current_owner = None
            except DomainSubscription.MultipleObjectsReturned:
                current_owner = DomainSubscription.objects.filter(domain_name=domain, owner=current_user)[0].owner

            try:
                current_domain = DomainMonitor.objects.get(domain_name=domain).domain_name
            except DomainMonitor.DoesNotExist:
                current_domain = None
            except DomainMonitor.MultipleObjectsReturned:
                current_domain = DomainMonitor.objects.filter(domain_name=domain)[0].domain_name


            try:

                new_monitor = DomainMonitor(owner=current_user,
                                            domain_name=domain,
                                            lookup_interval=set_interval,
                                            next_lookup=lookup_time)
                new_monitor = self.update_monitor(new_monitor)
               # new_monitor.save()

                new_subscription = DomainSubscription(domain_name=new_monitor,owner=current_user)

                # IF there is no existing owner and no existing domain in the database, then perform an initial save for the new values
                if not current_owner and not current_domain:
                    new_monitor.save()
                    new_subscription.save()
                # IF the domain exists but there is no existing user, then save the new owner info in the domain subscription table
                elif not current_owner and current_domain == domain:
                    new_subscription.save()
                # IF the domain exists for a different user, then save the owner info in the domain subscription table
                elif current_owner != current_user and current_domain == domain:
                    new_subscription.save()
                # IF no condition is satisified, then set success flag to False and do nothing
                else:
                    request.success = False
                    request.msg = "No indicator added for monitoring because duplicate domain exists"

            except:
                LOGGER.exception("Error saving domain monitor from %s for %s", current_user, domain)
                request.success = False
                request.msg = "Error saving domain monitor for " +  domain

        for ip_address in self.valid_ips:

            try:
                current_owner = IpSubscription.objects.get(ip_address=ip_address).owner
            except IpSubscription.DoesNotExist:
                current_owner = None
            except IpSubscription.MultipleObjectsReturned:
                current_owner = IpSubscription.objects.filter(ip_address=ip_address, owner=current_user)[0].owner

            try:
                current_IP = IpMonitor.objects.get(ip_address=ip_address).ip_address
            except IpMonitor.DoesNotExist:
                current_IP = None
            except IpMonitor.MultipleObjectsReturned:
                current_IP = IpMonitor.objects.filter(ip_address=ip_address)[0].ip_address

            try:
               # current_owner = IpSubscription.objects.get(domain_name=domain).owner
               # current_IP = IpSubscription.objects.get(domain_name=domain).domain_name

                new_monitor = IpMonitor(owner=current_user,
                                        ip_address=ip_address,
                                        lookup_interval=set_interval,
                                        next_lookup=lookup_time)
                new_monitor = self.update_monitor(new_monitor)
              #  new_monitor.save()

                new_subscription = IpSubscription(ip_address=new_monitor, owner=current_user)

                #IF there is no existing owner and no existing IP in the database, then perform an initial save for the new values
                if not current_owner and not current_IP:
                    new_monitor.save()
                    new_subscription.save()
                # IF the IP exists but there is no existing user, then save the new owner info in the IP subscription table
                elif not current_owner and current_IP == ip_address:
                    new_subscription.save()
                # IF the IP exists for a different user, then save the owner info in the IP subscription table
                elif current_owner != current_user and current_IP == ip_address:
                    new_subscription.save()
                # IF no condition is satisified, then set success flag to False and do nothing
                else:
                    request.success = False
                    request.msg = "No indicator added for monitoring because duplicate IP address exists"

            except:
                LOGGER.exception("Error saving IP monitor from %s for %s", current_user, ip_address)
                request.success = False
                request.msg = "Error saving IP monitor for "  + ip_address
    #
    # def save_submission(self, request):
    #
    #     request.success = True
    #     request.msg = "Indicator has been added for submission"
    #
    #     current_user = User.objects.get(email__exact=request.user)
    #     lookup_time = time_jump(minutes=2)
    #     set_interval = 24
    #
    #     for domain in self.valid_domains:
    #
    #         try:
    #             new_monitor = DomainMonitor(owner=current_user,
    #                                         domain_name=domain,
    #                                         lookup_interval=set_interval,
    #                                         next_lookup=lookup_time)
    #             new_monitor = self.update_monitor(new_monitor)
    #             new_monitor.save()
    #         except:
    #             LOGGER.exception("Error saving domain monitor from %s for %s", current_user, domain)
    #             request.success = False
    #             request.msg = "Error saving domain monitor for " +  domain
    #
    #     for ip_address in self.valid_ips:
    #
    #         try:
    #             new_monitor = IpMonitor(owner=current_user,
    #                                     ip_address=ip_address,
    #                                     lookup_interval=set_interval,
    #                                     next_lookup=lookup_time)
    #             new_monitor = self.update_monitor(new_monitor)
    #             new_monitor.save()
    #         except:
    #             LOGGER.exception("Error saving IP monitor from %s for %s", current_user, ip_address)
    #             request.success = False
    #             request.msg = "Error saving IP monitor for "  + ip_address

    def update_monitor(self, monitor):
        """
        Update an indicator monitor.

        The default implementation will return the monitor unmodified.  Subclasses may override this method if they
        provide additional information for the monitor.

        :param monitor: The monitor to be updated.  This will be a subclass of IndicatorLookupBase.
        :return: The updated monitor
        """
        return monitor


class SubmissionWithHosts(forms.Form):
    """
    A Django form for submitting a list of hosts.

    This is intended as a superclass for any monitor forms that would allow the user to specify initial hosts rather
    than considering the initial hosts to be an empty field.  (This means that not all resolved hosts will necessarily
    be considered new the first time the monitor is run.)

    Users may specify any number of hosts.  Multiple hosts are delimited with a comma, semicolon, pipe, or whitespace.
    Subclasses may access validated hosts via the 'valid_hosts' member.  Should subclasses require additional host
    validation (e.g. enforcing only IP addresses as hosts), they should override 'clean_hosts.'

    Finally, this class provides the 'update_monitor' method that will set the 'last_hosts' member of a provided
    IndicatorLookupBase monitor to the hosts provided in the form input.
    """

    hosts = forms.CharField(label="Hosts (separate with comma, semicolon, or space)",
                            widget=forms.TextInput(),
                            required=False)
    """The hosts to be associated with any submitted indicators.  Multiple hosts may be submitted separated by a comma,
    semicolon, pipe, or space."""

    def __init__(self, *args, **kwargs):
        super(SubmissionWithHosts, self).__init__(*args, **kwargs)
        self.valid_hosts = list()

    def clean_hosts(self):
        """
        Clean the values of the 'hosts' form field.

        Note: There's Django magic in this method name.  All method names "clean_foo" are used to clean the data member
        "foo."  Thus this method is used to clean the data member "hosts."

        :return: This method returns no values
        """
        try:
            submission = self.cleaned_data.get("hosts")
            if submission is not None and len(submission) > 0:
                self.valid_hosts = re.split(r"[,;|\n\r ]+", submission)
        except Exception as e:
            LOGGER.exception("Unexpected exception cleaning hosts")
            raise e

    def update_monitor(self, monitor):
        """
        Update an IndicatorLookupBase subclass monitor with the provided last hosts.

        :param monitor: The monitor to be updated
        :return: The updated monitor
        """
        # Note: Even though this class doesn't inherit from MonitorSubmission, using this method signature will ensure
        # that it "just works" if you do multiple inheritance to have both indicator values and hosts (i.e.
        # MonitorSubmissionWithHosts, below).
   #     monitor.last_hosts = list(self.valid_hosts) commented out by LNguyen
        return monitor


class MonitorSubmissionWithHosts(MonitorSubmission, SubmissionWithHosts):
    """
    A Django form allowing users to submit IP or Domain indicators for monitoring with an optional initial list of
    hosts.
    """

    # Note: The idea is that, if they ever want to allow initial hosts to be specified with IPs or Domains, they can
    # just start using this class instead of MonitorSubmission.  (Note that they would still have to update the
    # 'add.html' template, however!)
    def __init__(self, *args, **kwargs):
        super(MonitorSubmissionWithHosts, self).__init__(*args, **kwargs)


class CertificateSubmission(SubmissionWithHosts):
    """
    A Django form for submitting a monitor for a certificate indicator.

    Users submit a certificate fragment.  They may optionally also submit one or more hosts.
    """

    fragment = forms.CharField(label="Certificate Fragment", widget=forms.TextInput())
    """The certificate value to be used as a monitor"""

    def __init__(self, *args, **kwargs):
        super(CertificateSubmission, self).__init__(*args, **kwargs)

    def save_submission(self, request):
        """
        Save a CertificateMonitor based upon the contents of this form.

        :param request: The request being processed
        :return:  This method returns no values
        """
        request.success = True
        request.msg = "Indicator(s) added for monitoring"
        #indicator = self.cleaned_data.get("fragment").replace('','').replace('"','').strip()

        indicator = re.sub(r'[,\';"|\n\r ]+', '', self.cleaned_data.get("fragment")).strip()

        if indicator is None:
            LOGGER.debug("No certificate specified")
            return
        user = User.objects.get(email__exact=request.user)
        lookup_time = time_jump(minutes=2)
        interval = 1
        current_time = datetime.datetime.utcnow()

        # Build the 'resolutions' monitor member.  We're not actually going to do full resolutions now (which would
        # entail doing geo-location and domain lookup for each IP host).   Rather, we'll just use placeholder values
        # until the monitor runs for the first time (as a periodic task).  This is important because it means that we
        # will have a set of hosts already saved for this monitor.  Therefore, when this monitor runs for the first time
        # it will have a previous set of hosts to which to compare.  (In other words, the first time it runs not every
        # host will necessarily be new, and there may be some missing hosts on the first run.)
        resolutions = dict()
        for host in self.valid_hosts:
            if host not in resolutions:
                resolutions[host] = dict()
            resolution = resolutions[host]
            resolution[GEOLOCATION_KEY] = PENDING
            resolution[DOMAIN_KEY] = [PENDING]


     #   for indicator in self.valid_certificates:
        # added by LNguyen on 10jan2017 to retrieve current owner and cert values from the database
        # Need to first check if there is an existing owner with the given cert in the database
        # If an existing owner does not exist, then set existing owner to NONE.
        # If there are multiple existing owners, then set existing owner to the 1st owner
        try:
            current_owner = CertificateSubscription.objects.get(certificate=indicator).owner

        except CertificateSubscription.DoesNotExist:
            current_owner = None
        except CertificateSubscription.MultipleObjectsReturned:
            current_owner = CertificateSubscription.objects.filter(certificate=indicator, owner=user)[0].owner


        # added by LNguyen on 10jan2017
        # Need to check if the given cert exists in the database
        # If the cert does not exist, then set the cert to NONE.
        # If there are multiple entries for the given cert, then set the cert to the 1st entry
        try:
            current_cert = CertificateMonitor.objects.get(certificate_value=indicator).certificate_value

        except CertificateMonitor.DoesNotExist:
            current_cert = None
        except CertificateMonitor.MultipleObjectsReturned:
            current_cert = CertificateMonitor.objects.filter(certificate_value=indicator)[0].certificate_value


        # Finally, we can construct the actual monitor object for the certificate info and save it to the database.
        # updated by LNguyen on 29nov2016
        # added created field
        print("saving Certificate Monitor...")

        monitor = CertificateMonitor(owner=user,
                                     created=current_time,
                                     certificate_value=indicator,
                                     lookup_interval=interval,
                                     next_lookup=lookup_time,
                                     last_hosts=self.valid_hosts,
                                     resolutions=resolutions)
        monitor = self.update_monitor(monitor)

        # Construct the subscription to store the new certificate and owner relationship
        subscription = CertificateSubscription(certificate=monitor,owner=user)


        try:

            # If there is no existing owner and no existing cert in the database, then perform an initial save for the new values in
            # the certificate monitor and certificate subscription tables
            if not current_owner and not current_cert:
               monitor.save()
               subscription.save()

            # If the cert exists but there is no existing owner, then save the new owner info in the certificate subscription table and update the submission for new hosts info
            elif not current_owner and current_cert == indicator:
                subscription.save()
                self.update_submission(request)

            # If the cert exists for a different owner, then save the new owner info in the certificate subscription table and update the submission for new hosts info
            elif current_owner != user and current_cert == indicator:
                subscription.save()
                self.update_submission(request)

            # Else if no condition is satisfied, then set success flag to False and do nothing
            else:
                request.success = False
                request.msg = "No indicator added for monitoring because duplicate certificate exists"
                 # Updates the last_hosts and resoultions fields for the Certificate Monitor record
               #  CertificateMonitor.objects.filter(certificate_value=indicator, owner=user).update(last_hosts=self.valid_hosts,resolutions=resolutions)

           # Enable the following lines to test save for CertificateMontior and CertificateSubscription tables
           # monitor.save()
           # subscription.save()

            LOGGER.info("New certificate monitor from %s for '%s' (initial hosts: %s)",
                        user,
                        indicator,
                        self.valid_hosts)

        except Exception as err:
            LOGGER.exception("Error saving certificate monitor: ", str(err))
            request.success = False
            request.msg = "Error saving certificate monitor submission: " + str(err)


    def update_submission(self, request):
        """
        Created by: LNguyen
        Date: 1/7/2017
        Update a CertificateMonitor based upon the contents of this form.

        :param request: The request being processed
        :return:  This method returns no values
        """
        request.success = True
        request.msg = "Indicator has been updated"
        #indicator = self.cleaned_data.get("fragment").strip()
        indicator = re.sub(r'[,\';"|\n\r ]+', '', self.cleaned_data.get("fragment")).strip()
        if indicator is None:
            LOGGER.debug("No certificate specified")
            return
        user = User.objects.get(email__exact=request.user)
        lookup_time = time_jump(minutes=2)
        interval = 1
        current_time = datetime.datetime.utcnow()

        # Build the 'resolutions' monitor member.  We're not actually going to do full resolutions now (which would
        # entail doing geo-location and domain lookup for each IP host).   Rather, we'll just use placeholder values
        # until the monitor runs for the first time (as a periodic task).  This is important because it means that we
        # will have a set of hosts already fsaved for this monitor.  Therefore, when this monitor runs for the first time
        # it will have a previous set of hosts to which to compare.  (In other words, the first time it runs not every
        # host will necessarily be new, and there may be some missing hosts on the first run.)
        resolutions = dict()
        for host in self.valid_hosts:
            if host not in resolutions:
                resolutions[host] = dict()
            resolution = resolutions[host]
            resolution[DOMAIN_KEY] = [PENDING]
            resolution[GEOLOCATION_KEY] = PENDING



        # Retrieve current certificate hosts info from the database and compare it to new hosts data.
        # If the new hosts data does not exist in the database, then append the data to the list of current hosts data and save the updates in the database
        # If the new hosts data exists in the database, then set the success flag to False and do not save the updates.
        try:
            # Retrieve the current certificate hosts from the database for the given cert
           # lasthosts = CertificateMonitor.objects.get(
           #     certificatesubscription=CertificateSubscription.objects.get(certificate=indicator,
           #                                                                 owner=user)).last_hosts
            lasthosts = CertificateMonitor.objects.get(certificate_value=indicator).last_hosts

            # For every item in the list of new hosts, check to see if it exists in the list of current hosts
            for host in self.valid_hosts:
                # If there is no match, then perform the updates
                if host not in lasthosts:
                   # dbresolutions = CertificateMonitor.objects.get(
                   #     certificatesubscription=CertificateSubscription.objects.get(certificate=indicator,
                   #                                                                 owner=user)).resolutions
                    dbresolutions = CertificateMonitor.objects.get(certificate_value=indicator).resolutions

                    # Combine the current and new hosts to the current list
                    lasthosts.extend(list(self.valid_hosts))

                    # Combine the current and new resolutions and store to temp variable -  dbtmp
                    dbtmp = {**resolutions, **dbresolutions}

                    # Updates the last_hosts and resolutions fields for the Certificate Monitor record
                    CertificateMonitor.objects.filter(certificate_value=indicator).update(last_hosts=lasthosts, resolutions=dbtmp)


#                CertificateMonitor.objects.filter(certificatesubscription=CertificateSubscription.objects.get(certificate=indicator,
#                                                                                                                  owner=user)).update(last_hosts=lasthosts, resolutions=dbtmp)

                # Else if there is no match, then set the success Flag to False and do nothing
                else:
                    request.success = False
                    request.msg =  "Indicator has not been updated because duplicate value exists"

            LOGGER.info("New certificate monitor from %s for '%s' (initial hosts: %s)",
                        user,
                        indicator,
                        self.valid_hosts)
        except Exception as err:
            LOGGER.exception("Error updating certificate monitor: ", str(err))
            request.success = False
            request.msg = "Error updating certificate monitor : " + str(err)

