import csv
import json
import datetime
import logging
import dateutil.parser
#from promise import Promise

from django.http import HttpResponse
from django.shortcuts import render
from django.views.generic.base import View
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

from .forms import SubmissionForm
from .models import IndicatorRecord, TaskTracker
from core.utilities import time_jump, discover_type
from core.lookups import geolocate_ip
from celery.result import GroupResult
from braces.views import LoginRequiredMixin
from pivoteer.records import RecordType
from pivoteer.writer.censys import CensysCsvWriter
from pivoteer.writer.hosts import HostCsvWriter
from pivoteer.writer.malware import MalwareCsvWriter
from pivoteer.writer.safebrowsing import SafeBrowsingCsvWriter
from pivoteer.writer.search import SearchCsvWriter
from pivoteer.writer.threatcrowd import ThreatCrowdCsvWriter
from pivoteer.writer.whois import WhoIsCsvWriter
from pivoteer.writer.dnstwist import DNSTwistCsvWriter


LOGGER = logging.getLogger(__name__)

# promise = Promise(
#     lambda resolve, reject:resolve('RESOLVED!')
# )

class PivotManager(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = 'pivoteer/pivoteer.html'

    def __init__(self):
        self.template_vars = {'SubmissionForm': SubmissionForm}

    def get(self, request):
        request.dateval = datetime.datetime.utcnow()
        return render(request, self.template_name, self.template_vars)

    def post(self, request):

        task_tracking = {}
        submitted_form = SubmissionForm(request.POST)
        current_time = datetime.datetime.utcnow()
        desired_time = time_jump(hours=-24)

        if submitted_form.is_valid():
            recent_tasks = submitted_form.check_recent_tasks(desired_time)

            # If a recent task exists, use that one instead
            if recent_tasks:
                task_tracking['id'] = recent_tasks.group_id
            else:
                new_task = submitted_form.create_new_task(current_time)

                if new_task:
                    task_tracking['id'] = new_task.id
                else:
                    task_tracking["errors"] = "Unexpected Failure"

        else:  # pass form errors back to user from async request
            task_tracking["errors"] = submitted_form.errors

        json_response = json.dumps(task_tracking)
        return HttpResponse(json_response, content_type="application/json")


# Check if task completed
# https://zapier.com/blog/async-celery-example-why-and-how/
class CheckTask(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = "pivoteer/UnknownRecords.html"

    def __init__(self):
        self.template_vars = {}

    def get_pds_data(self, indicator, request):
    # Subroutine to format PDNS data for the Historical hosts tab
        pds_data = []
        try:
            pds_records = IndicatorRecord.objects.pds_historical_hosts(indicator)

            info = pds_records['info']
            info_source = pds_records['info_source']

            if discover_type(indicator) == "ip":

                location = geolocate_ip(indicator)

                for record in info['results']:
                    record['info'] = record
                    record['firstseen'] = dateutil.parser.parse(record['firstseen'])
                    record['lastseen'] = dateutil.parser.parse(record['lastseen'])
                    record['location'] = location
                    record['info_source'] = info_source
                    pds_data.append(record)

            elif discover_type(indicator) == "domain":

                for record in info['results']:
                    record['info'] = record
                    record['location'] = geolocate_ip(record['ip'])
                    record['firstseen'] = dateutil.parser.parse(record['firstseen'])
                    record['lastseen'] = dateutil.parser.parse(record['lastseen'])
                    record['info_source'] = info_source
                    pds_data.append(record)

            # for result in info['results']:
            #  #   info = getattr(record, 'info')
            #     result['location'] = location
            #     result['firstseen'] = dateutil.parser.parse(result['firstseen'])
            #     result['lastseen'] = dateutil.parser.parse(result['lastseen'])
            #     result['info_source'] = info_source
            #     pds_data.append(result)

        except Exception as err:
            LOGGER.error("Historical PDS processing failed for indicator '%s': %s ", indicator, str(err))

        return pds_data


    def get_dns_host_data(self, indicator, request, type):
    # Subroutine to format DNS hosts data for the Recent and Historical hosts tabs
        dnshost_data = []

        try:
            if type == 'Recent':
                dnshost_records = IndicatorRecord.objects.dns_recent_hosts(indicator)

            elif type =="Historical":
                dnshost_records = IndicatorRecord.objects.dns_historical_hosts(indicator)


            # We must lookup the country for each IP address for use in the template.
            # We do this outside the task because we don't know the IP addresses until the task completes.
            for record in dnshost_records:
                info = record['info']
                record['firstseen'] = record['info_date']
                record['lastseen'] = ''
                record['location'] = geolocate_ip(info['ip'])
                dnshost_data.append(record)

        except Exception as err:
            LOGGER.error("DNS Historical processing failed for indicator '%s': %s", indicator, str(err))

        return dnshost_data


    def get_host_data(self, indicator, request, type):
    # Subroutine to format miscellaneous hosts data for the Recent and Historical hosts tabs
        host_data = []

        try:
            if type =="Recent":
                host_records = IndicatorRecord.objects.recent_hosts(indicator)

            elif type == "Historical":
                host_records = IndicatorRecord.objects.historical_hosts(indicator, request)


            if discover_type(indicator)== "ip":

                location = geolocate_ip(indicator)

                for record in host_records:
                        info = record['info']
                        record['firstseen'] = dateutil.parser.parse(info['firstseen'])
                        record['lastseen'] = dateutil.parser.parse(info['lastseen'])
                        record['location'] = location
                        record['info_source'] = record['info_source']
                        host_data.append(record)

            elif discover_type(indicator)=="domain":

                for record in host_records:
                    info = record['info']
                    record['location'] = geolocate_ip(info['ip'])
                    record['firstseen'] = dateutil.parser.parse(info['firstseen'])
                    record['lastseen'] = dateutil.parser.parse(info['lastseen'])
                    record['info_source'] = record['info_source']

                    host_data.append(record)


            # We must lookup the country for each IP address for use in the template.
            # We do this outside the task because we don't know the IP addresses until the task completes.
            # for record in host_records.iterator():
            #     info = record['info']
            #     record['location'] = geolocate_ip(info['ip'])
            #     record['info_source'] = record['info_source']
            #
            #     if (record['info_source'] == "PTO"):
            #          record['firstseen'] = dateutil.parser.parse(info['firstseen'])
            #          record['lastseen'] = dateutil.parser.parse(info['lastseen'])
              #       record['info_source'] = record['info_source']


             #   host_data.append(record)

        except Exception as err:
            LOGGER.error("Historical processing failed for indicator '%s': %s", indicator, str(err))

        return host_data


    def post(self, request):

        task = request.POST['task_id']
        res = GroupResult.restore(task)

        if res and not res.ready():
            return HttpResponse(json.dumps({"status": "loading"}), content_type="application/json")

        # Task completion allows for origin information to be pulled
        try:
            task_origin = TaskTracker.objects.get(group_id=task)
            record_type = task_origin.type
            indicator = task_origin.keyword


        except MultipleObjectsReturned:
            task_origin = TaskTracker.objects.filter(group_id=task).latest('date')
            record_type = task_origin.type
            indicator = task_origin.keyword

        except ObjectDoesNotExist:
            record_type = None
            indicator = None

        # Pull data according to the record type
        if record_type == "Recent":
         #Recent tab should include recent DNS and other hosts data that have been retrieved from APIs within 24 hrs
            self.template_name = "pivoteer/RecentRecords.html"

            dns_records = self.get_dns_host_data(indicator, request, 'Recent')
            misc_records = self.get_host_data(indicator, request, 'Recent')
            recent_records = dns_records + misc_records

            self.template_vars["current_hosts"] = recent_records

            # Pull data according to the record type
        elif record_type == "RecentThreat":

            self.template_name = "pivoteer/RecentThreat.html"

                # Current ThreatCrowd record
            tc_info = IndicatorRecord.objects.recent_tc(indicator)
            self.template_vars["tc_info"] = tc_info

        elif record_type == "RecentCert":

            self.template_name = "pivoteer/RecentCert.html"
            cert_info = []
            #cert_info = IndicatorRecord.objects.recent_cert(indicator)
            self.template_vars["cert_info"] = cert_info

        elif record_type == "WhoIs":

            self.template_name = "pivoteer/WhoIsRecords.html"

            whois_record = IndicatorRecord.objects.historical_whois(indicator)
            self.template_vars["historical_whois"] = whois_record

        elif record_type == "HistoricalDNS":
            # Historical DNS tab should include only DNS host data that have been retrieved from APIs beyond 24 hrs
            self.template_name = "pivoteer/HistoricalRecords.html"
            self.template_vars["host_records"] = self.get_dns_host_data(indicator, request, 'Historical')

        elif record_type == "Historical":
            # Historical tab should include other hosts data that have been retrieved from APIs beyond 24 hrs and all PDNS host data
            self.template_name = "pivoteer/HistoricalRecords.html"

            misc_records = self.get_host_data(indicator, request, "Historical")
            pds_records = self.get_pds_data(indicator, request)
            historical_records = misc_records + pds_records

            self.template_vars["host_records"] = historical_records

        elif record_type == "Malware":

            self.template_name = "pivoteer/MalwareRecords.html"

            malware_records = IndicatorRecord.objects.malware_records(indicator)
            self.template_vars["malware_records"] = malware_records

            self.template_vars["origin"] = indicator

        elif record_type == "SafeBrowsing":

            safebrowsing_records = IndicatorRecord.objects.safebrowsing_record(indicator)
            self.template_name = "pivoteer/Google.html"
            self.template_vars["records"] = safebrowsing_records
            self.template_vars["google_url"] = settings.GOOGLE_SAFEBROWSING_URL + indicator

            self.template_vars["origin"] = indicator

        elif record_type == "Search":
            self.template_name = "pivoteer/SearchRecords.html"
            search_records = IndicatorRecord.objects.get_search_records(indicator)
            self.template_vars["search_records"] = search_records

        elif record_type == "External":
            self.template_name = "pivoteer/ExternalRecords.html"
            self.template_vars['indicator'] = indicator
            self.template_vars['type'] = discover_type(indicator)

        elif record_type == "DNSTwist":
            self.template_name = "pivoteer/DNSTwist.html"
            dnstwist_records = IndicatorRecord.objects.get_dnstwist_record(indicator)
            self.template_vars['dnstwist_records'] = dnstwist_records


        return render(request, self.template_name, self.template_vars)


class ExportRecords(LoginRequiredMixin, View):
    # ---------------------------------------------------
    # HELP!  I want to add export support for a new type!
    # ---------------------------------------------------
    # Follow these simple steps:
    # 1. Create a pivoteer.writer.core.CsvWriter subclass that processes your record type.
    # 2. Update ExportRecords._get_csv_writer to return an instance of the writer you created in Step 1.
    # 3. Add a new method to ExportRecords that performs two steps:
    #     a. Retrieve IndicatorRecords (via a method on pivoteer/models/IndicatorManager)
    #     b. Call self._write_records with your record type, the indicator value, and the records obtained in Step A
    #         Note: If Step A returns a single record, you must wrap it in a list for Step B
    # 4. Update ExportRecords.get to call the method you created in Step 3.

    login_url = "login"
    redirect_unauthenticated_users = True

    def __init__(self):

        # Create the HttpResponse object with the appropriate CSV header.
        self.response = HttpResponse(content_type='text/csv')
        self.response['Content-Disposition'] = 'attachment; filename="exported_records.csv"'
        self.writer = csv.writer(self.response)

    def get(self, request):
        indicator = request.GET.get('indicator', '')
        filtering = request.GET.get('filter', '')
        LOGGER.debug("EXPORTING '%s' with filter: %s", indicator, filtering)

        if indicator and filtering == '':
            #self.export_recent(indicator)
            self.export_recent_hosts(indicator)
            self.line_separator()
            self.export_recent_threatcrowd(indicator)
            self.line_separator()
            #self.export_recent_certificates(indicator)
            #self.line_separator()
            self.export_whois(indicator)
            self.line_separator()
            self.export_historical_hosts(indicator, request)
            self.line_separator()
            self.export_malware(indicator)
            self.line_separator()
            self.export_search_records(indicator)
            self.line_separator()
            self.export_safebrowsing_records(indicator)
            self.line_separator()
            self.export_dnstwist_records(indicator)

        elif indicator and filtering == 'recent':
            self.export_recent_hosts(indicator)

        elif indicator and filtering == 'threatcrowd':
            self.export_recent_threatcrowd(indicator)

        elif indicator and filtering == 'certificate':
            self.export_recent_certificates(indicator)

        elif indicator and filtering == 'whois':
            self.export_whois(indicator)
            #self.export_recent_whois(indicator)

        elif indicator and filtering == 'historical':
            self.export_historical_hosts(indicator, request)

        elif indicator and filtering == 'malware':
            self.export_malware(indicator)

        elif indicator and filtering == 'search':
            self.export_search_records(indicator)

        elif indicator and filtering == 'safebrowsing':
            self.export_safebrowsing_records(indicator)

        elif indicator and filtering == 'dnstwist':
            self.export_dnstwist_records(indicator)


        return self.response

    def export_dnstwist_records(self, indicator):
        """
        Export recent 'DR' (DNS Twist Record) indicator records to CSV.

        :param indicator: The indicator whose records are to be exported
        :return: This method returns no values
        """
        dnstwist_records = IndicatorRecord.objects.get_dnstwist_record(indicator)
        self._write_records(RecordType.DR, indicator, dnstwist_records)


    def export_safebrowsing_records(self, indicator):
        """
        Export recent 'SB' (SafeBrowsing) indicator records to CSV.

        :param indicator: The indicator whose records are to be exported
        :return: This method returns no values
        """
        safebrowsing_records = IndicatorRecord.objects.safebrowsing_record(indicator)
        self._write_records(RecordType.SB, indicator, safebrowsing_records)

    def export_recent_hosts(self, indicator):
        """
        Export the recent Host Records (IndicatorRecords with record type "HR") for the following types:
        1. DNS hosts records
        2. Miscellaneous host records, excluding PDNS data
        This method is called as part of 'export_recent_hosts.'

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        dnshosts = IndicatorRecord.objects.dns_recent_hosts(indicator)
        self._write_records(RecordType.HR, indicator, dnshosts)
        recenthosts = IndicatorRecord.objects.recent_hosts(indicator)
        self._write_records(RecordType.HR, indicator, recenthosts)

      #  hosts = IndicatorRecord.objects.recent_hosts(indicator)
      #  self._write_records(RecordType.HR, indicator, hosts)


    def export_whois(self, indicator):
        """
        Export recent 'WR' (Whois Record) indicator records to CSV.

        This method is called as part of 'export_recent'

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        self.export_recent_whois(indicator)
        self.line_separator()
        self.export_historical_whois(indicator)


    def export_recent_whois(self, indicator):
        """
        Export recent 'WR' (Whois Record) indicator records to CSV.

        This method is called as part of 'export_recent'

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        whois = IndicatorRecord.objects.recent_whois(indicator)
        self._write_records(RecordType.WR, indicator, [whois])


    def export_recent_threatcrowd(self, indicator):
        """
        Export the most recent 'TR' (ThreatCrowd Record) indicator records to CSV.

        This method is called as part of 'export_recent'

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        tc_info = IndicatorRecord.objects.recent_tc(indicator)
        self._write_records(RecordType.TR, indicator, [tc_info])

    def export_recent_certificates(self, indicator):
        """
        Export recent 'CE' (Censys Record) indicator records in CSV format.

        This method is called as part of 'export_recent'

        :param indicator: The indicator to be exported
        :return: This method returns no values
        """
        latest = IndicatorRecord.objects.recent_cert(indicator)
        self._write_records(RecordType.CE, indicator, [latest])

    def export_historical_hosts(self, indicator, request):
        """
        Export the historical Host Records (IndicatorRecords with record type "HR") for the following types:
        1. All PDNS hosts records
        2. DNS hosts records
        3. Miscellaneous host records


        :param indicator: The indicator whose historical records are to be exported
        :param request: The request being processed
        :return: This method returns no values
        """
        pdshosts = IndicatorRecord.objects.pds_historical_hosts(indicator)
        self._write_records(RecordType.HR, indicator, pdshosts)
        hosts = IndicatorRecord.objects.historical_hosts(indicator, request)
        self._write_records(RecordType.HR, indicator, hosts)
        dnshosts = IndicatorRecord.objects.dns_historical_hosts(indicator)
        self._write_records(RecordType.HR, indicator, dnshosts)


    def export_historical_whois(self, indicator):
        """
        Export historical Who Is Records (IndicatorRecords with record type "WR")

        :param indicator: The indicator whose historical records are to be exported
        :return: This method returns no values
        """
        whois = IndicatorRecord.objects.historical_whois(indicator)
        self._write_records(RecordType.WR, indicator, whois)

        #self.export_historical_hosts(indicator, request)
       # self.line_separator()
       # self.export_historical_whois(indicator)

    def export_malware(self, indicator):
        """
        Export all Malware Records (IndicatorRecords with a record type of "MR") for an indicator to CSV.

        :param indicator: The indicator whose malware records are to be exported
        :return: This method returns no values
        """
        malware = IndicatorRecord.objects.malware_records(indicator)
        self._write_records(RecordType.MR, indicator, malware)

    def export_search_records(self, indicator):
        """
        Export IndicatorRecords with a record type of 'SR' (Search Record).

        This will produce a CSV file containing three columns:
            title: The title of the search result
            url: The URL of the search result
            content: A brief summary of the content of the result

        :param indicator: The indicator whose search results are to be exported
        :return: This method does not return any values
        """
        records = IndicatorRecord.objects.get_search_records(indicator)
        self._write_records(RecordType.SR, indicator, records)

    def _write_records(self, record_type, indicator, records):
        """
        Write a list of records of a given type.

        :param record_type: The record type (which should be one of the values from IndicatoRecord.record_choices)
        :param indicator: The indicator value
        :param records: The records to be written
        :return: This method returns no values
        """
        record_writer = self._get_csv_writer(record_type)
        LOGGER.debug("Writing %d record(s) of type %s (%s) for indicator '%s' using writer type %s",
                     len(records),
                     record_type.name,
                     record_type.title,
                     indicator,
                     type(record_writer).__name__)
        if records is None or 0 == len(records):
            LOGGER.warn("No '%s' records to write for indicator '%s'", record_type, indicator)
        else:
            record_writer.write(indicator, records)

    def _get_csv_writer(self, record_type):
        """
        Get a CsvWriter for the given record type

        :param record_type: The record type.  This should match one of the values defined in
        IndicatorRecord.record_choices.
        :return: An instantiated CsvWriter
        """
        if RecordType.SR is record_type:
            return SearchCsvWriter(self.writer)
        elif RecordType.HR is record_type:
            return HostCsvWriter(self.writer)
        elif RecordType.WR is record_type:
            return WhoIsCsvWriter(self.writer)
        elif RecordType.TR is record_type:
            return ThreatCrowdCsvWriter(self.writer)
        elif RecordType.CE is record_type:
            return CensysCsvWriter(self.writer)
        elif RecordType.SB is record_type:
            return SafeBrowsingCsvWriter(self.writer)
        elif RecordType.MR is record_type:
            return MalwareCsvWriter(self.writer)
        elif RecordType.DR is record_type:
            return DNSTwistCsvWriter(self.writer)
        else:
            msg = "No writer for record type: " + record_type
            LOGGER.error(msg)
            raise RuntimeError(msg)

    def line_separator(self):
        """
        Add a blank line in the CSV output.

        :return: This method does not return any values
        """
        self.writer.writerow([])
