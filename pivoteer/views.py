import csv
import json
import datetime
import logging

import core.google

from django.http import HttpResponse
from django.shortcuts import render
from django.views.generic.base import View
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned

from .forms import SubmissionForm
from .models import IndicatorRecord, TaskTracker
from core.utilities import time_jump
from core.lookups import geolocate_ip, resolve_domain
from celery.result import GroupResult
from braces.views import LoginRequiredMixin


LOGGER = logging.getLogger(__name__)


class PivotManager(LoginRequiredMixin, View):

    login_url = "login"
    redirect_unauthenticated_users = True

    template_name = 'pivoteer/pivoteer.html'

    def __init__(self):
        self.template_vars = {'SubmissionForm': SubmissionForm}

    def get(self, request):
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

            self.template_name = "pivoteer/RecentRecords.html"

            # Current hosting records
            host_record = IndicatorRecord.objects.recent_hosts(indicator)

            # We must lookup the country for each IP address for use in the template.
            # We do this outside the task because we don't know the IP addresses until the task completes.
            host_records_complete = []
            for record in host_record:
                info = getattr(record, 'info')
                record.location = geolocate_ip(info['ip'])
                host_records_complete.append(record)

            self.template_vars["current_hosts"] = host_records_complete

            # Current WHOIS record
            whois_record = IndicatorRecord.objects.recent_whois(indicator)
            self.template_vars["current_whois"] = whois_record
            
            # Current ThreatCrowd record
            tc_info = IndicatorRecord.objects.recent_tc(indicator)
            self.template_vars["tc_info"] = tc_info
            
            cert_info = IndicatorRecord.objects.recent_cert(indicator)
            self.template_vars["cert_info"] = cert_info



        elif record_type == "Historical":

            self.template_name = "pivoteer/HistoricalRecords.html"

            # Historical hosting records
            host_records = IndicatorRecord.objects.historical_hosts(indicator, request)

            # We must lookup the country for each IP address for use in the template.
            # We do this outside the task because we don't know the IP addresses until the task completes.
            host_records_complete = []
            for record in host_records:
                info = getattr(record, 'info')
                record.location = geolocate_ip(info['ip'])
                host_records_complete.append(record)

            self.template_vars["hosting_records"] = host_records_complete

            # Historical WHOIS records
            whois_record = IndicatorRecord.objects.historical_whois(indicator)
            self.template_vars["historical_whois"] = whois_record

        elif record_type == "Malware":

            self.template_name = "pivoteer/MalwareRecords.html"

            malware_records = IndicatorRecord.objects.malware_records(indicator)
            self.template_vars["malware_records"] = malware_records

            self.template_vars["origin"] = indicator

        elif record_type == "SafeBrowsing":

            safebrowsing_records = IndicatorRecord.objects.safebrowsing_record(indicator)
            self.template_name = "pivoteer/Google.html"
            self.template_vars["records"] = safebrowsing_records
            self.template_vars["google_url"] = "https://www.google.com/transparencyreport/safebrowsing/diagnostic/?hl=en#url=" + indicator

            self.template_vars["origin"] = indicator

        elif record_type == "Search":
            self.template_name = "pivoteer/SearchRecords.html"
            search_records = IndicatorRecord.objects.get_search_records(indicator)
            self.template_vars["search_records"] = search_records

        return render(request, self.template_name, self.template_vars)


class ExportRecords(LoginRequiredMixin, View):

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
            self.export_recent(indicator)
            self.export_historical(indicator, request)
            self.export_malware(indicator)
            self.export_search_records(indicator)

        elif indicator and filtering == 'recent':
            self.export_recent(indicator)

        elif indicator and filtering == 'historical':
            self.export_historical(indicator, request)

        elif indicator and filtering == 'malware':
            self.export_malware(indicator)

        elif indicator and filtering == 'search':
            self.export_search_records(indicator)

        return self.response

    def export_recent(self, indicator):

        hosts = IndicatorRecord.objects.recent_hosts(indicator)
        whois = IndicatorRecord.objects.recent_whois(indicator)

        if hosts:
            self.line_separator()
            self.writer.writerow(["Date", "Source", "IP", "Domain", "IP Location"])

            for host in hosts:
                entry = [host.info_date, host.info_source,
                         host.info['ip'], host.info['domain'], host.info['geo_location']]

                self.writer.writerow(entry)

        if whois:
            self.line_separator()
            self.writer.writerow(["Lookup Date", "WHOIS Information"])
            self.writer.writerow([whois['info_date'], whois['info']])

    def export_historical(self, indicator, request):

        hosts = IndicatorRecord.objects.historical_hosts(indicator, request)
        whois = IndicatorRecord.objects.historical_whois(indicator)

        if hosts:
            print(hosts)
            self.line_separator()
            self.writer.writerow(["Date", "Source", "IP", "Domain", "IP Location"])

            for host in hosts:
                entry = [host.info_date, host.info_source,
                         host.info['ip'], host.info['domain'], host.info['geo_location']]

                self.writer.writerow(entry)

        if whois:
            self.line_separator()
            self.writer.writerow(['First Seen / Last Seen', 'WHOIS Information'])

            for record in whois:
                self.writer.writerow([str(record['earliest']) + " / " + str(record['latest']), record['info']])

    def export_malware(self, indicator):

        malware = IndicatorRecord.objects.malware_records(indicator)

        if malware:
            self.line_separator()
            self.writer.writerow(["Date", "Source", "Indicator", "MD5", "SHA1", "SHA256", "Report Link"])

            for record in malware:
                entry = [record.info_date, record.info_source, record.info['indicator'], record.info['md5'],
                         record.info['sha1'], record.info['sha256'], record.info['link']]

                self.writer.writerow(entry)

    def export_search_records(self, indicator):
        """
        Export Search Results.

        This will produce a CSV file containing three columns:
            title: The title of the search result
            url: The URL of the search result
            content: A brief summary of the content of the result

        :param indicator: The indicator whose search results are to be exported
        :return: This method does not return any values
        """
        records = IndicatorRecord.objects.get_search_records(indicator)
        LOGGER.debug("Found %d record(s) for export", len(records))
        if records:
            self.line_separator()
            self.writer.writerow(["Title", "URL", "Content"])
            number = 0
            for record in records:
                number += 1
                info = record['info']
                results = info['results']
                LOGGER.debug("Found %d result(s) in record #%d", len(results), number)
                for result in results:
                    LOGGER.debug("Processing result: %s", result)
                    url = result[core.google.SearchResult.URL]
                    title = result[core.google.SearchResult.TITLE]
                    content = result[core.google.SearchResult.CONTENT]
                    entry = [title, url, content]
                    self.writer.writerow(entry)

    def line_separator(self):
        self.writer.writerow([])
