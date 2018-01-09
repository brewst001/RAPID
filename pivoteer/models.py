import pickle
import hashlib
import datetime
import logging
import dateutil.parser
from django.db import models
from django.db.models import Q
from django.db.models import Max, Min
from django_pgjson.fields import JsonField
from core.utilities import check_domain_valid, get_base_domain
from pivoteer.records import RecordType, RecordSource
from core.lookups import geolocate_ip

LOGGER = logging.getLogger(__name__)

class IndicatorManager(models.Manager):

    def host_records(self, indicator):
        record_type = RecordType.HR

        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(indicator=indicator))
        return records

    def recent_cert(self, indicator):
        """Retrieve the most recent censys.io certificate result for the provided indicator
        # Updated by LNguyen
        # Date: 05May2017
        # Description: Former query was not correctly handling unicode characters in the info field so had to update where condition to use wildcard contains

            Args:
                indicator (str): The indicator to search for
            
            Returns (IndicatorRecord): The IndicatorRecord for the most recently saved
                result for the provided indicator or an empty query set if no record was found.
        """
        
        # TODO: Why are we returning empty query sets hiversus None when there are no results?
        
        record_type = RecordType.CE
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(info_date__gte=time_frame),
                                             Q(indicator=indicator)).values('info', 'info_date')

        # records = self.get_queryset().filter(Q(record_type=record_type.name),
        #                                      Q(info_date__gte=time_frame),
        #                                      Q(info__at_indicator__exact=indicator)).values('info', 'info_date')
        if records:
            return records.latest('info_date')
        LOGGER.info("Failed to retrieve certificate data for indicator %s" % indicator)
        return records

    def recent_tc(self, indicator):
        """Retrieve the most recent ThreatCrowd record for the provided indicator
        # Updated by LNguyen
        # Date: 05May2017
        # Description: Former query was not correctly handling unicode characters in the info field so had to update where condition to use wildcard contains

            Args:
                indicator (str): The indicator to search for

            Returns (IndicatorRecord): The indicator record for the most recently saved
                result for the provided indicator.
        """
        record_type = RecordType.TR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(info_date__gte=time_frame),
                                             Q(indicator=indicator)).values('info', 'info_date')
        # records = self.get_queryset().filter(Q(record_type=record_type.name),
        #                                      Q(info_date__gte=time_frame),
        #                                      Q(info__at_domain__exact=indicator) |
        #                                      Q(info__at_ip__exact=indicator)).values('info', 'info_date')


        if records:
            return records.latest('info_date')
        LOGGER.info("Failed to retrieve ThreatCrowd data for indicator %s" % indicator)
        return records


    def dns_recent_hosts(self, indicator):
        # Updated by LNguyen
        # Date: 04Jan2018
        # Description: Query to get recent DNS data where info_date is within 24 hrs
        record_type = RecordType.HR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(Q(info_source=RecordSource.DNS.name),
                                                 Q(record_type=record_type.name),
                                                 Q(info_date__gte=time_frame),
                                                 Q(indicator=indicator)).values('info', 'info_date', 'info_source')

        return records


    def recent_hosts(self, indicator):
        # Updated by LNguyen
        # Date: 26April2017
        # Description: Former query was not correctly handling unicode characters in the info field so had to update where condition to use wildcard contains
        # Date: 4Jan2018
        # Description: Query to get miscellaneous recent host data where first seen and last seen dates are within 24 hrs
        record_type = RecordType.HR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(~Q(info_source=RecordSource.PDS.name),
                                             ~Q(info_source=RecordSource.DNS.name),
                                             Q(record_type=record_type.name),
                                             Q(indicator=indicator),
                                             Q(info__at_firstseen__gte=time_frame) |
                                             Q(info__at_lastseen__gte=time_frame)
                                             ).values('info', 'info_source')

        # records = self.get_queryset().filter(Q(record_type=record_type.name),
        #                                      Q(info_date__gte=time_frame),
        #                                      Q(info__at_domain__endswith=indicator) |
        #                                      Q(info__at_ip__endswith=indicator))

        return records

    def dns_historical_hosts(self, indicator):
        # Updated by LNguyen
        # Date: 26April2017
        # Description: Former query was not correctly handling unicode characters in the info field so had to update where condition to use wildcard contains
        # Date: 4Jan2018
        # Description: Query to get historical DNS data where info_date is beyond 24 hrs
        record_type = RecordType.HR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(Q(info_source=RecordSource.DNS.name),
                                                 Q(record_type=record_type.name),
                                                 Q(info_date__lt=time_frame),
                                                 Q(indicator=indicator)).values('info', 'info_date', 'info_source')
        #temp#
        if (records.count() == 0):
            self.get_queryset().filter(Q(info_source=RecordSource.DNS.name),
                                       Q(record_type=record_type.name),
                                       Q(info_date__lt=time_frame),
                                       Q(indicator__isnull=True),
                                       Q(info__contains=indicator)).update(indicator=indicator)

            records = self.get_queryset().filter(Q(info_source=RecordSource.DNS.name),
                                                 Q(record_type=record_type.name),
                                                 Q(info_date__lt=time_frame),
                                                 Q(indicator=indicator)).values('info', 'info_date', 'info_source')

        return records

    def historical_hosts(self, indicator, request):
        # Updated by LNguyen
        # Date: 26April2017
        # Description: Former query was not correctly handling unicode characters in the info field so had to update where condition to use wildcard contains
        # Date: 1Aug2017
        # Description: Update to include PDNS Data into Historical dataset
        # Date: 4Jan2018
        # Description: Query to get miscellaneous host data where first seen and last seen dates are beyond 24 hrs
        record_type = RecordType.HR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        if request.user.is_staff:
            records = self.get_queryset().filter(~Q(info_source=RecordSource.PDS.name),
                                                 ~Q(info_source=RecordSource.DNS.name),
                                                 Q(record_type=record_type.name),
                                                 Q(indicator=indicator),
                                                 Q(info__at_firstseen__lt=time_frame),
                                                 Q(info__at_lastseen__lt=time_frame)
                                                 ).values('info', 'info_source')
        else:
            records = self.get_queryset().filter(~Q(info_source=RecordSource.PDS.name),
                                                 ~Q(info_source=RecordSource.IID.name),
                                                 ~Q(info_source=RecordSource.DNS.name),
                                                 Q(record_type=record_type.name),
                                                 Q(indicator=indicator),
                                                 Q(info__at_firstseen__lt=time_frame),
                                                 Q(info__at_lastseen__lt=time_frame)
                                                 ).values('info', 'info_source')

        if (records.count() == 0):
            self.get_queryset().filter(~Q(info_source=RecordSource.PDS.name),
                                       ~Q(info_source=RecordSource.DNS.name),
                                       Q(record_type=record_type.name),
                                       Q(info__at_firstseen__lt=time_frame),
                                       Q(info__at_lastseen__lt=time_frame),
                                       Q(indicator__isnull=True),
                                       Q(info__contains=indicator)).update(indicator=indicator)

            records = self.get_queryset().filter(~Q(info_source=RecordSource.PDS.name),
                                                 ~Q(info_source=RecordSource.DNS.name),
                                                 Q(record_type=record_type.name),
                                                 Q(indicator=indicator),
                                                 Q(info__at_firstseen__lt=time_frame),
                                                 Q(info__at_lastseen__lt=time_frame)
                                                 ).values('info', 'info_source')

        return records


    def pds_historical_hosts(self, indicator):
        # Updated by LNguyen
        # Date: 1Aug2017
        # Description: Update to get all PDNS historical data
        record_type = RecordType.HR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        records = self.get_queryset().filter(Q(info_source=RecordSource.PDS.name),
                                                 Q(record_type=record_type.name),
                                                 Q(indicator=indicator)).values('info', 'info_source')

        if (records.count() == 0):
            self.get_queryset().filter(Q(info_source=RecordSource.PDS.name),
                                                 Q(record_type=record_type.name),
                                                 Q(indicator__isnull=True),
                                                 Q(info__contains=indicator)).update(indicator=indicator)

            records = self.get_queryset().filter(Q(info_source=RecordSource.PDS.name),
                                             Q(record_type=record_type.name),
                                             Q(indicator=indicator)).values('info', 'info_source')

        return records.latest('info_date')
        #return records


    def malware_records(self, indicator):
        # Updated by LNguyen
        # Date: 12Mayl2017
        # Description: Update to store dataset in array variable because dates were not being handled as datetime and date sorting was not working
        record_type = RecordType.MR

        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(indicator=indicator))


        records_complete = []
        for record in records:
            new_record = {
                'info': record.info,
                'info_date': record.info_date,
                'info_hash':record.info_hash,
                'get_info_source_display':record.get_info_source_display()
            }
            records_complete.append(new_record)

        return records

    def recent_malware(self, indicator):
        record_type = RecordType.MR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(days=-30)

        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(info_date__gte=time_frame),
                                             Q(indicator=indicator))

        return records

    def historical_malware(self, indicator):
        record_type = RecordType.MR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(days=-30)

        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(info_date__lt=time_frame),
                                             Q(indicator=indicator))

        return records

    def whois_records(self, indicator):
        record_type = RecordType.WR

        if check_domain_valid(indicator):
            indicator = get_base_domain(indicator)

        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(indicator=indicator)).values('info', 'info_date')

        return records

    def recent_whois(self, indicator):
        # Updated by LNguyen
        # Date: 26April2017
        # Description: Former query was not correctly handling unicode characters in the info field so had to update where condition to use wildcard contains

        record_type = RecordType.WR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        if check_domain_valid(indicator):
            indicator = get_base_domain(indicator)

        record = self.get_queryset().filter(Q(record_type=record_type.name),
                                            Q(info_date__gte=time_frame),
                                            Q(indicator=indicator)).values('info', 'info_date')
        # record = self.get_queryset().filter(Q(record_type=record_type.name),
        #                                     Q(info_date__gte=time_frame),
        #                                     Q(info__at_query__iendswith=indicator) |
        #                                     Q(info__at_domain_name__iendswith=indicator)).values('info', 'info_date')


        if record:
            return record.latest('info_date')

        return record

    def historical_whois(self, indicator):
        # Updated by LNguyen
        # Date: 26April2017
        # Description: Former query was not correctly handling unicode characters in the info field so had to update where condition to use wildcard contains
        # Updated by LNguyen
        # Date: 12Mayl2017
        # Description: Update to store dataset in array variable because dates were not being handled as datetime and date sorting was not working

        record_type = RecordType.WR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)

        if check_domain_valid(indicator):
            indicator = get_base_domain(indicator)

        raw_records = self.get_queryset().filter(Q(record_type=record_type.name),
                                                 Q(indicator=indicator)).values('info_hash', 'info_date', 'info')

        # raw_records = self.get_queryset().filter(Q(record_type=record_type.name),
        #                                          Q(info_date__lt=time_frame),
        #                                          Q(info__at_query__endswith=indicator) |
        #                                          Q(info__at_domain_name__endswith=indicator)).values('info_hash',
        #                                                                                              'info_date')

        unique_records = []

        if (raw_records.count() > 0):
            latest = raw_records.latest('info_date')['info_date']
            earliest = raw_records.earliest('info_date')['info_date']
            span = str(earliest) + " / " + str(latest)

            for record in raw_records:
                new_record = {'latest': latest,
                              'earliest': earliest,
                              'info_date': span,
                              'info': record['info']}
                unique_records.append(new_record)

      #  annotated_records = raw_records.annotate(latest=Max('info_date')).annotate(earliest=Min('info_date'))

       # for record in annotated_records:
       #     hash_value = record['info_hash']

       #     if hash_value not in tracking:
        #        record_info = self.get_queryset().filter(info_hash=hash_value).values('info')[0]['info']
        #        span = str(record['earliest']) + " / " + str(record['latest'])
        #        new_record = {'latest': record['latest'],
        #                      'earliest': record['earliest'],
        #                      'info_date': span,
        #                      'info': record_info}
         #       unique_records.append(new_record)
         #       tracking.append(hash_value)

        return unique_records


    def safebrowsing_record(self, indicator):
        record_type = RecordType.SB
        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(indicator=indicator))
        return records

    def get_search_records(self, indicator):
        """
        Retrieve any search records from within the last 24 hours for an indicator from the database.

        :param indicator: The indicator value
        :return:  The search records for the indicator
        """
        record_type = RecordType.SR
        time_frame = datetime.datetime.utcnow() + datetime.timedelta(hours=-24)
        value = indicator
        if check_domain_valid(indicator):
            value = get_base_domain(indicator)
        LOGGER.debug("Using search value: %s", value)
        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(info_date__gte=time_frame),
                                             Q(indicator=value)).values('info', 'info_date')
        if LOGGER.isEnabledFor(logging.INFO):
            rank = 0
            msg = "Found %d search record(s):" % len(records)
            for record in records:
                info = record['info']
                results = info['results']
                for result in results:
                    rank += 1
                    url = result['url']
                    msg += "\n\t%d - %s" % (rank, url)
            LOGGER.info(msg)
        return records


    def get_dnstwist_record(self, indicator):
        """
        Retrieve DNSTwist records for an indicator from the database.

        :param indicator: The indicator value
        :return:  The DNSTwist records for the indicator
        """

        record_type = RecordType.DR

        records = self.get_queryset().filter(Q(record_type=record_type.name),
                                             Q(indicator=indicator)).values('info', 'info_date')

        return records


class IndicatorRecord(models.Model):

    record_choices = tuple((rt.name, rt.title) for rt in RecordType)
    source_choices = tuple((rs.name, rs.title) for rs in RecordSource)

    record_type = models.CharField(max_length=2, choices=record_choices)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    modified = models.DateTimeField(auto_now=True)

    info = JsonField()
    info_source = models.CharField(max_length=3, choices=source_choices)
    info_hash = models.CharField(max_length=40)
    info_date = models.DateTimeField()
    indicator = models.CharField(max_length=253, blank=True, null=True)

    objects = IndicatorManager()

    class Meta:
        unique_together = (("indicator", "info_hash", "info_source", "info_date"),)

    def generate_hash(self):
        info_pickle = pickle.dumps(self.info)
        info_sha1 = hashlib.sha1(info_pickle).hexdigest()
        return info_sha1

    def save(self, *args, **kwargs):

        if not self.info_hash:
            self.info_hash = self.generate_hash()

        super(IndicatorRecord, self).save(*args, **kwargs)


class TaskTracker(models.Model):
    """ Tracker for identifying and resuming tasks """
    keyword = models.CharField(max_length=253)
    group_id = models.CharField(max_length=50)
    type = models.CharField(max_length=50)
    date = models.DateTimeField()


class ExternalSessions(models.Model):
    """ External cookie sessions for scrapers """

    # Note: Yes, this syntax is mildly awkward, but it allows for very easy addition of additional sources in the list
    # at the end of the line
    service_choices = tuple((rs.name, rs.title) for rs in RecordSource if rs in [RecordSource.IID])

    service = models.CharField(max_length=3, choices=service_choices)
    cookie = JsonField()

