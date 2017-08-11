"""
Classes and functions for writing Host Records.

Host Records are IndicatorRecords with a record type of "HR."
"""
import dateutil.parser

from pivoteer.writer.core import CsvWriter
from core.lookups import geolocate_ip

class HostCsvWriter(CsvWriter):
    """
    A CsvWriter implementation for IndicatorRecord objects with a record type of "HR" (Host Record)
    """

    def __init__(self, writer):
        """
        Create a new CsvWriter for Host Records using the given writer.

        :param writer: The writer
        """
        super(HostCsvWriter, self).__init__(writer)

    def create_header(self):
        return ["Date", "Source", "Domain", "IP", "IP Location", "First Seen", "Last Seen"]

    def create_rows(self, record):

        if record is not None:

          if (record.info_source == 'PDS'):
            for result in record.info['results']:

                new_record = {
                    'domain': result['domain'],
                    'ip': result['ip'],
                    'geo_location': geolocate_ip(result['ip'])['country'],
                    'firstseen': dateutil.parser.parse(result['firstseen']),
                    'lastseen': dateutil.parser.parse(result['lastseen'])
                }

                row = [
                    record.info_date,
                    record.info_source,
                    new_record['domain'],
                    new_record['ip'],
                    new_record['geo_location'],
                    new_record['firstseen'],
                    new_record['lastseen']]

                yield row

          else:

                new_record = {
                    'domain': record.info["domain"],
                    'ip': record.info["ip"],
                    'geo_location': geolocate_ip(record.info["ip"])['country'],
                    'firstseen': record.created,
                    'lastseen': ''
                }

                if ('firstseen' in record.info) and (record.info['firstseen'] != ''):
                    new_record['firstseen'] = dateutil.parser.parse(record.info['firstseen'])
                if ('lastseen' in record.info) and (record.info['lastseen'] != '') and (record.info['lastseen'] != {}):
                    new_record['lastseen'] = dateutil.parser.parse(record.info['lastseen'])

                row = [
                    record.created,
                    record.info_source,
                    new_record['domain'],
                    new_record['ip'],
                    new_record['geo_location'],
                    new_record['firstseen'],
                    new_record['lastseen']]

                yield row

