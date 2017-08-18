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

            if (record.info_source =='PDS'):

                for result in record.info['results']:
                    new_record = {
                        'domain': result['domain'],
                        'ip': result['ip'],
                        'firstseen': dateutil.parser.parse(result['firstseen']),
                        'lastseen': dateutil.parser.parse(result['lastseen']),
                        'info_date': record.info_date,
                        'geo_location': geolocate_ip(result['ip'])['country'],
                    }

                    yield [record.info_date,
                           record.info_source,
                           new_record["domain"],
                           new_record["ip"],
                           new_record["geo_location"],
                           new_record["firstseen"],
                           new_record["lastseen"]]

            else:
                new_record = {
                    'domain': record.info["domain"],
                    'ip': record.info["ip"],
                    'geo_location': geolocate_ip(record.info["ip"])['country'],
                    'firstseen':record.info_date,
                    'lastseen':''
                }

                yield [record.info_date,
                       record.info_source,
                       new_record["domain"],
                       new_record["ip"],
                       new_record["geo_location"],
                       new_record["firstseen"],
                       new_record["lastseen"]]
