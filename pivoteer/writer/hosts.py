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
            yield [record["info_date"],
                   record["get_info_source_display"],
                   record["info"]["domain"],
                   record["info"]["ip"],
                   record["location"]["country"],
                   record["firstseen"],
                   record["lastseen"]]
