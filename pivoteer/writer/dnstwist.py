"""
Classes and functions for writing IndicatorRecord objects with record type "DR" (DNSTwist Record)
"""

from pivoteer.writer.core import CsvWriter


class DNSTwistCsvWriter(CsvWriter):
    """
    A CsvWriter implementation for IndicatorRecords with a record type of "DR" (DNSTwist Record)
    """

    def __init__(self, writer):
        """
        Create a new CsvWriter for DNSTwist Records using the given writer.

        :param writer: The writer
        """
        super(DNSTwistCsvWriter, self).__init__(writer)

    def create_title_rows(self, indiator, records):
        yield ["DNSTwist Search Results"]

    def create_header(self):
        return ["Date", "Source", "Indicator", "Detection Type", "Domain Variant", "IP Address"]

    def create_rows(self, record):
        date = record["info_date"]
        source = 'DNSTwist'
        indicator = record["info"]["indicator"]
        info = record["info"]
        results = info["results"]
        for result in results:
            if result["IP"] != "none":
              row = [
                date,
                source,
                result["type"],
                result["domain"],
                result["IP"] ]

              #yield [date, source, indicator, type, domain, IP]
              yield row
