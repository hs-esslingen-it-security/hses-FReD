from csv import DictReader
from hses_fred.utils.constants import MEASUREMENT_HEADERS

class MeasurementReader():
    def __init__(self, file = None, headers = None) -> None:
        self.lines = list(DictReader(file, headers if headers != None else MEASUREMENT_HEADERS))[1:]

    def get_local_conversion_rate(self):
        values = [(float(row['optimized_rule_total']) / float(row['original_rule_total'])) for row in self.lines if float(row['original_rule_total']) > 0]
        return values

    def get_global_conversion_rate(self):
        values = [(float(row['network_rule_total']) / float(row['optimized_rule_total'])) for row in self.lines if float(row['optimized_rule_total']) > 0]
        return values
    
    def get_total_conversion_rate(self):
        values = [(float(row['network_rule_total']) / float(row['original_rule_total'])) for row in self.lines if float(row['original_rule_total']) > 0]
        return values
    
    def get_local_latency_reduction_median(self):
        values = [(float(row['local_timestamp_median']) / float(row['original_timestamp_median'])) for row in self.lines if float(row['original_timestamp_median']) > 0]
        return values
    
    def get_local_latency_reduction_average(self):
        values = [(float(row['local_timestamp_average']) / float(row['original_timestamp_average'])) for row in self.lines if float(row['original_timestamp_average']) > 0]
        return values
    
    def get_global_latency_reduction_median(self):
        values = [(float(row['global_timestamp_median']) / float(row['local_timestamp_median'])) for row in self.lines if float(row['local_timestamp_median']) > 0]
        return values
    
    def get_global_latency_reduction_average(self):
        values = [(float(row['global_timestamp_average']) / float(row['local_timestamp_average'])) for row in self.lines if float(row['local_timestamp_average']) > 0]
        return values
    
    def get_total_latency_reduction_median(self):
        values = [(float(row['global_timestamp_median']) / float(row['original_timestamp_median'])) for row in self.lines if float(row['original_timestamp_median']) > 0]
        return values
    
    def get_total_latency_reduction_average(self):
        values = [(float(row['global_timestamp_average']) / float(row['original_timestamp_average'])) for row in self.lines if float(row['original_timestamp_average']) > 0]
        return values

    def get_values(self, label : str, include_malicious = False):
        values = [row[label] for row in self.lines if row[label] != label and (include_malicious or row['run_label'] != 'malicious')]
        return values