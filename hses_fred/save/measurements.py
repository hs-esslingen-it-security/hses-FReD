from csv import DictWriter
from hses_fred.objects.simulation import Packet, PathElement
from hses_fred.utils.constants import MEASUREMENT_HEADERS

class MeasurementWriter():

    def __init__(self, file = None, headers = None) -> None:
        self.writer = DictWriter(file, headers if headers != None else MEASUREMENT_HEADERS)

    def toDict(self, run_label : str, path_element : PathElement, packet : Packet):
        return {
            'run_label' : run_label,
            'packet' : str(packet),
            'path_index' : str(path_element.path),
            'timestamp' : path_element.timestamp,
            'current_location' : path_element.location,
            'current_location_ip' : path_element.location_ip,
            'decision' : path_element.decision,
            'introduced_delay' : path_element.introduced_delay,
            'transition_delay' : path_element.transition_delay,
            'reason' : f"'{path_element.reasoning}'",
            'expected_endresult' : f'{packet.expected_decision}',
            'hitcount' : packet.hit_count
        }
    
    def writeHeader(self):
        self.writer.writeheader()

    def write(self, entry):
        self.writer.writerow(entry)