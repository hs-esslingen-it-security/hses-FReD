from csv import DictReader, DictWriter
from hses_fred.objects.simulation import Packet

class PacketWriter():
    PACKET_HEADERS = [
        'index',
        'conditions',
        'hit_count',
        'expected_decision'
    ]

    def __init__(self, file = None, headers = None) -> None:
        self.writer = DictWriter(file, headers if headers != None else PacketWriter.PACKET_HEADERS)

    def writeHeader(self):
        self.writer.writeheader()

    def write(self, entry):
        self.writer.writerow(entry)

    @staticmethod
    def read(file, headers = None, topology = None):
        lines = list(DictReader(file, headers if headers != None else PacketWriter.PACKET_HEADERS))[1:]
        packets = [Packet.from_writer_entry(line) for line in lines if line != None]
        
        if topology == None:
            return packets
        
        return [p.process_condition_values(topology) for p in packets]