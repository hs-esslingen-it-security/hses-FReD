from hses_genesis.utils.enum_objects import EPacketDecision
from argparse import ArgumentParser
from reload.measurements import MeasurementReader
from utils.constants import BASE_FOLDER_KEY, RESULT_FOLDER_KEY, DISTRIBUTED_FOLDER_KEY, DECORRELATED_FOLDER_KEY, PACKET_TRACE_FILE
from os import listdir
from os.path import join, isdir
from collections import defaultdict
from utils.display import print_progress_bar

parser = ArgumentParser()
parser.add_argument('-i', '--input_location')
args = parser.parse_args()

if not args.input_location:
    raise Exception('No input location provided!!!')

for directory_name in listdir(args.input_location):
    directory_path = join(args.input_location, directory_name)
    if not isdir(directory_path):
        continue
    for sub_location_name in [BASE_FOLDER_KEY, DECORRELATED_FOLDER_KEY, DISTRIBUTED_FOLDER_KEY]:
        measurement_path = join(directory_path, sub_location_name, RESULT_FOLDER_KEY, PACKET_TRACE_FILE)
        with open(join(measurement_path)) as measurement_file:
            lines = MeasurementReader(measurement_file).lines
            grouped_measurements = defaultdict(list)
            
            for measurement in lines:
                grouped_measurements[measurement['packet']].append(measurement)
            
            for i, (packet, measurements) in enumerate(grouped_measurements.items()):
                print_progress_bar('- check packet', i + 1, len(grouped_measurements))
                if EPacketDecision.ACCEPT.name in packet:
                    if any(measurement['decision'] == EPacketDecision.DROP.name for measurement in measurements):
                        drop_reason = measurement['reason']
                        raise Exception(f'Packet {packet} was dropped but should not have been in {measurement_path} ({drop_reason})!')
                else:
                    if all(measurement['decision'] == EPacketDecision.ACCEPT.name for measurement in measurements):
                        raise Exception(f'Packet {packet} was NOT dropped but should have been in {measurement_path}!')