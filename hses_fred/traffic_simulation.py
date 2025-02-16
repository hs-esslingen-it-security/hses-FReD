from argparse import ArgumentParser
from save.locations import generate_csv_file_name
from os.path import join
import hses_genesis.reload.topology as topology
from save.measurements import MeasurementWriter
from save.packets import PacketWriter
from simulate.traffic import send_packet
from utils.constants import GRAPH_FILE, PACKET_FILE, BASE_FOLDER_KEY, DECORRELATED_FOLDER_KEY, DISTRIBUTED_FOLDER_KEY
from os import listdir
from os.path import isdir, join
from utils.display import print_progress_bar

parser = ArgumentParser()
parser.add_argument('-i', '--input_location')
args = parser.parse_args()

if not args.input_location:
    raise Exception('No input location provided!!!')

run_directories = list(filter(lambda x: isdir(join(args.input_location, x)), listdir(args.input_location)))
for j, run_dir in enumerate(run_directories):

    for sub_location in [BASE_FOLDER_KEY, DECORRELATED_FOLDER_KEY, DISTRIBUTED_FOLDER_KEY]:
        network = topology.from_file(join(args.input_location, run_dir, sub_location, GRAPH_FILE))
        packets = PacketWriter.read(open(join(args.input_location, run_dir, PACKET_FILE), 'r'), topology=network)
        with open(generate_csv_file_name(join(args.input_location, run_dir, sub_location), 'packet_traces'), 'w') as trace_file:
            writer = MeasurementWriter(trace_file)
            writer.writeHeader()

            for i, packet in enumerate(packets):
                print_progress_bar('- sending packets', i + 1, len(run_directories))
                paths = send_packet(network, packet)
                [writer.write(writer.toDict('original', trace_entry, packet.process_condition_values(network, False))) for path in paths for trace_entry in path]