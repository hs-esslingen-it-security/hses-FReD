from argparse import ArgumentParser
from ipaddress import ip_network
from os import getcwd, listdir
from os.path import isdir, join, exists, dirname
from random import randint
from shutil import copyfile
from hses_genesis.utils.constants import GRAPH_FOLDER, PACKET_FOLDER, FULL_RANGES
from hses_genesis.utils.enum_objects import EDeviceRole, EPacketDecision, EParameterType
from networkx import Graph
from hses_fred.objects.simulation import Packet
from hses_fred.save.locations import generate_csv_file_name, generate_output_location, generate_run_location
from hses_fred.save.measurements import MeasurementWriter
from hses_fred.save.packets import PacketWriter
from hses_fred.simulate.traffic import simulate_traffic, validate_traffic
from hses_fred.utils.constants import BASE_FOLDER_KEY, DEFAULT_ACTION_KEY, GRAPH_FILE, IPTABLES_FOLDER_KEY, PACKET_FILE, ROLE_KEY, RULESET_FOLDER_KEY, RULESET_KEY, SUBNET_KEY, DISTRIBUTED_FOLDER_KEY
import hses_genesis.reload.topology as topology
import hses_genesis.reload.packets as packets
from hses_genesis.save.rulesets import to_save_file
from hses_fred.utils.functions import get_runtime_measurements, measure_runtime, reset_runtime_measurements, rule_to_str
from hses_fred.prioritize.container import get_paths_to_cover

@measure_runtime
def whitelisting_distribution(G : Graph):
    g_copy = G.copy()
    for node, data in g_copy.nodes(data=True):
        if data[ROLE_KEY] == EDeviceRole.SWITCH:
            ip_range = list(ip_network(data[SUBNET_KEY], False).hosts())
            subnet_range = int(ip_range[0]),int(ip_range[-1])
            g_copy.nodes[node][RULESET_KEY] = [('INPUT', (subnet_range, subnet_range, FULL_RANGES[EParameterType.PROTOCOL], FULL_RANGES[EParameterType.NUMBER], FULL_RANGES[EParameterType.NUMBER]), EPacketDecision.ACCEPT)]
            g_copy.nodes[node][DEFAULT_ACTION_KEY] = EPacketDecision.DROP
        
        original_ruleset = data.get(RULESET_KEY, [])
        if data[ROLE_KEY] != EDeviceRole.ROUTER or not original_ruleset:
            continue

        g_copy.nodes[node][DEFAULT_ACTION_KEY] = EPacketDecision.ACCEPT

        for rule in original_ruleset:
            paths = get_paths_to_cover(G, node, rule)
            for path in paths:
                for container in path:
                    container_ruleset = g_copy.nodes[container].get(RULESET_KEY, [])
                    if g_copy.nodes[container][ROLE_KEY] != EDeviceRole.SWITCH or rule in container_ruleset:
                        continue
                    
                    g_copy.nodes[container][RULESET_KEY] = container_ruleset + [rule]
        g_copy.nodes[node][RULESET_KEY] = []
    return g_copy

parser = ArgumentParser()
parser.add_argument('-i', '--input_location', default=join(dirname(dirname(__file__)), 'resources', 'default'))
parser.add_argument('-o', '--output_location', default=join(getcwd(), 'output'))
parser.add_argument('-l', '--label', default='default_config')
parser.add_argument('-f', '--force_all_runs', action='store_true')
args = parser.parse_args()


input_location = args.input_location
output_location = args.output_location
label = args.label
force_all_runs = args.force_all_runs

output_root = generate_output_location(join(output_location, 'whitelisted'), label)
print(f'Output location: {output_root}')
copyfile(join(input_location, 'config.json'), join(output_root, 'config.json'))
copyfile(join(input_location, '.genesistag'), join(output_root, '.genesistag'))

run_ids = [run_id for run_id in listdir(input_location) if isdir(join(input_location, run_id)) and not (exists(join(input_location, run_id, '.fred-footprint')) and not force_all_runs)]

for run_id in run_ids:
    run_output_location = generate_run_location(output_root, run_id)
    graph_location = join(input_location, run_id, GRAPH_FOLDER, GRAPH_FILE)
    
    copyfile(graph_location, join(run_output_location, BASE_FOLDER_KEY, GRAPH_FOLDER, GRAPH_FILE))
    network = topology.from_file(graph_location)
    for node, data in network.nodes(data=True):
        if data[ROLE_KEY] != EDeviceRole.ROUTER:
            continue
        ruleset = data.get(RULESET_KEY, [])
        if ruleset:
            to_save_file(join(run_output_location, BASE_FOLDER_KEY, RULESET_FOLDER_KEY, IPTABLES_FOLDER_KEY), node, [rule_to_str(r) for r in network.nodes[node][RULESET_KEY]])
        
    with open(join(run_output_location, PACKET_FILE), 'w') as packet_file:
        writer = PacketWriter(packet_file)
        writer.writeHeader()

        genesis_packets = packets.from_csv(join(input_location, run_id, PACKET_FOLDER, PACKET_FILE))
        processed_packets = [Packet.from_genesis_entry(packet, i, randint(0,500)) for i, packet in enumerate(genesis_packets)]
        for packet in processed_packets:
            writer.write(packet.to_writer_dict())

    measurement_path = generate_csv_file_name(join(run_output_location, BASE_FOLDER_KEY), 'packet_traces')
    measurements = simulate_traffic(network, processed_packets, measurement_path)
    validate_traffic(network, measurements, measurement_path)

    network = whitelisting_distribution(network)

    measurement_path = generate_csv_file_name(join(run_output_location, DISTRIBUTED_FOLDER_KEY), 'packet_traces')
    measurements = simulate_traffic(network, processed_packets, measurement_path)
    validate_traffic(network, measurements, measurement_path)
    
    with open(join(run_output_location, 'runtime_measurements.csv'), 'w') as runtime_measurement_file:
        writer = MeasurementWriter(runtime_measurement_file, ['method', 'runtime'])
        writer.writeHeader()
        for method, runtime in get_runtime_measurements().items():
            writer.write({
                'method' : method,
                'runtime' : runtime
            })

    check_location = join(input_location, run_id, '.fred-footprint')
    with open(check_location, 'w') as footprint_file:
        footprint_file.write(run_output_location)
    reset_runtime_measurements()

    print(f'INFO: run informations saved to {output_root}')