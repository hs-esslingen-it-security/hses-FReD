from ipaddress import ip_network
import hses_genesis.reload.topology as topology
from random import Random, randint
from networkx import write_graphml
from hses_fred.distribute.ruleset import compress_ruleset, presorting_ruleset_distribution
from hses_fred.history.decorrelation import prepare_nodes
from hses_fred.prioritize.container import get_paths_to_cover
from hses_fred.process.topology import get_stripped_network, prepare_network_export
from hses_fred.save.warnings import to_csv as save_leftovers
from hses_fred.simulate.traffic import rule_packet_match, simulate_traffic, validate_traffic
from hses_fred.save.measurements import MeasurementWriter
from hses_fred.save.locations import generate_csv_file_name, generate_output_location, generate_run_location
from hses_fred.save.packets import PacketWriter
from hses_fred.utils.functions import generate_full_range_rule, measure_runtime, rule_to_str, get_runtime_measurements, reset_runtime_measurements
from hses_fred.objects.simulation import Packet
from hses_fred.utils.display import print_progress_bar
from hses_fred.utils.constants import BASE_FOLDER_KEY, RESULT_FOLDER_KEY, LOG_FOLDER_KEY, DEFAULT_ACTION_KEY, DISTRIBUTED_FOLDER_KEY, IPTABLES_FOLDER_KEY, MAX_ACL_SIZE, PACKET_FILE, ROLE_KEY, RULESET_FOLDER_KEY, RULESET_KEY, DECORRELATED_FOLDER_KEY, GRAPH_FILE, SUBNET_KEY, WHITELISTED_FOLDER_KEY
from hses_fred.decorrelate.ruleset import inplace as inplace_ruleset_decorrelation
from argparse import ArgumentParser
from hses_genesis.utils.constants import PACKET_FOLDER, GRAPH_FOLDER, FULL_RANGES
from hses_genesis.utils.enum_objects import EDeviceRole, EPacketDecision, EState, EParameterType
from hses_genesis.save.topology import to_graphml
from hses_genesis.save.rulesets import to_save_file
from hses_genesis.generation.network_configuration import NetworkConfigurationGenerator
from hses_genesis.reload.packets import from_csv as reload_packets
from shutil import copyfile
from os.path import join, dirname, isdir, exists
from os import listdir, getcwd

def __calculate_priorities__(G, rule, packet_traffic : list[Packet]):
    return sum([packet.hit_count for packet in packet_traffic if rule_packet_match(rule, packet, G)])

def sort_ruleset(G, ruleset : list[tuple], packet_traffic : list[Packet]):
    priority_map = {}
    for rule in ruleset:
        priority_map[rule] = __calculate_priorities__(G, rule, packet_traffic)
    ruleset.sort(key=lambda x: priority_map[x] if x in priority_map.keys() else 0, reverse=True)
    return ruleset

@measure_runtime
def perform_full_network_decorrelation(G, routers, decorrelation_trees, run_output_location, debuggung = True):
    for router in routers:
        if RULESET_KEY not in G.nodes[router] or len(G.nodes[router][RULESET_KEY]) == 0:
            G.nodes[router][RULESET_KEY] = [generate_full_range_rule(action=G.nodes[router][DEFAULT_ACTION_KEY])]
        else:
            G.nodes[router][RULESET_KEY], decorrelation_trees[router] = inplace_ruleset_decorrelation(G.nodes[router][RULESET_KEY], default_action=G.nodes[router][DEFAULT_ACTION_KEY])
            if debuggung:
                write_graphml(prepare_nodes(decorrelation_trees[router]), join(run_output_location, DECORRELATED_FOLDER_KEY, RULESET_FOLDER_KEY, LOG_FOLDER_KEY, f'{router}-decorrelation-history.graphml'))
    return G, decorrelation_trees

@measure_runtime
def perform_network_wide_local_optimization(G, routers, run_output_location, to_zimpl : bool = False, debugging = True):
    for r_i, router in enumerate(routers):
        if RULESET_KEY not in G.nodes[router].keys():
            continue
        print_progress_bar(f'- router optimization', r_i + 1, len(routers))

        decorrelated_ruleset = G.nodes[router][RULESET_KEY]
        rulesets_location = join(run_output_location, DECORRELATED_FOLDER_KEY, RULESET_FOLDER_KEY, IPTABLES_FOLDER_KEY)

        to_save_file(rulesets_location, f'{router}.1_decorrelated', [rule_to_str(r) for r in decorrelated_ruleset])
        
        decorrelated_ruleset = [rule for rule in decorrelated_ruleset if rule[2] == EPacketDecision.DROP]
        G.nodes[router][DEFAULT_ACTION_KEY] = EPacketDecision.ACCEPT
        to_save_file(rulesets_location, f'{router}.2_blacklisted', [rule_to_str(r) for r in decorrelated_ruleset])
        
        decorrelated_ruleset, joining_tree = compress_ruleset(decorrelated_ruleset)
        to_save_file(rulesets_location, f'{router}.3_joined', [rule_to_str(r) for r in decorrelated_ruleset])
        
        decorrelated_ruleset = sort_ruleset(G, decorrelated_ruleset, [packet.process_condition_values(G, False) for packet in packets])
        to_save_file(rulesets_location, f'{router}.4_sorted', [rule_to_str(r) for r in decorrelated_ruleset])
        
        G.nodes[router][RULESET_KEY] = decorrelated_ruleset
        if debugging:
            write_graphml(prepare_nodes(joining_tree), join(run_output_location, DECORRELATED_FOLDER_KEY, RULESET_FOLDER_KEY, LOG_FOLDER_KEY, f'{router}-join-history.graphml'))

    to_graphml(prepare_network_export(G), join(run_output_location, DECORRELATED_FOLDER_KEY, GRAPH_FOLDER))
    measurement_path = generate_csv_file_name(join(run_output_location, DECORRELATED_FOLDER_KEY), 'packet_traces')
    measurements = simulate_traffic(G, packets, measurement_path)
    validate_traffic(G, measurements, measurement_path)
    return G

@measure_runtime
def perform_accept_only_distribution(G, run_output_location):
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
            if rule[2] == EPacketDecision.DROP:
                continue
            paths = get_paths_to_cover(G, node, rule)
            for path in paths:
                for container in path:
                    container_ruleset = g_copy.nodes[container].get(RULESET_KEY, [])
                    if g_copy.nodes[container][ROLE_KEY] != EDeviceRole.SWITCH or rule in container_ruleset:
                        continue
                    
                    g_copy.nodes[container][RULESET_KEY] = container_ruleset + [rule]
        g_copy.nodes[node][RULESET_KEY] = []

    for node, data in g_copy.nodes(data=True):
        ruleset = data.get(RULESET_KEY, [])
        if ruleset:
            to_save_file(join(run_output_location, WHITELISTED_FOLDER_KEY, RULESET_FOLDER_KEY, IPTABLES_FOLDER_KEY), node, [rule_to_str(r) for r in ruleset], default_action=data[DEFAULT_ACTION_KEY])

    overfull_acls = [(node, len(data.get(RULESET_KEY, []))) for node, data in g_copy.nodes(data=True) if data[ROLE_KEY] == EDeviceRole.SWITCH and len(data.get(RULESET_KEY, [])) > MAX_ACL_SIZE]
    to_graphml(prepare_network_export(g_copy), join(run_output_location, WHITELISTED_FOLDER_KEY, GRAPH_FOLDER))
    
    if overfull_acls:
        with open(join(run_output_location,  join(run_output_location, WHITELISTED_FOLDER_KEY, '.undistributed')), 'w') as file:
            file.write(f'Undistributed due to:\n')
            for target_container, acl_length in overfull_acls:
                file.write(f'Invalid run: ACL of {target_container} violates maximal ACL rule count ({acl_length}/{MAX_ACL_SIZE}) after distribution.')
    else:
        measurement_path = generate_csv_file_name(join(run_output_location, WHITELISTED_FOLDER_KEY), 'packet_traces')
        measurements = simulate_traffic(g_copy, packets, measurement_path)
        validate_traffic(g_copy, measurements, measurement_path)

    return g_copy

@measure_runtime
def perform_presorted_global_optimization(G, routers, run_output_location, decorrelation_trees = None, debugging = True):
    G, leftovers, distribution_tree, decorrelation_trees, transition_trees, overfull_acls = presorting_ruleset_distribution(G, routers)
    save_leftovers(leftovers, join(run_output_location, DISTRIBUTED_FOLDER_KEY, RESULT_FOLDER_KEY))

    for source, target, data in distribution_tree.edges(data=True):
        if not 'rules' in data.keys():
            continue
        distribution_tree.edges[(source, target)]['rules'] = '\n'.join(data['rules'])

    if debugging:
        debug_location = join(run_output_location, DISTRIBUTED_FOLDER_KEY, RULESET_FOLDER_KEY, LOG_FOLDER_KEY)
        write_graphml(prepare_nodes(distribution_tree), join(debug_location, f'distribution-history.graphml'))

        for container, decorrelation_tree in decorrelation_trees.items():
            write_graphml(prepare_nodes(decorrelation_tree), join(debug_location, f'decorrelation-history-{container.lower()}.graphml'))

        for transition_name, transition_tree in transition_trees.items():
            write_graphml(prepare_nodes(transition_tree), join(debug_location, f'transitional-decorrelation-history-{transition_name.lower()}.graphml'))

    for rule_container in G.nodes:
        if RULESET_KEY in G.nodes[rule_container] and len(G.nodes[rule_container][RULESET_KEY]) > 0:
            to_save_file(join(run_output_location, DISTRIBUTED_FOLDER_KEY, RULESET_FOLDER_KEY, IPTABLES_FOLDER_KEY), rule_container, [rule_to_str(r) for r in G.nodes[rule_container][RULESET_KEY]], default_action=EPacketDecision.ACCEPT)
    
    to_graphml(prepare_network_export(G), join(run_output_location, DISTRIBUTED_FOLDER_KEY, GRAPH_FOLDER))
    
    if overfull_acls:
        with open(join(run_output_location,  join(run_output_location, DISTRIBUTED_FOLDER_KEY, '.undistributed')), 'w') as file:
            file.write(f'Undistributed due to:\n')
            for target_container, acl_length in overfull_acls:
                file.write(f'Invalid run: ACL of {target_container} violates maximal ACL rule count ({acl_length}/{MAX_ACL_SIZE}) after distribution.')
    else:
        measurement_path = generate_csv_file_name(join(run_output_location, DISTRIBUTED_FOLDER_KEY), 'packet_traces')
        measurements = simulate_traffic(G, packets, measurement_path)
        validate_traffic(G, measurements, measurement_path)
    return G

parser = ArgumentParser()
parser.add_argument('-i', '--input_location', default=join(dirname(dirname(__file__)), 'resources', 'default'))
parser.add_argument('-o', '--output_location', default=join(getcwd(), 'output'))
parser.add_argument('-l', '--label', default='default_config')
parser.add_argument('-r', '--ripple', action='store_true')
parser.add_argument('-f', '--force_all_runs', action='store_true')
parser.add_argument('-s', '--seed', default=randint(0,1000))
parser.add_argument('-zpl', '--to_zimpl_parsable', action='store_true')
args = parser.parse_args()

if not args.input_location:
    raise Exception('No input location provided!')

print('Given inputs:', list(vars(args).items()))

run_locations = [run_id for run_id in listdir(args.input_location) if isdir(join(args.input_location, run_id)) and not (exists(join(args.input_location, run_id, '.fred-footprint')) and not args.force_all_runs)]

if len(run_locations) == 0:
    print('No run folders found. Consider providing the -f flag, if you already provided the same folder as input in a previous run.')

else:

    output_root = generate_output_location(args.output_location, args.label)
    print(f'Output location: {output_root}')
    copyfile(join(args.input_location, 'config.json'), join(output_root, 'config.json'))
    copyfile(join(args.input_location, '.genesistag'), join(output_root, '.genesistag'))
    random = Random(args.seed)

    for run_id in run_locations:
        run_output_location = generate_run_location(output_root, run_id, to_zimpl=args.to_zimpl_parsable)
        graph_location = join(args.input_location, run_id, GRAPH_FOLDER, GRAPH_FILE)
        print('Applying distribution to:', graph_location)
        print(f'Run output location: {run_output_location}')

        # COPY BASE CASE
        copyfile(graph_location, join(run_output_location, BASE_FOLDER_KEY, GRAPH_FOLDER, GRAPH_FILE))

        # READ GeNESIS FILES.
        network = topology.from_file(graph_location)
        to_graphml(prepare_network_export(get_stripped_network(network)), join(run_output_location, BASE_FOLDER_KEY, GRAPH_FOLDER), file_name='rule_stripped_graph.graphml')

        routers = [n for n in network.nodes() if EDeviceRole.from_device_id(n) == EDeviceRole.ROUTER]
        for router in network.nodes:
            if RULESET_KEY in network.nodes[router].keys() and len(network.nodes[router][RULESET_KEY]) > 0:
                to_save_file(join(run_output_location, BASE_FOLDER_KEY, RULESET_FOLDER_KEY, IPTABLES_FOLDER_KEY), router, [rule_to_str(r) for r in network.nodes[router][RULESET_KEY]])

        decorrelation_trees = {}

        # DECORRELATION
        network, decorrelation_trees = perform_full_network_decorrelation(network, routers, decorrelation_trees, run_output_location)

        # TRAFFIC GENERATION
        print('TRAFFIC GENERATION STARTED')
        with open(join(run_output_location, PACKET_FILE), 'w') as packet_file:
            writer = PacketWriter(packet_file)
            writer.writeHeader()

            preprocessed_packets = reload_packets(join(args.input_location, run_id, PACKET_FOLDER, PACKET_FILE))
            packets = [Packet.from_genesis_entry(l, i, randint(0,500)) for i, l in enumerate(preprocessed_packets)]
            for packet in packets:
                writer.write(packet.to_writer_dict())

            accepted_rules = [rule for (_, data) in list(network.nodes(data=True)) if RULESET_KEY in data.keys() and data[ROLE_KEY] == EDeviceRole.ROUTER for rule in data[RULESET_KEY] if rule[2] == EPacketDecision.ACCEPT]
            decorrelated_rules, _ = inplace_ruleset_decorrelation(accepted_rules, EPacketDecision.DROP, 1)

            for i, (chain, conditions, action) in enumerate(decorrelated_rules):
                print_progress_bar('- packet generation', i + 1, len(decorrelated_rules))
                if action == EPacketDecision.ACCEPT:
                    continue
                packet = Packet.from_rule(network, (chain, conditions, action), random, len(packets), randint(0, 500))
                if packet and not any(packet == p for p in packets):
                    packets += [packet]
                    writer.write(packet.to_writer_dict())

        # BASE TRAFFIC MEASUREMENTS
        measurement_path = generate_csv_file_name(join(run_output_location, BASE_FOLDER_KEY), 'packet_traces')
        measurements = simulate_traffic(network, packets, measurement_path)
        validate_traffic(network, measurements, measurement_path)

        # WHITELISTED ONLY DISTRIBUTION
        print('WHITELISTED DISTRIBUTION STARTED')
        perform_accept_only_distribution(network, run_output_location)

        # OPTIMIZE RULESET
        print('OPTIMIZATION STARTED')
        network = perform_network_wide_local_optimization(network, routers, run_output_location, to_zimpl=args.to_zimpl_parsable)

        # DISTRIBUTE RULESET
        print('DISTRIBUTION STARTED')
        network = perform_presorted_global_optimization(network, routers, run_output_location, decorrelation_trees=decorrelation_trees)
            

        with open(join(run_output_location, 'runtime_measurements.csv'), 'w') as runtime_measurement_file:
            writer = MeasurementWriter(runtime_measurement_file, ['method', 'runtime'])
            writer.writeHeader()
            for method, runtime in get_runtime_measurements().items():
                writer.write({
                    'method' : method,
                    'runtime' : runtime
                })

        check_location = join(args.input_location, run_id, '.fred-footprint')
        with open(check_location, 'w') as footprint_file:
            footprint_file.write(run_output_location)
        reset_runtime_measurements()

    print(f'INFO: run informations saved to {output_root}')