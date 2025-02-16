from networkx import Graph, all_simple_paths, has_path
from hses_fred.save.measurements import MeasurementWriter
from hses_fred.utils.display import print_progress_bar
from hses_fred.utils.functions import device_id_to_ip, rule_to_str
from hses_fred.utils.constants import DEFAULT_ACTION_KEY, IP_KEY, RULESET_KEY
from hses_fred.objects.simulation import Packet, PathElement
from hses_genesis.utils.enum_objects import EPacketDecision, EDeviceRole, EParameterKey

CABLE_DELAY = 3.8

ROUTER_BASE_DELAY = 16.6

SWF_BASE_DELAY = 56.376

RULE_DELAY = 0.024

SWITCH_BASE_DELAY = 1.5

def send_packet(G : Graph, packet : Packet):
    src, dst = packet.conditions[EParameterKey.SRC], packet.conditions[EParameterKey.DST]
    if not G.has_node(src) or not G.has_node(dst) or not has_path(G, src, dst):
        print('WARNING: skipped packet due to missing src/dst!')
        return []
    
    paths = [path for path in list(all_simple_paths(G, src, dst))]
    weighted_paths = []
    for p_i, path in enumerate(paths):
        weighted_path = []
        for i, element_id in enumerate(path):
            device_data = G.nodes[element_id]
            if device_data == None:
                raise Exception(f'Found no device {element_id}')
            introduced_delay, decision, reasoning =  __calculate_descision_delay__(G, device_data, packet.process_condition_values(G, False))
            timestamp = 0
            if i > 0:
                ancestor : PathElement = weighted_path[i - 1]
                timestamp = ancestor.timestamp + ancestor.introduced_delay + CABLE_DELAY
            element_data = PathElement(element_id=element_id, element_ip=device_data[IP_KEY], timestamp=timestamp, decision=decision, introduced_delay=introduced_delay, transition_delay=CABLE_DELAY, reasoning=reasoning, path=p_i)
            weighted_path.append(element_data)

            if decision != EPacketDecision.ACCEPT:
                break
        weighted_paths.append(weighted_path)

    return weighted_paths

def __calculate_descision_delay__(G, device_data : dict, packet : Packet):
    if RULESET_KEY not in device_data.keys():
        return 0.0, EPacketDecision.ACCEPT, 'no other action specified...'
    
    if device_data['role'] == EDeviceRole.ROUTER:
        delay = ROUTER_BASE_DELAY
        if len(device_data[RULESET_KEY]) > 0:
            delay += SWF_BASE_DELAY
        
        for index, rule in enumerate(device_data[RULESET_KEY]):
            if rule_packet_match(rule, packet, G):
                delay += (device_data[RULESET_KEY].index(rule) + 1) * RULE_DELAY
                return delay, rule[2], f'rule action decision: {rule_to_str(rule)} [{index}]'
        delay += len(device_data[RULESET_KEY]) * RULE_DELAY
        return delay, device_data[DEFAULT_ACTION_KEY], f'default router decision'
    
    for rule in device_data[RULESET_KEY]:
        if rule_packet_match(rule, packet, G):
            return SWITCH_BASE_DELAY, rule[2], f'rule action decision: {rule_to_str(rule)}'
        
    return SWITCH_BASE_DELAY, device_data[DEFAULT_ACTION_KEY], 'default switch decision'
    
    
def rule_packet_match(rule : tuple, packet : Packet, G : Graph = None):
    _, conditions, _ = rule
    for i, key in enumerate(EParameterKey):
        if key not in packet.conditions.keys():
            continue
        
        p_value = packet.conditions.get(key)
        if i < 2 and isinstance(p_value, str) and G != None:
            p_value = device_id_to_ip(G, packet.conditions.get(key))
        r_start, r_end = conditions[i]
        if p_value < r_start or r_end < p_value:
            return False
    return True

def rule_device_match(rule : tuple, device, G : Graph = None):
    _, conditions, _ = rule
    if isinstance(device, str) and G != None:
        device_value = device_id_to_ip(G, device)
    else:
        device_value = device
    
    for i in range(2):
        r_start, r_end = conditions[i]
        if device_value >= r_start and device_value <= r_end:
            return True

    return False

def simulate_traffic(G, packets, save_location, run_label = 'original'):
    output = []
    with open(save_location, 'w') as trace_file:
        writer = MeasurementWriter(trace_file)
        writer.writeHeader()

        for i, packet in enumerate(packets):
            print_progress_bar('- sending packets', i + 1, len(packets))
            measurements = send_packet(G, packet)
            [writer.write(writer.toDict(run_label, trace_entry, packet.process_condition_values(G, False))) for path in measurements for trace_entry in path]
            output.append((packet, measurements))
    return output

def validate_traffic(G, measurements, measurement_file_path):
    for i, (packet, measured_packet_path) in enumerate(measurements):
        print_progress_bar('- validating packet', i + 1, len(measurements))
        for path in measured_packet_path:
            last_element = path[-1]
            if last_element.decision != packet.expected_decision and any(RULESET_KEY in G.nodes[element.location].keys() for element in path):
                if packet.expected_decision == EPacketDecision.ACCEPT:
                    raise Exception(f'Packet {packet} was dropped but should not have been in {measurement_file_path}!')
                else:
                    raise Exception(f'Packet {packet} was NOT dropped but should have been in {measurement_file_path}!')