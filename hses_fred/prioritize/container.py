from itertools import product
from networkx import DiGraph, Graph, all_simple_paths, has_path
from hses_fred.objects.enums import EFirewallSelectionStrategy
from hses_fred.objects.simulation import Rule
from hses_fred.utils.constants import MAX_ACL_SIZE, ROLE_KEY, RULESET_KEY, DEFAULT_ACTION_KEY
from hses_genesis.utils.enum_objects import EDeviceRole, EPacketDecision
from hses_fred.utils.functions import device_id_to_ip, measure_runtime
from hses_fred.decorrelate.ruleset import inplace as inplace_ruleset_decorrelation

def __device_inclusion_check__(parameter_value_range : tuple, device_ip : int):
    start, end = parameter_value_range
    if start == end:
        return start == device_ip
    else:
        return start <= device_ip and device_ip <= end

def __get_shortest_paths__(G, start, end, original_container_ip):
    if not has_path(G, start, original_container_ip) or not has_path(G, original_container_ip, end):
        return []

    paths = []
    for path in list(all_simple_paths(G, start, end)):
        # Nur Pfade annehmen, die den ursprünglichen RuleContainer enthalten
        if original_container_ip not in path:
            continue

        # Nur Pfade annehmen, die nicht ausschließlich aus Routern bestehen
        if all(EDeviceRole.from_device_id(device) == EDeviceRole.ROUTER for device in path):
            continue
        
        paths.append(path)

    return paths

@measure_runtime
def get_paths_to_cover(G : Graph, original_container : str, rule : Rule):
    all_rule_paths : list[list[str]] = []
    _, conditions, _ = rule

    sources = [node for node, data in G.nodes(data=True) if data[ROLE_KEY] in EDeviceRole.configurables() and __device_inclusion_check__(conditions[0], device_id_to_ip(G, node))]
    destinations = [node for node, data in G.nodes(data=True) if data[ROLE_KEY] in EDeviceRole.configurables() and __device_inclusion_check__(conditions[1], device_id_to_ip(G, node))]
    for start_node, end_node in product(sources, destinations):
        if start_node == end_node:
            continue
        
        all_paths = __get_shortest_paths__(G, start_node, end_node, original_container)
        filtered_paths = [path for path in all_paths if any(EDeviceRole.from_device_id(device) in EDeviceRole.configurables() for device in path)]
        all_rule_paths.extend(filtered_paths)
    
    return all_rule_paths

def __get_container_priorities__(G : Graph, paths):
    switch_ports = [n for n in G.nodes if EDeviceRole.from_device_id(n) == EDeviceRole.SWITCH]
    priority_map = {}
    for path in paths:
        if len(path) < 2:
            continue

        for port in switch_ports:
            if port not in path:
                continue

            if port not in priority_map.keys():
                priority_map[port] = {
                    'path_count' : 1,
                    'path_index' : path.index(port)
                }
            else:
                priority_map[port]['path_count'] += 1
                priority_map[port]['path_index'] += path.index(port)
    
    return priority_map

def __get_extended_priority_map__(G, paths, strategy : EFirewallSelectionStrategy):
    priority_map = __get_container_priorities__(G, paths)
    for port in priority_map.keys():
        if strategy == EFirewallSelectionStrategy.PLACE_EARLY:
            priority_map[port]['placement_priority'] = -1 * priority_map[port]['path_index'] / priority_map[port]['path_count']
        elif strategy == EFirewallSelectionStrategy.MINIMIZE_GLOBAL_RULESET:
            priority_map[port]['placement_priority'] = priority_map[port]['path_count']
        else:
            priority_map[port]['placement_priority'] = (-1 * priority_map[port]['path_index'] / priority_map[port]['path_count']) + priority_map[port]['path_count']
    return priority_map


def __all_paths_covered__(containers, paths):
    # alle relevanten Pfade werden von mindestens einem container abgedeckt.
    return all(any(choice in path for choice in containers) for path in paths if len(path) > 1)

def __calc_path_value__(contained_containers : list, priority_map : dict):
    return sum([priority_map[port]['placement_priority'] for port, _ in contained_containers])

def __all_container_paths_covered__(already_assigned_containers, paths):
    return all([any(n in p for n in already_assigned_containers) for p in paths])

def calculate_possible_distributions(G : Graph, paths_to_cover, subgraphs : list[Graph], subgraph_rulesets : list[tuple], original_container : str, rule, strategy = EFirewallSelectionStrategy.PLACE_EARLY, max_distribution_iterations = -1, debug_file = None, distribution_tree = None):
    
    priority_map = __get_extended_priority_map__(G, paths_to_cover, strategy)
    sorted_containers = list(priority_map.keys())
    sorted_containers.sort(key=lambda x : priority_map[x]['placement_priority'], reverse=True)

    possible_distributions, unable_containers = [], []
    if distribution_tree == None:
        distribution_tree = DiGraph()
    
    for i in range(len(sorted_containers) - 1):
        assigned_containers = []
        for j in range(i, len(sorted_containers) - 1):
            target_container = sorted_containers[j]

            if target_container in unable_containers or __all_container_paths_covered__(assigned_containers, paths_to_cover):
                continue

            if RULESET_KEY not in G.nodes[target_container]:
                G.nodes[target_container][DEFAULT_ACTION_KEY] = EPacketDecision.ACCEPT
                G.nodes[target_container][RULESET_KEY] = []

            target_ruleset = G.nodes[target_container][RULESET_KEY]
            appendable, additional_rules, distribution_tree = check_appendability(target_container=target_container, subgraphs=subgraphs, subgraph_rulesets=subgraph_rulesets, rule=rule, target_ruleset=target_ruleset, distribution_tree=distribution_tree, debug_file=debug_file)
            if appendable:
                assigned_containers.append((target_container, additional_rules))
            else:
                unable_containers.append(target_container)

            if __all_paths_covered__([container for container, _ in assigned_containers], paths_to_cover):
                break

        if __all_paths_covered__([container for container, _ in assigned_containers], paths_to_cover):
            possible_distributions.append((assigned_containers, __calc_path_value__(assigned_containers, priority_map)))
            if max_distribution_iterations > 0 and len(possible_distributions) >= max_distribution_iterations:
                break

    possible_distributions.sort(key = lambda x: -x[1])

    return possible_distributions, distribution_tree

def calculate_possible_distribution(G : Graph, paths_to_cover, subgraph_data : list[tuple[Graph, list[tuple]]], original_container : str, rule, strategy = EFirewallSelectionStrategy.PLACE_EARLY, debug_file = None, distribution_tree = None):
    priority_map = __get_extended_priority_map__(G, paths_to_cover, strategy)
    sorted_containers = list(priority_map.keys())
    sorted_containers.sort(key=lambda x : priority_map[x]['placement_priority'], reverse=True)

    if distribution_tree == None:
        distribution_tree = DiGraph()
    
    unable_containers, assigned_containers = [], []
    # rule_affected_subnets = set([G.nodes[device]['subnet'] for path in paths_to_cover for device in path])
    
    for target_container in sorted_containers:
        if target_container in unable_containers:
            continue
        
        remaining_paths = [path for path in paths_to_cover if not any(device in assigned_containers for device in path)]
        are_all_paths_covered = len(remaining_paths) == 0
        if are_all_paths_covered:
            break

        is_container_covering_open_paths = len([path for path in remaining_paths if target_container in path]) > 0
        if not is_container_covering_open_paths:
            continue

        if RULESET_KEY not in G.nodes[target_container]:
            G.nodes[target_container][DEFAULT_ACTION_KEY] = EPacketDecision.ACCEPT
            G.nodes[target_container][RULESET_KEY] = []

        target_ruleset = G.nodes[target_container][RULESET_KEY]

        is_target_container_full = len(target_ruleset) >= MAX_ACL_SIZE
        if is_target_container_full:
            unable_containers.append(target_container)
            continue

        target_subgraph_infos = [(subgraph, ruleset) for subgraph, ruleset in subgraph_data if target_container in subgraph.nodes]
        is_assignment_to_sender_receiver_side_impossible = len(target_subgraph_infos) != 1
        if is_assignment_to_sender_receiver_side_impossible:
            unable_containers.append(target_container)
            continue

        target_subgraph, target_subgraph_ruleset = target_subgraph_infos[0]
        # subgraph_subnets = set([data['subnet'] for _, data in G.nodes(data=True)])
        # all(subnet in subgraph_subnets for subnet in rule_affected_subnets):
        
        additional_rules = [rule]
        if not original_container in target_subgraph.nodes:
            additional_rules, distribution_tree = inplace_ruleset_decorrelation(target_subgraph_ruleset + additional_rules, depth=1, debug_file=debug_file, decorrelation_tree=distribution_tree)
            additional_rules = [(chain, conditions, action) for chain, conditions, action in additional_rules if action == EPacketDecision.DROP]

        if len(additional_rules) == 0:
            unable_containers.append(target_container)
            continue

        if (len(target_ruleset + additional_rules)) > MAX_ACL_SIZE:
            unable_containers.append(target_container)
            continue

        assigned_containers.append((target_container, additional_rules))

        if __all_paths_covered__([container for container, _ in assigned_containers], paths_to_cover):
            break

    return [(assigned_containers, __calc_path_value__(assigned_containers, priority_map))], distribution_tree

def is_generally_appendable(rule, target_container, target_ruleset, subgraphs, debug_file = None):
    """
    Returns False if target container is full OR if target container is on the sender and the receiver side of the original container
    """
    if len(target_ruleset) >= MAX_ACL_SIZE:
        if debug_file != None:
            debug_file.write(f'\nWARNING: Full target container {target_container}')
        return False

    sides_of_target = [subgraph for subgraph in subgraphs if target_container in subgraph.nodes]
    if len(sides_of_target) != 1:
        if debug_file != None:
            debug_file.write(f'\nWARNING: NW-contextual impossible target container {target_container} for {rule_to_str(rule)} chosen (does not split sender-receiver space sufficiently)!')
        return False
    return True
    
def check_appendability(subgraphs : list[Graph], subgraph_rulesets : list[tuple], target_container : str, target_ruleset : list[Rule], rule : Rule, distribution_tree, debug_file = None):
    if not is_generally_appendable(rule, target_container, target_ruleset, subgraphs, debug_file):
        return False, [], distribution_tree
    
    subgraph_ruleset = subgraph_rulesets[[i for i, subgraph in enumerate(subgraphs) if target_container in subgraph.nodes][0]]
    additional_rules, distribution_tree = inplace_ruleset_decorrelation(subgraph_ruleset + [rule], depth=1, debug_file=debug_file, decorrelation_tree=distribution_tree)
    additional_rules = [(chain, conditions, action) for chain, conditions, action in additional_rules if action == EPacketDecision.DROP]

    if len(additional_rules) == 0:
        if debug_file != None:
            debug_file.write(f'\nWARNING: NW-contextual impossible target container {target_container} for {rule_to_str(rule)} chosen (rule shadowed by existing rules in target container)')
        return False, [], distribution_tree

    if (len(target_ruleset + additional_rules)) > MAX_ACL_SIZE:
        if debug_file != None:
            debug_file.write(f'\nWARNING: Full target container {target_container}')
        return False, [], distribution_tree
    
    return True, additional_rules, distribution_tree