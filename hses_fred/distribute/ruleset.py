
from collections import Counter
from copy import copy
from functools import lru_cache
from itertools import combinations, product
from numpy import mean
from hses_fred.decorrelate.enums import ELeftoverReason, EParameterRelation, ERuleRelation
from hses_fred.distribute.error import OverfullACLException
from hses_fred.simulate.traffic import rule_device_match
from hses_fred.utils.display import print_progress_bar
from hses_fred.utils.functions import device_id_to_ip, measure_runtime, rule_to_str
from hses_fred.prioritize.container import get_paths_to_cover
from hses_fred.decorrelate.ruleset import from_each_other as relative_ruleset_decorrelation, inplace as inplace_ruleset_decorrelation
from hses_fred.utils.constants import DEFAULT_ACTION_KEY, MAX_ACL_SIZE, ROLE_KEY, RULESET_KEY, SUBNET_KEY
from hses_fred.process.parameters import parse_paramter_endpoints
from networkx import DiGraph, Graph, all_simple_paths, connected_components, dfs_tree, shortest_path
from hses_genesis.utils.enum_objects import EDeviceRole, EPacketDecision, EParameterKey, EParameterType
from hses_genesis.utils.constants import FULL_RANGES
from hses_fred.history.decorrelation import add_joining as extend_tree
from warnings import warn

def __ensure_ruleset__(G : Graph, container):
    if RULESET_KEY not in G.nodes[container]:
        G.nodes[container][DEFAULT_ACTION_KEY] = EPacketDecision.ACCEPT
        G.nodes[container][RULESET_KEY] = []

def __is_ruleset_full__(G : Graph, container):
    target_ruleset = G.nodes[container][RULESET_KEY]

    is_target_container_full = len(target_ruleset) >= MAX_ACL_SIZE
    if is_target_container_full:
        return True
    return False
    
def ripple_wave_distribution(G : Graph, original_container, rule, visited = None, depth = 0):
    if visited == None:
        visited = []

    visited.append(original_container)
    tree = dfs_tree(G, original_container, 3)
    possible_targets = set([node for node in tree.nodes() if node not in visited and tree.out_degree(node)==0 and tree.in_degree(node)==1 and EDeviceRole.from_device_id(node) != EDeviceRole.PORT])
    affected_connected_devices = [target for target in possible_targets if EDeviceRole.from_device_id(target) in EDeviceRole.configurables() and rule_device_match(rule, target, G)]
    if len(affected_connected_devices) > 0:
        if depth == 0:
            print(f'Cannot ripple wave distribute rule {rule_to_str(rule)} as one or more rule affected nodes ({affected_connected_devices}) are connected directly to the original container.')
        return []

    i = 0
    possible_targets = [target for target in possible_targets if EDeviceRole.from_device_id(target) == EDeviceRole.SWITCH]

    while i < len(possible_targets):
        container = possible_targets[i]
        
        __ensure_ruleset__(G, container)

        if __is_ruleset_full__(G, container) or EDeviceRole.from_device_id(container) == EDeviceRole.ROUTER:
            replacement_targets = ripple_wave_distribution(G, container, rule, visited + list(possible_targets), depth + 1)
            if len(replacement_targets) == 0:
                if depth == 0:
                    print(f'\nCannot ripple wave distribute rule {rule_to_str(rule)} as the ruleset of container {container} is full.')
                return []
            possible_targets.remove(container)
            possible_targets += replacement_targets
            continue
        i += 1
    return possible_targets

@lru_cache()
def get_subgraph_path_map(subgraph : Graph):
    possible_sender_nodes = [node for node, data in subgraph.nodes(data = True) if data[ROLE_KEY] in EDeviceRole.configurables()]
    subgraph_path_map = {}
    for src in possible_sender_nodes:
        for dst in possible_sender_nodes:
            if src == dst:
                continue
            subgraph_path_map[(src,dst)] = all_simple_paths(subgraph, src, dst)
    return subgraph_path_map

# TODO fix!
@measure_runtime
def get_target_container_base_ruleset(target_container, subgraph_infos : dict):
    subgraph_path_infos = [(subgraph, subgraph_paths) for subgraph, subgraph_paths in subgraph_infos if target_container in subgraph.nodes]
    if len(subgraph_path_infos) > 1:
        raise Exception(f'Target container {target_container} is part of multiple subgraphs but should not.')
    
    base_rule_values = [FULL_RANGES[EParameterType.from_parameter_key(p)] for p in EParameterKey][2:]

    ruleset = []
    for subgraph, subgraph_path_info in subgraph_path_infos:
        for (src, dst), src_dst_paths in subgraph_path_info.items():
            if any(target_container in path for path in src_dst_paths):
                src_ip = device_id_to_ip(subgraph, src)
                dst_ip = device_id_to_ip(subgraph, dst)
                rule_conditions = tuple([(src_ip, src_ip), (dst_ip, dst_ip)] + base_rule_values)
                ruleset.append((('INPUT', rule_conditions, EPacketDecision.ACCEPT), src_dst_paths))
    ruleset, _ = compress_subgraph_ruleset(ruleset)

    return [rule for rule, _ in ruleset]

def ripple_wave_leftovers(G, original_container, rule):
    tree : DiGraph = dfs_tree(G, original_container, 5)
    paths = [list(shortest_path(tree, original_container, leaf)) for leaf in tree.nodes if tree.out_degree(leaf) == 0 and tree.in_degree(leaf) == 1]
    paths = [[n for n in path if EDeviceRole.from_device_id(n) != EDeviceRole.PORT] for path in paths]
    paths = [path for path in paths if len(path) > 1]
    chosen_containers = []
    for path in paths:
        path_covered = False
        for possible_container in path[1:]:
            if possible_container in chosen_containers or EDeviceRole.from_device_id(possible_container) == EDeviceRole.SWITCH:
                path_covered = True
                if possible_container not in chosen_containers:
                    chosen_containers.append(possible_container)
                break
        if not path_covered:
            print(f'Cannot ripple wave distribute rule {rule_to_str(rule)}.')
            return []
    return chosen_containers

def create_subnet_graph(G : Graph):
    subnets = set([d[SUBNET_KEY] for _, d in G.nodes(data=True)])
    subnet_graph = Graph()
    subnet_graph.add_nodes_from(subnets)
    edges = []
    for n in G.nodes():
        node_edges = G.edges(n)
        edges.extend(set(map(lambda x: (G.nodes[x[0]][SUBNET_KEY], G.nodes[x[1]][SUBNET_KEY]), node_edges)))
    subnet_graph.add_edges_from(set(edges))
    return subnet_graph

def get_rule_passed_subnets(G : Graph, rule):
    _, (src, dst, _, _, _), _ = rule
    src_subnets = []
    dst_subnets = []
    for node in G.nodes:
        subnet_endpoints = parse_paramter_endpoints(node)
        if EParameterRelation.from_parameter_values(src, subnet_endpoints) != EParameterRelation.DISJOINT:
            src_subnets.append(node)
        if EParameterRelation.from_parameter_values(dst, subnet_endpoints) != EParameterRelation.DISJOINT:
            dst_subnets.append(node)

    all_paths = [all_simple_paths(G, s, d) for s, d in product(src_subnets, dst_subnets)]
    return set([element for list_of_paths in all_paths for path in list_of_paths for element in path])

def __ensure_trees__(distribution_tree = None, decorrelation_trees = None, transition_trees = None):
    if transition_trees == None:
        transition_trees : dict = {}

    if decorrelation_trees == None:
        decorrelation_trees : dict = {}
    
    if distribution_tree == None:
        distribution_tree = DiGraph(directed = True)

    return distribution_tree, decorrelation_trees, transition_trees

def find_minimal_covers(paths, possible_containers):

    def is_cover(combo, paths):
        covered = set()
        for elem in combo:
            for path in paths:
                if elem in path:
                    covered.add(frozenset(path))
        return len(covered) == len(paths)

    def find_combinations(possible_containers, paths):
        minimal_covers = []
        
        for i in range(1, len(possible_containers) + 1):
            for combo in combinations(possible_containers, i):
                if is_cover(combo, paths):
                    is_minimal = all(not set(combo).issubset(set(c)) for c in minimal_covers)
                    if is_minimal:
                        minimal_covers.append(combo)
        return minimal_covers

    return find_combinations(possible_containers, paths)

def assign_elements_to_containers(G : Graph, original_containers):

    """
    In the following code: add a functionality to evenly chose covers, if some container already has a lot of assigned elements
    """

    def greedy_assign_elements(elements, containers, minimal_covers):
        assignment = {container: [] for container in containers}
        unassigned = []

        for element in elements:
            assigned = False

            valid_covers = sorted(
                minimal_covers[element],
                key=lambda cover: len(cover) + sum(len(assignment[container]) for container in cover)
            )

            for cover in valid_covers:
                if all(len(assignment[container]) < MAX_ACL_SIZE for container in cover):
                    for container in cover:
                        assignment[container].append(element)
                    assigned = True
                    break

            if not assigned:
                reasoning = f"WARNING: Cannot assign rule {rule_to_str(element[1])} to a minimal cover (⌀{mean([len(assignment[container]) for container in cover])} in {len(cover)} covers with max ACL size of {MAX_ACL_SIZE};)"
                unassigned.append(reasoning)
                warn(reasoning)

        return assignment, unassigned
    
    switches = [n for n, data in G.nodes(data = True) if data[ROLE_KEY] == EDeviceRole.SWITCH]

    minimal_covers = {}
    leftovers = []

    for original_container in original_containers:
        if RULESET_KEY not in G.nodes[original_container].keys():
            continue

        ruleset = G.nodes[original_container][RULESET_KEY]
        if len(ruleset) == 0:
            continue

        for i, rule in enumerate(ruleset):
            print_progress_bar('Calculating rule covers', i, len(ruleset) - 1)
            paths_to_cover = get_paths_to_cover(G, original_container, rule)
            if len(paths_to_cover) == 0:
                reasoning = f'WARNING: Unable to calculate conduit paths of rule {rule_to_str(rule)} in {original_container}.'
                leftovers.append((ELeftoverReason.NoPath, original_container, rule, reasoning))
                continue

            covers = find_minimal_covers(paths_to_cover, [n for n in switches if any(n in path for path in paths_to_cover)])
            if len(covers) == 0:
                reasoning = f"WARNING: Unable to calculate minimal covers for {len(paths_to_cover)} paths defined by rule {rule_to_str(rule)} in {original_container}."
                leftovers.append((ELeftoverReason.NoCovers, original_container, rule, reasoning))
                warn(reasoning)
            else:
                covers = sorted(covers, key=lambda x: len(x))
                minimal_covers[(original_container, rule)] = covers

    assignments, unassigned = greedy_assign_elements(minimal_covers.keys(), switches, minimal_covers)
    leftovers += [(ELeftoverReason.ACLOverflow, original_container, rule, warning_message) for warning_message in unassigned]
    return assignments, leftovers
        
@measure_runtime
def presorting_ruleset_distribution(G : Graph, original_containers, distribution_tree = None, decorrelation_trees = None, transition_trees = None):
    overfull_acls = []
    distribution_tree, decorrelation_trees, transition_trees = __ensure_trees__(distribution_tree, decorrelation_trees, transition_trees)
    assignments, leftovers = assign_elements_to_containers(G, original_containers)

    for (reason, router, rule, _) in leftovers:
        if reason == ELeftoverReason.NoPath:
            G.nodes[router][RULESET_KEY] = [r for r in G.nodes[router][RULESET_KEY] if r != rule]

    subgraph_map = {original_container : get_subgraphs(G, original_container) for original_container in original_containers}
    ruleset_map = {target_container : [] for target_container in assignments.keys()}

    for i, (target_container, rule_origin_information) in enumerate(assignments.items()):
        print_progress_bar('Calculating target container ruleset', i + 1, len(assignments))
        __ensure_ruleset__(G, target_container)

        if target_container not in distribution_tree.nodes:
            distribution_tree.add_node(target_container, subnet=G.nodes[target_container][SUBNET_KEY])

        if target_container not in decorrelation_trees.keys():
            decorrelation_trees[target_container] = DiGraph(directed=True)

        for original_container, rule in rule_origin_information:
            
            if original_container not in distribution_tree.nodes:
                distribution_tree.add_node(original_container, subnet=G.nodes[original_container][SUBNET_KEY])

            if (original_container, target_container) not in distribution_tree.edges:
                distribution_tree.add_edge(original_container, target_container, rules = [])

            distribution_tree.edges[(original_container, target_container)]['rules'].append(rule_to_str(rule))

            associated_subgraphs = [subgraph for subgraph in subgraph_map[original_container] if target_container in subgraph.nodes]
            subgraph_ruleset = [rule for _, ruleset in get_targeted_subgraph_ruleset(target_container, associated_subgraphs) for rule, _ in ruleset]
            decorrelation_ruleset, decorrelation_trees[target_container] = compress_ruleset(subgraph_ruleset, decorrelation_trees[target_container])

            transition_name = f'{original_container}-{target_container}'
            if transition_name not in transition_trees.keys():
                transition_trees[transition_name] = DiGraph(directed = True)

            transition_ruleset, transition_trees[transition_name] = relative_ruleset_decorrelation(decorrelation_ruleset, [rule], decorrelation_tree=transition_trees[transition_name], depth=1)
            ruleset_map[target_container] = ruleset_map[target_container] + transition_ruleset
            G.nodes[original_container][RULESET_KEY] = [r for r in G.nodes[original_container][RULESET_KEY] if r != rule]

        decorrelated_ruleset, decorrelation_trees[target_container] = inplace_ruleset_decorrelation(ruleset_map[target_container], depth=1, decorrelation_tree=decorrelation_trees[target_container])
        ruleset_map[target_container] = [rule for rule in decorrelated_ruleset if rule[2] == EPacketDecision.DROP]

    for target_container, ruleset in ruleset_map.items():
        if len(ruleset) > MAX_ACL_SIZE:
            warn(f'Invalid run: ACL of {target_container} violates maximal ACL rule count ({len(ruleset)}/{MAX_ACL_SIZE}) after distribution.')
            overfull_acls.append((target_container, len(ruleset)))

        G.nodes[target_container][RULESET_KEY] = ruleset

    return G, leftovers, distribution_tree, decorrelation_trees, transition_trees, overfull_acls

@measure_runtime
def greedy_ruleset_distribution(G : Graph, original_container, ruleset, distribution_tree = None, apply_ripple_distribution = False, decorrelation_trees = None, transition_trees = None):
    distribution_tree, decorrelation_trees, transition_trees = __ensure_trees__(distribution_tree, decorrelation_trees, transition_trees)

    if original_container not in distribution_tree.nodes:
        distribution_tree.add_node(original_container, subnet=G.nodes[original_container][SUBNET_KEY])

    subgraphs = get_subgraphs(G, original_container)
    
    switches = [switch for switch, data in G.nodes(data = True) if data[ROLE_KEY] == EDeviceRole.SWITCH]
    switch_affected_connections = {}
    for i, switch in enumerate(switches):
        print_progress_bar('-- calculating target container ruleset', i + 1, len(switches))
        associated_subgraphs = [subgraph for subgraph in subgraphs if switch in subgraph.nodes]
        switch_affected_connections[switch] = get_targeted_subgraph_ruleset(switch, associated_subgraphs)
    unable_containers = []
    
    for i, rule in enumerate(ruleset):
        print_progress_bar('-- distributing rule', i + 1, len(ruleset))

        paths_to_cover = get_paths_to_cover(G, original_container, rule)
        chosen_containers = []

        if len(paths_to_cover) == 0 and apply_ripple_distribution:
            chosen_containers = ripple_wave_leftovers(G, original_container, rule)
            if len(chosen_containers) == 0:
                continue

        else:
            prioritized_containers = Counter(device for path in paths_to_cover for device in path if device in switches and device not in unable_containers)
            assignable_containers = list(prioritized_containers.keys())
            assignable_containers.sort(key=lambda x: prioritized_containers[x], reverse=True)

            for path in paths_to_cover:
                is_already_covered = any(device in chosen_containers for device in path)
                if is_already_covered:
                    continue

                possible_containers = [container for container in assignable_containers if container in path and container not in unable_containers]
                
                if len(possible_containers) == 0:
                    print(f'Cannot distribute rule {rule_to_str(rule)} due to missing possible target containers.')
                    chosen_containers = []
                    break
                
                chosen_container = None

                for container in possible_containers:
                    related_subgraph = [subgraph for subgraph in subgraphs if container in subgraph.nodes]
                    is_subgraph_undistinguishable = len(related_subgraph) != 1
                    if is_subgraph_undistinguishable:
                        continue

                    __ensure_ruleset__(G, container)

                    if __is_ruleset_full__(G, container):
                        unable_containers.append(container)
                        continue

                    chosen_container = container
                    break

                if chosen_container:
                    chosen_containers.append(chosen_container)
                else:
                    print(f'Cannot distribute rule {rule_to_str(rule)} due to uncoverable path {path}')
                    chosen_containers = []
                    break
        
        if len(chosen_containers) > 0:
            for container in chosen_containers:
                if container not in distribution_tree.nodes:
                    distribution_tree.add_node(container, subnet=G.nodes[container]['subnet'])

                if distribution_tree.has_edge(original_container, container):
                    distribution_tree.edges[original_container, container]['value'] += 1
                    distribution_tree.edges[original_container, container]['rules'] += [rule_to_str(rule)]
                else:
                    distribution_tree.add_edge(original_container, container, value=1, distance=len(shortest_path(G, original_container, container)), rules = [rule_to_str(rule)])
                
                if container not in decorrelation_trees.keys():
                    decorrelation_trees[container] = DiGraph(directed=True)
                
                transition_name = f'{original_container}-{container}'
                if transition_name not in transition_trees.keys():
                    transition_trees[transition_name] = DiGraph(directed = True)

                # The semantics of all paths containing the target container must remain the same
                decorrelation_ruleset = []
                if len(paths_to_cover) > 0:
                    for subgraph, subgraph_ruleset in switch_affected_connections[container]:
                        if original_container not in subgraph.nodes:
                            decorrelation_ruleset.extend([rule for rule, _ in subgraph_ruleset])
                        else:
                            for rule, rule_paths in subgraph_ruleset:
                                if any(original_container in path for path in rule_paths):
                                    continue
                                decorrelation_ruleset.append(rule)
                decorrelation_ruleset, decorrelation_trees[container] = compress_ruleset(list(set(decorrelation_ruleset)), decorrelation_trees[container])
                transition_ruleset, transition_trees[transition_name] = relative_ruleset_decorrelation(decorrelation_ruleset, [rule], decorrelation_tree=transition_trees[transition_name], depth=1)
                decorrelated_ruleset, decorrelation_trees[container] = inplace_ruleset_decorrelation(G.nodes[container][RULESET_KEY] + transition_ruleset, depth=1, decorrelation_tree=decorrelation_trees[container])
                blacklisting_ruleset = [rule for rule in decorrelated_ruleset if rule[2] == EPacketDecision.DROP]
                if len(blacklisting_ruleset) > MAX_ACL_SIZE:
                    raise OverfullACLException(container, len(blacklisting_ruleset), MAX_ACL_SIZE)
                G.nodes[container][RULESET_KEY] = blacklisting_ruleset
        
            G.nodes[original_container][RULESET_KEY] = [r for r in G.nodes[original_container][RULESET_KEY] if r != rule]

    return G, distribution_tree, decorrelation_trees, transition_trees


def connect_values(a, b):
    a_start, a_end = a
    b_start, b_end = b
    c_start, c_end = 0, 0
    if a_start <= b_start:
        c_start = a_start
    else:
        c_start = b_start
    
    if a_end >= b_end:
        c_end = a_end
    else:
        c_end = b_end
    return (c_start, c_end)

def join_rules(a : tuple, b : tuple):
    if a == b:
        return [a]

    a_chain, a_conditions, a_action = a
    b_chain, b_conditions, b_action = b
    if a_chain != b_chain or a_action != b_action:
        return [a, b]
    
    parameter_relations = [EParameterRelation.from_parameter_values(a_conditions[i], b_conditions[i]) for i, _ in enumerate(EParameterKey)]
    rule_relation = ERuleRelation.from_parameter_relations(parameter_relations)
    
    if rule_relation == ERuleRelation.INCLUSIVELY_MATCHING_SUPER:
        return [a]
    
    if rule_relation == ERuleRelation.INCLUSIVELY_MATCHING_SUB:
        return [b]
    
    if len([p_r for p_r in parameter_relations if p_r != EParameterRelation.EQUAL]) != 1:
        return [a, b]
    
    if rule_relation in [ERuleRelation.COMPLETELY_DISJOINT, ERuleRelation.PARTIALLY_DISJOINT]:
        c_conditions = list(copy(b_conditions))
        for i, parameter_relation in enumerate(parameter_relations):
            if parameter_relation == EParameterRelation.SUPERSET:
                c_conditions[i] = a_conditions[i]
            elif parameter_relation == EParameterRelation.CORRELATED:
                c_conditions[i] = connect_values(list(a_conditions)[i], list(b_conditions)[i])
            elif parameter_relation == EParameterRelation.DISJOINT:
                a_value, b_value = list(a_conditions)[i], list(b_conditions)[i]
                if not (a_value[0] == b_value[1] + 1 or a_value[1] + 1 == b_value[0]):
                    return [a, b]
                c_conditions[i] = connect_values(a_value, b_value)
            else:
                continue # conditions are equal or b is superset of a --> keep b
        
        return [(a_chain, tuple(c_conditions), a_action)]
    
    return [a, b]

@measure_runtime
def compress_subgraph_ruleset(input_ruleset : list[tuple], decorrelation_tree = None, print_progress = False):
    if decorrelation_tree == None:
        decorrelation_tree = DiGraph(directed = True)

    ruleset = copy(input_ruleset)
    changes = True
    change_counter = 0
    while changes == True:
        change_counter += 1
        changes = False
        i = 0
        while i < len(ruleset):
            if print_progress:
                print_progress_bar(f'--- {change_counter}. ruleset compression', i + 1, len(ruleset))
            a, a_paths = ruleset[i]
            j = i + 1
            while j < len(ruleset):
                b, b_paths = ruleset[j]
                joined_rules = join_rules(a, b)
                decorrelation_tree = extend_tree(decorrelation_tree, [a, b], joined_rules)

                if len(joined_rules) > 1: # a and b cannot be joined -> continue with next b
                    j += 1
                    continue

                changes = True
                if a in joined_rules: # a is superset of or equal to b -> drop b and continue with same b index
                    ruleset = [(rule, paths) for rule, paths in ruleset if rule != b]
                    continue
                if b in joined_rules: # b is superset of a -> drop a and continue with same a index
                    ruleset = [(rule, paths) for rule, paths in ruleset if rule != a]
                    break

                c_paths = list(a_paths) + list(b_paths)
                ruleset = [(rule, paths) for rule, paths in ruleset if rule not in [a, b]] + [(rule, c_paths) for rule in joined_rules] # a & b were joined -> drop a & b from ruleset and add the joined rule; reset a index
                break
            if a in [rule for rule, _ in ruleset]:
                i += 1
    return ruleset, decorrelation_tree

@measure_runtime
def compress_ruleset(input_ruleset : list[tuple], decorrelation_tree = None, print_progress = False):
    if decorrelation_tree == None:
        decorrelation_tree = DiGraph(directed = True)

    ruleset = copy(input_ruleset)
    changes = True
    change_counter = 0
    while changes == True:
        change_counter += 1
        changes = False
        i = 0
        while i < len(ruleset):
            if print_progress:
                print_progress_bar(f'--- {change_counter}. ruleset compression', i + 1, len(ruleset))
            a = ruleset[i]
            j = i + 1
            while j < len(ruleset):
                b = ruleset[j]
                joined_rules = join_rules(a, b)
                decorrelation_tree = extend_tree(decorrelation_tree, [a, b], joined_rules)

                if len(joined_rules) > 1: # a and b cannot be joined -> continue with next b
                    j += 1
                    continue

                changes = True
                if a in joined_rules: # a is superset of or equal to b -> drop b and continue with same b index
                    ruleset.remove(b)
                    continue
                if b in joined_rules: # b is superset of a -> drop a and continue with same a index
                    ruleset.remove(a)
                    break

                ruleset = [rule for rule in ruleset if rule not in [a, b]] + joined_rules # a & b were joined -> drop a & b from ruleset and add the joined rule; reset a index
                break
            if a in ruleset:
                i += 1
    return ruleset, decorrelation_tree

@measure_runtime
def get_targeted_subgraph_ruleset(target_container, associated_subgraphs : list[Graph], print_progress = False):
    base_rule_values = [FULL_RANGES[EParameterType.from_parameter_key(p)] for p in EParameterKey][2:]
    subgraph_infos = []
    for subgraph in associated_subgraphs:
        path_extended_subgraph_ruleset = []
        possible_sender_nodes = [node for node, data in subgraph.nodes(data = True) if data[ROLE_KEY] in EDeviceRole.configurables()]
        for i, src in enumerate(possible_sender_nodes):
            for j, dst in enumerate(possible_sender_nodes):
                if print_progress:
                    print_progress_bar('-- checking src-dst combination', i * len(possible_sender_nodes) + j + 1, len(possible_sender_nodes) * len(possible_sender_nodes))

                if src == dst:
                    continue

                paths = all_simple_paths(subgraph, src, dst)
                if any(target_container in path for path in paths):
                    src_ip = device_id_to_ip(subgraph, src)
                    dst_ip = device_id_to_ip(subgraph, dst)
                    rule_conditions = tuple([(src_ip, src_ip), (dst_ip, dst_ip)] + base_rule_values)
                    path_extended_subgraph_ruleset.append((('INPUT', rule_conditions, EPacketDecision.ACCEPT), paths))
        path_extended_subgraph_ruleset, _ = compress_subgraph_ruleset(path_extended_subgraph_ruleset, print_progress=print_progress)
        subgraph_infos.append((subgraph, path_extended_subgraph_ruleset))

    return subgraph_infos

def get_subgraphs(G : Graph, router):
    redundant_routers = [node for node, data in G.nodes(data=True) if data[ROLE_KEY] == EDeviceRole.ROUTER and set(data[SUBNET_KEY]) == set(G.nodes[router][SUBNET_KEY])]
    [print(r, G.nodes[r][SUBNET_KEY]) for r in redundant_routers]
    g_copy = G.copy()
    g_copy.remove_nodes_from(redundant_routers)

    subgraphs = [g_copy.subgraph(c) for c in connected_components(g_copy)]

    if len(subgraphs) > 2:
        [print(list(subgraph.nodes)) for subgraph in subgraphs]
        raise Exception(f'Too many subgraphs after network split at container {router}s position ({len(subgraphs)}).')

    return subgraphs