from networkx import DiGraph

from hses_fred.utils.functions import is_default_rule, rule_to_str

STATE_KEY = 'state'
CAUSE_KEY = 'cause'
REMOVAL_CAUSE_KEY = 'removal_cause'

def add_joining(tree : DiGraph, original_rules, joined_rules):
    original_strings = [rule_to_str(rule) for rule in original_rules]
    [tree.add_node(original_string, state='active') for original_string in original_strings if original_string not in tree.nodes]
    
    rules_unjoined = (len(joined_rules) > 1)
    if rules_unjoined:
        return tree

    joined_string = rule_to_str(joined_rules[0])

    dropped_rules = [original_string for original_string in original_strings if original_string != joined_string]
    rule_subset_dropped = (len(dropped_rules) == 1)
    if rule_subset_dropped:
        superset_rule = [rule for rule in original_strings if rule not in dropped_rules][0]
        subset_rule = dropped_rules[0]
        tree.nodes[subset_rule][STATE_KEY] = 'removed'
        if REMOVAL_CAUSE_KEY not in tree.nodes[subset_rule].keys():
            tree.nodes[subset_rule][REMOVAL_CAUSE_KEY] = [superset_rule]
        else:
            tree.nodes[subset_rule][REMOVAL_CAUSE_KEY].append(superset_rule)
        return tree

    if joined_string not in tree.nodes:
        tree.add_node(joined_string, state = 'active')

    for rule in original_strings:
        tree.nodes[rule][STATE_KEY] = 'joined'
        tree.nodes[rule]['join_target'] = joined_string
        tree.add_edge(rule, joined_string)

    return tree

def add_decorrelation(tree : DiGraph, original_rules, decorrelated_rules):
    superior_string, inferior_string = [rule_to_str(rule) for rule in original_rules]
    for rule_string in [superior_string, inferior_string]:
        if rule_string not in tree.nodes:
            tree.add_node(rule_string, state = 'active')

    decorrelated_strings = [rule_to_str(rule) for rule in decorrelated_rules]

    no_decorrelation = superior_string == inferior_string or inferior_string in decorrelated_strings
    if no_decorrelation:
        return tree

    inferior_dropped = (len(decorrelated_strings) == 0)
    if inferior_dropped:
        tree.nodes[inferior_string][STATE_KEY] = 'removed'
        if REMOVAL_CAUSE_KEY not in tree.nodes[inferior_string].keys():
            tree.nodes[inferior_string][REMOVAL_CAUSE_KEY] = [superior_string]
        else:
            tree.nodes[inferior_string][REMOVAL_CAUSE_KEY].append(superior_string)

        return tree

    for rule_string in decorrelated_strings:
        if rule_string not in tree.nodes:
            tree.add_node(rule_string, state = 'active')


        tree.nodes[inferior_string][STATE_KEY] = 'removed'
        tree.add_edge(inferior_string, rule_string)

        if REMOVAL_CAUSE_KEY not in tree.nodes[inferior_string].keys():
            tree.nodes[inferior_string][REMOVAL_CAUSE_KEY] = [superior_string]
        else:
            tree.nodes[inferior_string][REMOVAL_CAUSE_KEY].append(superior_string)

        is_rule_inversion = is_default_rule(original_rules[1]) and original_rules[0][2] != original_rules[1][2]
        if is_rule_inversion:
            tree.nodes[superior_string][STATE_KEY] = 'inverted'
        
        tree.add_edge(superior_string, rule_string)
    return tree

def prepare_nodes(tree : DiGraph):
    tree_copy = tree.copy()
    for node, data in tree_copy.nodes(data=True):
        for key in [REMOVAL_CAUSE_KEY]:
            if key in data.keys():
                tree_copy.nodes[node][key] = str(data[key])
    return tree_copy