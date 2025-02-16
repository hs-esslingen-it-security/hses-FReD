from copy import deepcopy
from hses_genesis.utils.enum_objects import EPacketDecision
from hses_fred.simulate.traffic import rule_packet_match
from hses_fred.utils.functions import generate_full_range_rule, measure_runtime, rule_to_str
from hses_fred.utils.display import print_progress_bar
from hses_fred.decorrelate.rule import from_another as decorrelate_rules
from hses_fred.decorrelate.rule import ERuleRelation
from itertools import product
from networkx import DiGraph
from hses_fred.history.decorrelation import add_decorrelation as extend_tree

def write_to_debug_file(debug_file, a, b, relation, decorrelated):
    if debug_file and b not in decorrelated:
        debug_file.write(f'DECORRELATING\n- `{rule_to_str(a)}` ({a[1]}) from\n- `{rule_to_str(b)} ({b[1]})` ({relation.name}) to:\n')
        if len(decorrelated) == 0:
            debug_file.write('\t- `[]`\n')
        for rule in decorrelated:
            debug_file.write(f'\t- `{rule_to_str(rule)}` ({rule[1]})\n')
        debug_file.write('\n')

def __all_rules_disjoint__(rules):
    for a, b in product(rules, rules):
        if a == b:
            continue
        if ERuleRelation.from_rules(a, b) not in [ERuleRelation.COMPLETELY_DISJOINT, ERuleRelation.PARTIALLY_DISJOINT]:
            return False
    return True

def __check_decorrelation_validity__(original_rule, decorrelation_rule, decorrelations, packets):
    for packet in packets:
        if len(list(filter(lambda rule: rule_packet_match(rule, packet), [original_rule] + decorrelations))) > 1:
            raise Exception(f'More than 1 rules match {packet}')


    if original_rule[2] == EPacketDecision.DROP or decorrelation_rule[2] != EPacketDecision.DROP:
        return
    
    allowed_packets = list(filter(lambda p: rule_packet_match(original_rule, p), packets))
    div_packets = list(filter(lambda p: any(rule_packet_match(r, p) for r in decorrelations), allowed_packets))
    if len(div_packets) > 0:
        print('FAILED DECORRELATION!')
        print(original_rule, decorrelation_rule)
        [print(r) for r in decorrelations]
        print(':')
        dropped_packets = list(filter(lambda p: p not in allowed_packets and rule_packet_match(decorrelation_rule, p), packets))
        [print(p) for p in dropped_packets]
        print('-->')
        [print(p) for p in div_packets]
        raise Exception('Failed decorrelation')

@measure_runtime
def inplace(ruleset : list[tuple], default_action = None, depth = 0, decorrelation_tree = None, allowed_packets = None, debug_file = None):
    ruleset_copy = deepcopy(ruleset)
    if default_action != None:
        ruleset_copy.append(generate_full_range_rule(ruleset_copy[-1][0], default_action))

    if decorrelation_tree == None:
        decorrelation_tree = DiGraph(directed=True)

    i = 1
    while i < len(ruleset_copy):
        if depth == 0:
            print_progress_bar(f'- decorrelating rule', i, len(ruleset_copy) - 1)
        j = i
        while j < len(ruleset_copy):
            a, b = ruleset_copy[i - 1], ruleset_copy[j]

            relation = ERuleRelation.from_rules(a, b)
            decorrelated = decorrelate_rules(a, b, relation)

            decorrelation_tree = extend_tree(decorrelation_tree, [a, b], decorrelated)

            if debug_file and b not in decorrelated:
                write_to_debug_file(debug_file, a, b, relation, decorrelated)

            while not __all_rules_disjoint__(decorrelated):
                decorrelated, decorrelation_tree = inplace(decorrelated, depth=depth+1, decorrelation_tree=decorrelation_tree)

            if allowed_packets:
                __check_decorrelation_validity__(a, b, decorrelated, allowed_packets)
            
            ruleset_copy = ruleset_copy[:j] + decorrelated + ruleset_copy[(j + 1):]
            j += len(decorrelated)
            
        i += 1
    return ruleset_copy, decorrelation_tree

@measure_runtime
def from_each_other(superior_rules : list[tuple], inferior_rules : list[tuple], depth = 0, decorrelation_tree = None):
    decorrelated = deepcopy(inferior_rules)

    if decorrelation_tree == None:
        decorrelation_tree = DiGraph(directed=True)

    for j, superior_rule in enumerate(superior_rules):
        if depth == 0:
            print_progress_bar(f'- decorrelating rule [{len(decorrelated)}]', j + 1, len(superior_rules))
        
        i = 0
        while i < len(decorrelated):
            inferior_rule = decorrelated[i]
            relation = ERuleRelation.from_rules(superior_rule, inferior_rule)
            decorrelated_rules = decorrelate_rules(superior_rule, inferior_rule, relation)
            decorrelation_tree = extend_tree(decorrelation_tree, [superior_rule, inferior_rule], decorrelated)

            while not __all_rules_disjoint__(decorrelated_rules):
                decorrelated_rules, decorrelation_tree = inplace(decorrelated_rules, depth=1, decorrelation_tree=decorrelation_tree)

            decorrelated = decorrelated[:i] + decorrelated_rules + decorrelated[(i + 1):]
            i += len(decorrelated_rules)
    return inplace(decorrelated, decorrelation_tree=decorrelation_tree, depth=depth + 1)