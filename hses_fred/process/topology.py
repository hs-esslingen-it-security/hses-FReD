
from hses_fred.utils.constants import DEFAULT_ACTION_KEY, RULESET_KEY, SERVICES_KEY
from hses_fred.utils.functions import rule_to_str

def get_stripped_network(G):
    network = G.copy()
    for node in network.nodes():
        for rule_related_key in [RULESET_KEY, DEFAULT_ACTION_KEY]:
            if rule_related_key in network.nodes[node].keys():
                del network.nodes[node][rule_related_key]
    return network

def prepare_network_export(G):
    n_copy = G.copy()
    for node, data in n_copy.nodes(data=True):
        if RULESET_KEY in data.keys():
            n_copy.nodes[node][RULESET_KEY] = [rule_to_str(r) for r in data[RULESET_KEY]]
        if SERVICES_KEY in data.keys():
            n_copy.nodes[node][SERVICES_KEY] = [(service, None) for service in data[SERVICES_KEY]]
    return n_copy