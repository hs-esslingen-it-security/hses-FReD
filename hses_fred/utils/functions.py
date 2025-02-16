from ipaddress import ip_address
from time import time
from hses_fred.utils.constants import IP_KEY
from hses_genesis.utils.enum_objects import EParameterKey, EParameterType, EPacketDecision
from hses_genesis.utils.constants import FULL_RANGES, WILDCARD, PROTOCOLS

def device_id_to_ip(G, node_id):
    return int(ip_address(G.nodes[node_id][IP_KEY]))

def is_default_rule(rule):
    _, conditions, _ = rule
    return all(conditions[i] == FULL_RANGES[EParameterType.from_parameter_key(k)] for i, k in enumerate(EParameterKey))

def prettify_parameter_str(start : int, end : int, parameter_type : EParameterType):
    first, last = FULL_RANGES[parameter_type]
    if start == first and end == last:
        return WILDCARD

    s_value = str(ip_address(start)) if parameter_type == EParameterType.IP else str(start)
    e_value = str(ip_address(end)) if parameter_type == EParameterType.IP else str(end)

    if s_value == e_value:
        return s_value
    
    return f'{s_value}:{e_value}'

def genesis_entry_to_rule(G, data, action : EPacketDecision):
    output = []
    for i, key in enumerate(EParameterKey):
        if i < 2:
            value = device_id_to_ip(G, data[key.value])
        elif i == 2:
            value = PROTOCOLS[data[key.value].lower()]
        else:
            value = int(data[key.value])

        output += [(value, value)]
    return 'INPUT', tuple(output), action

def rule_to_str(rule : tuple):
    chain, conditions, action = rule
    return ' '.join([f'-A {chain}'] + [f'-{p.value} {prettify_parameter_str(conditions[i][0], conditions[i][1], EParameterType.from_parameter_key(p))}' for i, p in enumerate(EParameterKey)] + [f'-j {action.name}'])

RUNTIME_MEASUREMENTS = {}

def measure_runtime(func):
    def wrapper(*args, **kwargs):
        start_time = time()
        try:
            result = func(*args, **kwargs)
        except Exception as e:
            raise e
        finally:
            end_time = time()
            runtime = end_time - start_time
            
            global RUNTIME_MEASUREMENTS
            if func.__name__ not in RUNTIME_MEASUREMENTS.keys():
                RUNTIME_MEASUREMENTS[func.__name__] = runtime
            else:
                RUNTIME_MEASUREMENTS[func.__name__] += runtime

        return result
    return wrapper

def reset_runtime_measurements():
    global RUNTIME_MEASUREMENTS
    RUNTIME_MEASUREMENTS = {}

def get_runtime_measurements():
    global RUNTIME_MEASUREMENTS
    return RUNTIME_MEASUREMENTS

def generate_full_range_rule(chain : str = 'INPUT', action : EPacketDecision = EPacketDecision.DROP):
    return (chain, tuple([FULL_RANGES[EParameterType.from_parameter_key(key)] for key in EParameterKey]), action)