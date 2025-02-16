from ipaddress import ip_address
from itertools import product
from random import Random
from networkx import Graph, all_simple_paths
from hses_genesis.utils.enum_objects import EDeviceRole, EParameterType, EPacketDecision, EService, EParameterKey
from hses_genesis.utils.constants import PROTOCOLS
from json import dumps, loads
from hses_fred.utils.constants import IP_KEY, ROLE_KEY, SERVICES_KEY
from copy import deepcopy

class Rule():
    WILDCARD_MAP = {
        's' : (ip_address('0.0.0.1'), ip_address('255.255.255.255')),
        'd' : (ip_address('0.0.0.1'), ip_address('255.255.255.255')),
        'sport' : (0, 65535, EParameterType.NUMBER),
        'dport' : (0, 65535, EParameterType.NUMBER),
    }

    def __init__(self, chain_name = 'test', conditions = None, action = EPacketDecision.ACCEPT):
        self.__chain_name : str = chain_name
        self.__conditions = conditions if conditions != None else {}
        self.action : EPacketDecision = action
        self.__priority : int = 0

    def __str__(self) -> str:
        rule_conponents = [f'-A {self.__chain_name}']
        for param in ['s', 'd']:
            if param not in self.__conditions.keys():
                rule_conponents.append(f'-{param} *')
                continue
            value = str(self.__conditions[param])
            if value != Rule.WILDCARD_MAP[param]:
                rule_conponents.append(f'-{param} {value}')
        rule_conponents.append(f'-j {self.action.name}')
        return ' '.join(rule_conponents)

    def getChain(self):
        return self.__chain_name

    def setChain(self, chain_name : str):
        self.__chain_name = chain_name

    def setConditions(self, conditions):
        self.__conditions = conditions

    def getConditions(self):
        return self.__conditions

    def setChain(self, params):
        self.__conditions = params

    def setPriority(self, prio : int):
        self.__priority = prio

    def getPriority(self):
        return self.__priority
    
    def get(self, key):
        return self.__conditions[key] if key in self.__conditions.keys() else Rule.WILDCARD_MAP[key]
    
    def set(self, key : str, value : str):
        self.__conditions[key] = value

class Packet():
    def __init__(self, index : int, hit_count = 1, expected_decision = EPacketDecision.ACCEPT, conditions = None) -> None:
        self.index = index
        self.conditions = {} if conditions == None else conditions
        self.hit_count = hit_count
        self.expected_decision = expected_decision
        pass

    def __eq__(self, other: object) -> bool:
        if isinstance(other, self.__class__):
            if not all((p in self.conditions.keys() and p in other.conditions.keys()) or (p not in self.conditions.keys() and p not in other.conditions.keys()) for p in EParameterKey):
                return False
            return all([self.conditions[key] == other.conditions[key] for key in self.conditions.keys()]) and all([self.conditions[key] == other.conditions[key] for key in other.conditions.keys()])
        else:
            return False

    def process_condition_values(self, topology, replace = True):
        conditions = self.conditions
        if not replace:
            conditions = self.conditions.copy()

        for key in EParameterKey:
            if key in conditions.keys() and isinstance(conditions[key], str):
                value : str = conditions[key]
                if value.isdigit():
                    conditions[key] = int(value)
                elif key == EParameterKey.PROTOCOL:
                    conditions[key] = PROTOCOLS[conditions[key].lower()]
                else:
                    conditions[key] = int(ip_address(topology.nodes[conditions[key]][IP_KEY]))
        if replace:
            self.conditions = conditions
            return self
        
        clone = deepcopy(self)
        clone.conditions = conditions
        return clone

    @staticmethod
    def from_pointed_rule(rule : tuple, index = 0, hit_count = 1):
        _, conditions, action = rule
        packet = Packet(index, hit_count, action)
        for i, key in enumerate(EParameterKey):
            packet.conditions[key] = conditions[i][0]
        return packet

    @staticmethod
    def __get_matching_protocols__(protocol_range, port_range, services):
        protocol_start, protocol_end = protocol_range
        port_start, port_end = port_range

        matching_services = []
        for service in services:
            valid_protocol_key = [protocol_key for protocol_key in service.value[0] if protocol_start <= PROTOCOLS[protocol_key.lower()] and PROTOCOLS[protocol_key.lower()] <= protocol_end]
            if len(valid_protocol_key) == 0:
                continue

            valid_ports = [port_number for port_number in service.value[1] if port_start <= port_number and port_number <= port_end]
            if len(valid_protocol_key) != 0:
                matching_services += product(valid_protocol_key, valid_ports)

        return matching_services

    @staticmethod
    def __is_valid_choice__(node_data, ip_range, protocol_range, port_range):
        
        is_end_device = node_data[ROLE_KEY] in EDeviceRole.configurables()
        if not is_end_device:
            return False
        
        ip_start, ip_end = ip_range
        device_ip = int(ip_address(node_data[IP_KEY]))
        is_in_ip_range = ip_start <= device_ip and device_ip <= ip_end
        if not is_in_ip_range:
            return False
        
        is_in_protocol_range = len(Packet.__get_matching_protocols__(protocol_range, port_range, node_data[SERVICES_KEY])) > 0
        return is_in_protocol_range

    @staticmethod
    def from_rule(G: Graph, rule : tuple, random : Random, index = 0, hit_count = 1):
        _, (src, dst, p, sport, dport), action = rule
        packet = None
        src_choices = [(node, data) for node, data in list(G.nodes(data=True)) if Packet.__is_valid_choice__(data, src, p, sport)]

        if len(src_choices) == 0:
            return None
        alice, alice_data = random.choice(src_choices)

        overlapping_protocols = [a for a, b in product(Packet.__get_matching_protocols__(p, sport, alice_data[SERVICES_KEY]), Packet.__get_matching_protocols__(p, dport, alice_data[SERVICES_KEY])) if a == b]

        for protocol_key, port_number in overlapping_protocols:
            protocol_number = PROTOCOLS[protocol_key.lower()]
            dst_choices = [(node, data) for node, data in list(G.nodes(data=True)) if Packet.__is_valid_choice__(data, dst, (protocol_number, protocol_number), dport)]

            if len(dst_choices) == 0:
                return None

            random.shuffle(dst_choices)
            for bob, bob_data in dst_choices:
                shared_services = [a for a, b in product(alice_data[SERVICES_KEY], bob_data[SERVICES_KEY]) if a == b and protocol_key in a.value[0]]
                if len(shared_services) == 0:
                    continue

                all_paths_cross_routers = all(any(EDeviceRole.from_device_id(device) == EDeviceRole.ROUTER for device in path) for path in list(all_simple_paths(G, alice, bob)))
                if not all_paths_cross_routers:
                    continue

                packet = Packet(index=index, hit_count=hit_count, expected_decision=action, conditions = {
                    EParameterKey.SRC : alice,
                    EParameterKey.DST : bob,
                    EParameterKey.PROTOCOL : PROTOCOLS[protocol_key.lower()],
                    EParameterKey.SRC_PORT : port_number,
                    EParameterKey.DST_PORT : port_number
                })
                break

            if packet:
                break
        return packet

    def __str__(self) -> str:
        src = self.conditions[EParameterKey.SRC]
        if not isinstance(src, str):
            src = ip_address(src)
        dst = self.conditions[EParameterKey.DST]
        if not isinstance(dst, str):
            dst = ip_address(dst)

        sport = self.conditions[EParameterKey.SRC_PORT] if EParameterKey.SRC_PORT in self.conditions.keys() else "?"
        dport = self.conditions[EParameterKey.DST_PORT] if EParameterKey.DST_PORT in self.conditions.keys() else "?"
        protocol = f"[{self.conditions[EParameterKey.PROTOCOL]}]" if EParameterKey.PROTOCOL in self.conditions.keys() else ""
        return f'Packet #{self.index} [{self.hit_count}]: {src} ({sport}) -{protocol}-> {dst} ({dport}) [{self.expected_decision}]'
    
    def to_writer_dict(self) -> tuple:
        return {
            'index' : self.index,
            'conditions' : dumps({key.name: value for key, value in self.conditions.items()}),
            'hit_count' : self.hit_count,
            'expected_decision' : self.expected_decision
        }
    
    @staticmethod
    def from_writer_entry(input):
        return Packet(int(input['index']), int(input['hit_count']), EPacketDecision.from_str(input['expected_decision']), {EParameterKey.from_str(key): value for key, value in loads(input['conditions']).items()})
    
    @staticmethod
    def from_genesis_entry(input, index, hit_count, action = EPacketDecision.ACCEPT):
        return Packet(index, hit_count, action, { key :  int(input[key.value]) if input[key.value].isdigit() else input[key.value] for key in EParameterKey })

class PathElement():
    def __init__(self, element_id, element_ip, timestamp, decision, introduced_delay, transition_delay, reasoning, path = 0) -> None:
        self.location = element_id
        self.location_ip = element_ip
        self.timestamp = timestamp
        self.decision = decision
        self.introduced_delay = introduced_delay
        self.transition_delay = transition_delay
        self.reasoning = reasoning
        self.path = path