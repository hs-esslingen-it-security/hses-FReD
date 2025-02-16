from ipaddress import ip_address, ip_network
from re import compile
from hses_genesis.utils.enum_objects import EParameterType

IP_ADDRESS_MATCHER = compile(f'(?P<address>([0-9a-fA-F]+[\.:])+([0-9a-fA-F]+)?)')

def parse_paramter_endpoints(value):
    """
    Gibt die beiden Endpunkte (int oder IP) eines Bereiches bzw. eines Netzwerkes jeweils als int zurück.
    Handelt es sich um keine Range sondern um einen einzelnen Wert wird dieser gedoppelt zurückgegeben (als Start- und Endpunkt).
    """
    s_value = str(value)
    if '/' in s_value:
        network = ip_network(s_value, False)
        return int(network[1]), int(network[-1])

    for seperator in [':']:#, '-']:
        if seperator in s_value:
            splits = s_value.split(seperator)
            start, end = splits[0], splits[-1]
            if not start.isdigit():
                start, end = ip_address(start), ip_address(end)
            start, end = int(start), int(end)
            if start > end:
                raise Exception(f'Endpoints out of bounds: {s_value}')
            return start, end
        
    global IP_ADDRESS_MATCHER
    match = IP_ADDRESS_MATCHER.match(s_value)
    if match:
        address = ip_address(match.groupdict()['address'])
        return int(address), int(address)
    
    if s_value.isdigit():
        return int(value), int(value)
    
    return value, value

def map_to_string(parameter_flag : str, start, end):
    start_int, _ = parse_paramter_endpoints(start)
    end_int, _ = parse_paramter_endpoints(end)
    
    parameter_type = EParameterType.from_parameter_key(parameter_flag)

    if parameter_type == EParameterType.NUMBER:
        return f'{start_int}:{end_int}' if start_int != end_int else str(start_int)
    elif parameter_type == EParameterType.IP:
        if start_int != end_int:
            if start_int == int(ip_network(f'{str(ip_address(start_int))}/24', False).network_address):
                start_int += 1
            if end_int == int(ip_network(f'{str(ip_address(end_int))}/24', False).network_address):
                end_int -= 1
            if start_int == end_int:
                return str(ip_address(start_int))
            elif end_int < start_int:
                raise Exception('INVALID IP-RANGE')
            else:
                return f'{ip_address(start_int)}:{ip_address(end_int)}'
        else:
            return str(ip_address(start_int))

    return ','.join([start, end])

def to_subnet(ip : str):
    # if not isinstance(address, str):
    if ':' in ip:
        return ip
    
    tmp_ip = ip.split('#')[0] if '#' in ip else ip

    adr = f'{tmp_ip}/24' if '/24' not in tmp_ip else tmp_ip
    return str(ip_network(adr, False))