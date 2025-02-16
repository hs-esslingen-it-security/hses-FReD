RULESET_KEY = 'ruleset'

ROLE_KEY = 'role'

SERVICES_KEY = 'services'

SUBNET_KEY = 'subnet'

DEFAULT_ACTION_KEY = 'default_action'

IP_KEY = 'ip'

MAX_ACL_SIZE = 128

BASE_FOLDER_KEY = '00_base'

DECORRELATED_FOLDER_KEY = '01_sorted'

DISTRIBUTED_FOLDER_KEY = '02_drop_only_distributed'

WHITELISTED_FOLDER_KEY = '03_accept_only_distributed'

RESULT_FOLDER_KEY = 'results'

RULESET_FOLDER_KEY = 'rulesets'

IPTABLES_FOLDER_KEY = 'iptables'

LOG_FOLDER_KEY = 'logging'

GRAPH_FOLDER_KEY = 'graphs'

PACKET_FILE = 'packets.csv'

PACKET_TRACE_FILE = 'packet_traces.csv'

GRAPH_FILE = 'graph.graphml'

MEASUREMENT_HEADERS = [
    'run_label',
    'packet',
    'path_index',
    'timestamp',
    'current_location',
    'current_location_ip',
    'decision',
    'introduced_delay',
    'transition_delay',
    'reason',
    'expected_endresult',
    'hitcount'
]