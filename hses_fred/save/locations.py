from os import getcwd, makedirs
from os.path import join
from datetime import datetime
from hses_fred.utils.constants import BASE_FOLDER_KEY, RESULT_FOLDER_KEY, LOG_FOLDER_KEY, DISTRIBUTED_FOLDER_KEY, DECORRELATED_FOLDER_KEY, IPTABLES_FOLDER_KEY, RULESET_FOLDER_KEY, GRAPH_FOLDER_KEY, WHITELISTED_FOLDER_KEY

def generate_output_location(output_location = join(getcwd(), 'output'), config_name = 'default_config'):
    output_dir = join(output_location, config_name, datetime.now().strftime('%y-%m-%d-%H-%M-%S'))
    makedirs(output_dir, exist_ok=True)
    return output_dir

def generate_run_location(output_dir, run_id, to_zimpl : bool = False, debugging = True):
    run_dir = join(output_dir, run_id)
    for i, subfolter_name in enumerate([BASE_FOLDER_KEY, DECORRELATED_FOLDER_KEY, DISTRIBUTED_FOLDER_KEY, WHITELISTED_FOLDER_KEY]):
        for folder_key in [RESULT_FOLDER_KEY, RULESET_FOLDER_KEY, GRAPH_FOLDER_KEY]:
            sub_location = join(run_dir, subfolter_name, folder_key)
            makedirs(sub_location, exist_ok=True)
        
        if i > 0 and debugging:
            makedirs(join(run_dir, subfolter_name, RULESET_FOLDER_KEY, LOG_FOLDER_KEY), exist_ok=True)
        
        makedirs(join(run_dir, subfolter_name, RULESET_FOLDER_KEY, IPTABLES_FOLDER_KEY), exist_ok=True)

        if to_zimpl:
            makedirs(join(sub_location, 'zimpl'), exist_ok=True)
    return run_dir

def generate_csv_file_name(output_dir, file_name):
    csv_output_dir = join(output_dir, RESULT_FOLDER_KEY)
    makedirs(csv_output_dir, exist_ok=True)
    return join(csv_output_dir, f'{file_name}.csv')

def generate_debug_file_name(output_dir):
    debug_output_dir = join(output_dir, 'md')
    makedirs(debug_output_dir, exist_ok=True)
    return join(debug_output_dir, f'debug.md')