from argparse import ArgumentParser
from itertools import product
from os import listdir
from os.path import isdir, join, exists

from hses_fred.utils.constants import RESULT_FOLDER_KEY

parser = ArgumentParser()
parser.add_argument('-i', '--resource_location')
parser.add_argument('-o', '--output_location')
args = parser.parse_args()

if not (args.resource_location and args.output_location):
    raise Exception('You need to provide a resource AND an output location.')

output_locations = [join(args.output_location, output_id) for output_id in listdir(args.output_location) if isdir(join(args.output_location, output_id)) and exists(join(args.output_location, output_id, 'config.json'))]
resource_locations = [join(args.resource_location, resource_id) for resource_id in listdir(args.resource_location) if isdir(join(args.resource_location, resource_id)) and exists(join(args.resource_location, resource_id, 'config.json'))]

already_added = []

for output_location, resource_location in product(output_locations, resource_locations):
    with open(join(output_location, 'config.json'), 'r') as output_config, open(join(resource_location, 'config.json'), 'r') as resource_config:
        if output_config.read() != resource_config.read():
            continue

    for run_id in listdir(output_location):
        run_location = join(output_location, run_id)
        if not isdir(run_location):
            continue

        completed_run_indication_file = join(run_location, '02_distributed', RESULT_FOLDER_KEY, 'packet_traces.csv')
        resource_run_location = join(resource_location, run_id)
        footprint_location = join(resource_run_location, '.fred-footprint')
        if exists(completed_run_indication_file) and exists(resource_run_location) and not footprint_location in already_added:
            print(f'{len(already_added) + 1}.', f' insert footprint into {resource_run_location}.')
            open(footprint_location, 'w').close()
            already_added.append(footprint_location)