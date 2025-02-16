from csv import writer
from os.path import join

from hses_fred.utils.functions import rule_to_str

def to_csv(leftovers, location):
    with open(join(location, 'leftovers.csv'), 'w', newline='') as f:
        w = writer(f, ['type', 'container', 'rule', 'reasoning'])
        w.writerow(['type', 'container', 'rule', 'reasoning'])
        for reason_type, container, rule, message in leftovers:
            w.writerow([reason_type.name, container, rule_to_str(rule), message])