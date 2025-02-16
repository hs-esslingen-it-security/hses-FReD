

from copy import copy
from hses_genesis.utils.enum_objects import EPacketDecision, EParameterKey
from hses_fred.decorrelate.enums import EParameterRelation, ERuleRelation
from hses_fred.distribute.ruleset import compress_ruleset, connect_values, join_rules

def test_join_I():
    a = 'TEST', ((1,4), (3,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
    b = 'TEST', ((3,4), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP
    c = 'TEST', ((1,2), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP

    print(join_rules(a, b))
    print(join_rules(a, c))
    print(join_rules(b, c))

    print(join_rules(join_rules(b, c)[0], a))

def test_compress_II():
        c = 'TEST', ((1,4), (3,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((3,4), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        a = 'TEST', ((1,2), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP

        ruleset, _ = compress_ruleset([a, b, c])

        c = 'TEST', ((1,4), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        print(ruleset)
        print(c in ruleset)
    
def test_compress_III():
    c = 'TEST', ((1,4), (3,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
    b = 'TEST', ((3,4), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP
    a = 'TEST', ((1,2), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP

    ruleset, _ = compress_ruleset([c, b, a])

    c = 'TEST', ((1,4), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
    
    print(ruleset)
    print(c in ruleset)

test_compress_II()
test_compress_III()
test_join_I()