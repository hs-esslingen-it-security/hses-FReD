import unittest
from hses_fred.decorrelate.ruleset import inplace as decorrelate_rules
from hses_genesis.utils.enum_objects import EPacketDecision
from hses_fred.objects.simulation import Packet
from hses_fred.simulate.traffic import rule_packet_match

class TestDecorrelation(unittest.TestCase):
    def test_decorrelaten_coverage(self):
        a = 'TEST', ((1,1), (1,1), (1,1), (1,1), (1,1)), EPacketDecision.ACCEPT
        b = 'TEST', ((3,3), (3,3), (1,1), (1,1), (1,1)), EPacketDecision.ACCEPT
        c = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP

        ruleset, _ = decorrelate_rules([a,b,c], depth=1)

        for s in range(1,8):
            for d in range(1,8):
                for p in range(1,8):
                    for sport in range(1,8):
                        for dport in range(1,8):
                            packet = Packet.from_pointed_rule(('test', ((s,s), (d,d), (p,p), (sport,sport), (dport, dport)), EPacketDecision.DROP))
                            matching_rules = [rule for rule in ruleset if rule_packet_match(rule, packet)]
                            self.assertEqual(len(matching_rules), 1)
                            expected_action = EPacketDecision.ACCEPT if matching_rules[0] in [a, b] else EPacketDecision.DROP
                            self.assertEqual(expected_action, matching_rules[0][2])

    def test_decorrelation_of_superset_I(self):
        a = 'TEST', ((1,1), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((1,1), (1,5), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        ruleset, _ = decorrelate_rules([a, b], depth=1)
        
        c = 'TEST', ((1,1), (5,5), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        self.assertTrue(len(ruleset) == 2)
        for rule in [a, c]:
            self.assertIn(rule, ruleset)

    def test_decorrelation_of_superset_II(self):
        a = 'TEST', ((1,1), (2,5), (1,8), (1,8), (1,8)), EPacketDecision.ACCEPT
        b = 'TEST', ((1,1), (1,5), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        ruleset, _ = decorrelate_rules([a, b], depth=1)
        
        c = 'TEST', ((1,1), (1,1), (1,8), (1,8), (1,8)), EPacketDecision.DROP

        self.assertTrue(len(ruleset) == 2)
        for rule in [a, c]:
            self.assertIn(rule, ruleset)
        
    def test_decorrelation_of_superset_II(self):
        a = 'TEST', ((1,1), (2,4), (1,8), (1,8), (1,8)), EPacketDecision.ACCEPT
        b = 'TEST', ((1,1), (1,5), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        ruleset, _ = decorrelate_rules([a, b], depth=1)
        
        c = 'TEST', ((1,1), (1,1), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        d = 'TEST', ((1,1), (5,5), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        self.assertTrue(len(ruleset) == 3)
        for rule in [a, c, d]:
            self.assertIn(rule, ruleset)

    def test_decorrelation_of_subset_I(self):
        a = 'TEST', ((1,1), (1,5), (1,8), (1,8), (1,8)), EPacketDecision.ACCEPT
        b = 'TEST', ((1,1), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        ruleset, _ = decorrelate_rules([a, b], depth=1)
        
        self.assertTrue(len(ruleset) == 1)
        self.assertIn(a, ruleset)

    def test_decorrelation_of_subset_II(self):
        a = 'TEST', ((1,1), (1,5), (1,8), (1,8), (1,8)), EPacketDecision.ACCEPT
        b = 'TEST', ((1,1), (2,5), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        ruleset, _ = decorrelate_rules([a, b], depth=1)
        
        self.assertTrue(len(ruleset) == 1)
        self.assertIn(a, ruleset)

    def test_decorrelation_of_subset_III(self):
        a = 'TEST', ((1,1), (1,5), (1,8), (1,8), (1,8)), EPacketDecision.ACCEPT
        b = 'TEST', ((1,1), (2,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        ruleset, _ = decorrelate_rules([a, b], depth=1)
        
        self.assertTrue(len(ruleset) == 1)
        self.assertIn(a, ruleset)

    def test_decorrelation_of_correlated_I(self):
        a = 'TEST', ((1,4), (1,5), (1,8), (1,8), (1,8)), EPacketDecision.ACCEPT
        b = 'TEST', ((1,5), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        ruleset, _ = decorrelate_rules([a, b], depth=1)

        c = 'TEST', ((5,5), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        self.assertTrue(len(ruleset) == 2)
        for rule in [a, c]:
            self.assertIn(rule, ruleset)

    def test_decorrelation_of_correlated_II(self):
        a = 'TEST', ((1,4), (2,4), (1,8), (1,8), (1,8)), EPacketDecision.ACCEPT
        b = 'TEST', ((1,5), (1,5), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        ruleset, _ = decorrelate_rules([a, b], depth=1)

        c = 'TEST', ((5,5), (1,5), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        d = 'TEST', ((1,4), (1,1), (1,8), (1,8), (1,8)), EPacketDecision.DROP # (1,4) due to iterative decorrelation with c
        e = 'TEST', ((1,4), (5,5), (1,8), (1,8), (1,8)), EPacketDecision.DROP # (1,4) due to iterative decorrelation with c
        
        self.assertTrue(len(ruleset) == 4)
        for rule in [a, c, d, e]:
            self.assertIn(rule, ruleset)



if __name__ == '__main__':
    unittest.main()