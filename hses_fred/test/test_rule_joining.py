import unittest
from hses_genesis.utils.enum_objects import EPacketDecision
from hses_fred.distribute.ruleset import join_rules

class TestJoining(unittest.TestCase):
    
    def test_join_src(self):
        a = 'TEST', ((1,2), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((3,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        ruleset = join_rules(a, b)

        c = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        self.assertTrue(len(ruleset) == 1)
        self.assertIn(c, ruleset)
    
    def test_join_dst(self):
        a = 'TEST', ((1,8), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((1,8), (3,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        ruleset = join_rules(a, b)

        c = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        self.assertTrue(len(ruleset) == 1)
        self.assertIn(c, ruleset)
    
    def test_join_p(self):
        a = 'TEST', ((1,8), (1,8), (1,2), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((1,8), (1,8), (3,8), (1,8), (1,8)), EPacketDecision.DROP
        ruleset = join_rules(a, b)

        c = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        self.assertTrue(len(ruleset) == 1)
        self.assertIn(c, ruleset)
    
    def test_join_sport(self):
        a = 'TEST', ((1,8), (1,8), (1,8), (1,2), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((1,8), (1,8), (1,8), (3,8), (1,8)), EPacketDecision.DROP
        ruleset = join_rules(a, b)

        c = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        self.assertTrue(len(ruleset) == 1)
        self.assertIn(c, ruleset)
    
    def test_join_dport(self):
        a = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,2)), EPacketDecision.DROP
        b = 'TEST', ((1,8), (1,8), (1,8), (1,8), (3,8)), EPacketDecision.DROP
        ruleset = join_rules(a, b)

        c = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        self.assertTrue(len(ruleset) == 1)
        self.assertIn(c, ruleset)
    
    def test_join_subset_I(self):
        a = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((1,4), (1,4), (1,4), (1,4), (1,4)), EPacketDecision.DROP
        ruleset = join_rules(a, b)

        self.assertTrue(len(ruleset) == 1)
        self.assertIn(a, ruleset)
    
    def test_join_subset_II(self):
        a = 'TEST', ((1,4), (1,4), (1,4), (1,4), (1,4)), EPacketDecision.DROP
        b = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        ruleset = join_rules(a, b)

        self.assertTrue(len(ruleset) == 1)
        self.assertIn(b, ruleset)

    def test_join_remain(self):
        a = 'TEST', ((1,2), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((3,3), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        ruleset = join_rules(a, b)

        # self.assertTrue(len(ruleset) == 2)
        for rule in [a, b]:
            self.assertIn(rule, ruleset)

if __name__ == '__main__':
    unittest.main()