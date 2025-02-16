import unittest
from hses_genesis.utils.enum_objects import EPacketDecision

from hses_fred.distribute.ruleset import compress_ruleset

class TestJoining(unittest.TestCase):
    
    def test_compress_I(self):
        a = 'TEST', ((1,2), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((3,4), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        c = 'TEST', ((5,6), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        d = 'TEST', ((7,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        
        ruleset, _ = compress_ruleset([a, b, c, d])

        c = 'TEST', ((1,8), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP

        self.assertTrue(len(ruleset) == 1)
        self.assertIn(c, ruleset)
    
    def test_compress_II(self):
        c = 'TEST', ((1,4), (3,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((3,4), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        a = 'TEST', ((1,2), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP

        ruleset, _ = compress_ruleset([a, b, c])

        c = 'TEST', ((1,4), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP

        self.assertTrue(len(ruleset) == 1)
        self.assertIn(c, ruleset)
    
    def test_compress_III(self):
        c = 'TEST', ((1,4), (3,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((3,4), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        a = 'TEST', ((1,2), (1,2), (1,8), (1,8), (1,8)), EPacketDecision.DROP

        ruleset, _ = compress_ruleset([c, b, a])

        c = 'TEST', ((1,4), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP

        self.assertTrue(len(ruleset) == 1)
        self.assertIn(c, ruleset)
    
    def test_compress_III(self):
        a = 'TEST', ((1,2), (1,8), (1,8), (1,8), (1,8)), EPacketDecision.DROP
        b = 'TEST', ((3,3), (1,4), (1,8), (1,8), (1,8)), EPacketDecision.DROP

        ruleset, _ = compress_ruleset([a, b])

        # self.assertTrue(len(ruleset) == 2)
        for r in [a, b]:
            self.assertIn(r, ruleset)

if __name__ == '__main__':
    unittest.main()