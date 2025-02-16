from enum import Enum
        
class EFirewallSelectionStrategy(Enum):
    PLACE_EARLY = 0
    MINIMIZE_GLOBAL_RULESET = 1
    HYBRID = 2

    def from_args_key(key : str):
        if key == 'm':
            return EFirewallSelectionStrategy.MINIMIZE_GLOBAL_RULESET
        elif key == 'e':
            return EFirewallSelectionStrategy.PLACE_EARLY
        else:
            return EFirewallSelectionStrategy.HYBRID
        
    def __str__(self) -> str:
        return self.name