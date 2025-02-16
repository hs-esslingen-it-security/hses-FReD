from hses_fred.decorrelate.match_condition import of_rules as decorrelate_match_conditions
from hses_fred.decorrelate.enums import ERuleRelation

def from_another(a : tuple, b : tuple, given_relation = None):
    relation = ERuleRelation.from_rules(a, b) if given_relation == None else given_relation
    if relation in [ERuleRelation.COMPLETELY_DISJOINT, ERuleRelation.PARTIALLY_DISJOINT]:
        return [b]
    elif relation in [ERuleRelation.EXACTLY_MATCHING, ERuleRelation.INCLUSIVELY_MATCHING_SUPER]:
        return []
    
    # relation in [ERuleRelation.CORRELATED, ERuleRelation.INCLUSIVELY_MATCHING_SUB]:
    (b_chain, _, b_action) = b
    return [(b_chain, conditions, b_action) for conditions in decorrelate_match_conditions(a, b)]