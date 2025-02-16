from enum import Enum
from hses_genesis.utils.enum_objects import EParameterKey

class EParameterRelation(Enum):
    EQUAL = 0 # a == b
    SUPERSET = 1 # a > b
    SUBSET = 2 # a < b
    DISJOINT = 3
    CORRELATED = 4

    @staticmethod
    def from_parameter_values(a, b):
        """
        Return SUPERSET wenn a superset von b ist

        Return SUBSET wenn a subset von b ist
        """
        if a == b:
            return EParameterRelation.EQUAL

        try:
            if a[0] == b[0] and a[1] == b[1]:
                return EParameterRelation.EQUAL
            elif (a[0] <= b[0] and b[1] < a[1]) or (a[0] < b[0] and b[1] <= a[1]):
                return EParameterRelation.SUPERSET
            elif (b[0] <= a[0] and a[1] < b[1]) or (b[0] < a[0] and a[1] <= b[1]):
                return EParameterRelation.SUBSET
            elif a[1] < b[0] or b[1] < a[0]:
                return EParameterRelation.DISJOINT
            else:
                return EParameterRelation.CORRELATED
        except Exception as e:
            print(a, b)
            raise e


class ELeftoverReason(Enum):
    NoPath = 0,
    NoCovers = 1,
    ACLOverflow = 2
        
class ERuleRelation(Enum):
    COMPLETELY_DISJOINT = 0
    EXACTLY_MATCHING = 1 # a == b
    INCLUSIVELY_MATCHING_SUPER = 2 # a > b
    INCLUSIVELY_MATCHING_SUB = 3 # a < b
    PARTIALLY_DISJOINT = 4
    CORRELATED = 5

    @staticmethod
    def from_parameter_relations(parameter_relation : list[EParameterRelation]):
        """
        Genutze Definitionen von Al-Shaer et al.: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=4623689
        """
        if all(relation == EParameterRelation.EQUAL for relation in parameter_relation):
            return ERuleRelation.EXACTLY_MATCHING

        if all(relation == EParameterRelation.DISJOINT for relation in parameter_relation):
            return ERuleRelation.COMPLETELY_DISJOINT
        
        """
        Not covered by AL-Shaer et al...
        """
        if any(relation == EParameterRelation.DISJOINT for relation in parameter_relation):
            return ERuleRelation.PARTIALLY_DISJOINT
        
        if all(relation in [EParameterRelation.EQUAL, EParameterRelation.SUPERSET] for relation in parameter_relation):
            return ERuleRelation.INCLUSIVELY_MATCHING_SUPER
        
        if all(relation in [EParameterRelation.EQUAL, EParameterRelation.SUBSET] for relation in parameter_relation):
            return ERuleRelation.INCLUSIVELY_MATCHING_SUB
        
        if any(relation == EParameterRelation.DISJOINT in [EParameterRelation.SUPERSET, EParameterRelation.SUBSET, EParameterRelation.EQUAL] for relation in parameter_relation) and any(relation not in [EParameterRelation.SUPERSET, EParameterRelation.SUBSET, EParameterRelation.EQUAL] for relation in parameter_relation):
            return ERuleRelation.PARTIALLY_DISJOINT
        
        return ERuleRelation.CORRELATED
        
    @staticmethod
    def from_rules(a : tuple, b : tuple):
        (_, a_conditions, _), (_, b_conditions, _) = a, b
        p_relations = [EParameterRelation.from_parameter_values(a_conditions[i], b_conditions[i]) for i, _ in enumerate(EParameterKey)]
        return ERuleRelation.from_parameter_relations(p_relations)