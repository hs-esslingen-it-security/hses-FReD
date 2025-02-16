from hses_fred.decorrelate.enums import EParameterRelation
from hses_genesis.utils.enum_objects import EParameterKey
from copy import deepcopy, copy

def of_rules(rule_a : tuple, rule_b : tuple):
    """
    Aus Regel b werden alle Pakete entfernt, die eine Schnittmenge zu Regel a bilden.
    Hierfür werden alle Parameterwerte von b um die Parameterwerte von Regel a herum 'geschnitten'.
    Alle exakt gleichen und komplett unterschiedlichen Parameter bleiben gleich.
    Sind Parameterwerte teilweise gleich (existiert eine Schnittmenge) werden alle Werte von a.param aus b.param entfernt.
    """
    _, a_conditions, _ = rule_a
    _, b_conditions, _ = rule_b

    condition_collection = []

    for i, _ in enumerate(EParameterKey):
        a_value, b_value = a_conditions[i], b_conditions[i]
        parameter_relation = EParameterRelation.from_parameter_values(a_value, b_value)
        if parameter_relation in [EParameterRelation.EQUAL, EParameterRelation.SUPERSET]:
            continue
        for result in values(a_value, b_value, parameter_relation):
            new_conditions = list(deepcopy(b_conditions))
            new_conditions[i] = result
            new_conditions = tuple(new_conditions)
            if new_conditions != b_conditions:
                condition_collection.append(new_conditions)
    
    return condition_collection

def values(a : tuple, b : tuple, relation : EParameterRelation):
    if relation in [EParameterRelation.DISJOINT, EParameterRelation.EQUAL]:
        # correlated due to another parameter
        return [copy(b)]
    
    if relation == EParameterRelation.SUBSET:
        if a[0] == b[0]:
            output_element = ((a[1] + 1), b[1]) #, e.g., (1,4) x (1,5) -> (5,5)
            return [output_element]
        elif a[1] == b[1]:
            output_element = (b[0], (a[0] - 1)) #, e.g., (2,5) x (1,5) -> (1,1)
            return [output_element]
        else:
            pre, post = (b[0], (a[0] - 1)), ((a[1] + 1), b[1])
            return [pre, post]
    else: # relation == EParameterRelation.CORRELATED
        output = []
        if b[0] < a[0]:
            output += [(b[0], (a[0] - 1))]
        if a[1] < b[1]:
            output += [((a[1] + 1), b[1])]
        
        return output