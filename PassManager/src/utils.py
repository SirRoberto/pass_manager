from math import log2
from itertools import compress

alert_types = ["alert info", "alert success", "alert warning", "alert error"]

def entropy(d):
    stat = {}
    for c in d:
        m = c
        if m in stat:
            stat[m] +=1
        else:
            stat[m] = 1
    H = 0.0
    for i in stat.keys():
        pi = stat[i]/len(d)
        H -= pi*log2(pi)
    return H

def does_string_contain_only_allowed_chars(string, allowed):
    b = [c not in allowed for c in string]
    c = ''
    if any(b):
        c = list(compress(string, b))
        return False, c
    return True, c