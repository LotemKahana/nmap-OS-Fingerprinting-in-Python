from test_support import *
from math import gcd, log2
from statistics import stdev

def gcd_test(sg_syn):
    diffs = calculate_diffs(sg_syn)
    return gcd(*diffs)

def isr_test(sg_syn):
    seq_rates = calculate_rates(sg_syn, 0.1)
    average_rate = sum(seq_rates) / len(seq_rates)
    if average_rate < 1:
        isr = 0
    else:
        isr = round(8 * log2(average_rate))
    return isr

def sp_test(sg_syn, gcd_result):
    seq_rates = calculate_rates(sg_syn, 0.1)
    if len(seq_rates) >= 4:
    # Divide seq_rates by GCD if GCD is greater than nine
        if gcd_result > 9:
            seq_rates = [rate / gcd_result for rate in seq_rates]

        # Calculate the standard deviation of the seq_rates array
        standard_deviation = stdev(seq_rates)

        # Calculate the TCP ISN Sequence Predictability Index (SP)
        if standard_deviation <= 1:
            sp = 0
        else:
            sp = round(8 * log2(standard_deviation))
    else:
        sp = None
    return sp