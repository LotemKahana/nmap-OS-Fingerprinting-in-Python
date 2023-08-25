from math import gcd, log2, isclose
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

def ti_test(id_list):
    id_list = filter_none_probes(id_list)
    if len(id_list) < 3:
        return
    
    return sequence_test(id_list)

def ci_test(id_list):
    id_list = filter_none_probes(id_list)
    if len(id_list) < 2:
        return
    
    return sequence_test(id_list)

def ii_test(id_list):
    id_list = filter_none_probes(id_list)
    if len(id_list) < 2:
        return
    
    return sequence_test(id_list)

def ss_test(icmp_ids, tcp_ids, ii, ti):

    if ii in ['RI', 'BI', 'I'] and ii == ti:
        # Calculate avg based on the TCP IDs
        avg = (tcp_ids[-1] - tcp_ids[0]) // (len(tcp_ids) - 1)
        
        if icmp_ids[0] < (tcp_ids[-1] + 3 * avg):
            return 'S'
        else:
            return 'O'
    else:
        return

def ts_test(tsval_responses, time_elapsed=0.1):
    tsval_diffs = [tsval_responses[i] - tsval_responses[i-1] for i in range(1, len(tsval_responses)) if tsval_responses[i] is not None and tsval_responses[i - 1] is not None]
    time_intervals = [time_elapsed] * (len(tsval_responses) - 1)
    tsval_rates = [diff / time_interval for diff, time_interval in zip(tsval_diffs, time_intervals)]
    average_rate = sum(tsval_rates) / len(tsval_rates)
    
    if any(tsval == 0 for tsval in tsval_responses):
        ts_result = '0'
    elif any(isclose(average_rate, r, rel_tol=1e-2) for r in [2, 100, 200]):
        ts_result = '1' if isclose(average_rate, 2, rel_tol=1e-2) else '7' if isclose(average_rate, 100, rel_tol=1e-2) else '8'
    else:
        ts_result = str(round(log2(average_rate)))
    
    return ts_result


def calculate_diffs(numbers):
    results = []
    for i in range(len(numbers) - 1):
        if all((numbers[i], numbers[i + 1])):
            results.append((numbers[i + 1] - numbers[i]) & 0xFFFFFFFF)
    return results

def calculate_rates(numbers, time):
    diffs = calculate_diffs(numbers)
    return [diff / time for diff in diffs]

def filter_none_probes(unfiltered_list):
    return [element for element in unfiltered_list if element is not None]

def sequence_test(id_list):
    if all(id_num == 0 for id_num in id_list):
        return 'Z'
    
    if len(set(id_list)) == 1:
        return hex(id_list[0])
    
    diffs = []
    for i in range(len(id_list) - 1):
        diffs.append((id_list[i+1] - id_list[i]) & 0xffff)
    
    if (max(diffs) > 20000 and len(diffs) > 2): # mistake in nmap documantation "https://github.com/nmap/nmap/blob/master/osscan2.cc#L285C10-L285C10"
        return "RD"
    
    # Check if any difference between two consecutive IDs exceeds 1,000 and is not evenly divisible by 256
    if any(abs(id_list[i] - id_list[i + 1]) > 1000 and (id_list[i] - id_list[i + 1]) % 256 != 0 for i in range(len(id_list) - 1)):
        return 'RI'

    # Check if all differences are divisible by 256 and no greater than 5,120
    if all(diff % 256 == 0 and diff <= 5120 for diff in (id_list[i] - id_list[i + 1] for i in range(len(id_list) - 1))):
        return 'BI'

    # Check if all differences are less than ten
    if all(abs(id_list[i] - id_list[i + 1]) < 10 for i in range(len(id_list) - 1)):
        return 'I'

    # If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint
    return None