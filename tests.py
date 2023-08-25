from test_support import *
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

def seq_test(probes):
    data = extract_gcd(probes)
    gcd = gcd_test(data["sg_syn"])
    isr = isr_test(data["sg_syn"])
    sp = sp_test(data["sg_syn"], gcd)
    
    ti = ti_test(data["sg_id"])
    ci = ci_test(data["t_closed_id"])
    ii = ii_test(data["ie_id"])
    ss = ss_test(data["ie_id"], data["t_id"], ii, ti)
    ts = ts_test(data["sg_ts"])
    return {"gcd":gcd, "isr":isr, "sp":sp, "ti":ti, "ci":ci, "ii":ii, "ss":ss, "ts":ts}