from scapy.all import *
import math
import statistics
from tests import *
from send_probes import send_probes

dst_ip = '45.33.32.156'
open_port = 22
closed_port = 999



def extract_syn(packets):
    results = []
    for result in packets:
        if result is not None:
            results.append(result.seq)
        else:
            results.append(None)
    return results

def extract_ip_id(packets):
    results = []
    for result in packets:
        if result is not None:
            results.append(result.id)
        else:
            results.append(None)
    return results

def extract_time(packets):
    results = []
    for result in extract_tcp_options(packets):
        if result is not None:
            for option in result:
                if option[0] == "Timestamp":
                    results.append(option[1][0])
        else:
            results.append(None)
    return results

def extract_tcp_options(packets):
    results = []
    for result in packets:
        if result is not None:
            results.append(result.payload.options)
        else:
            results.append(None)
    return results

def extract_tcp_windows(packets):
    results = []
    for result in packets:
        if result is not None:
            results.append(result.window)
        else:
            results.append(None)
    return results

def extract_udp_response_ttl(packets):
    if packets[0] is None:
        return
    icmp_ttl = packets[0].ttl
    got_ttl = packets[0][ICMP].ttl
    return (icmp_ttl, got_ttl, packets[1])

def perform_id_sequence_test(test_type, id_list):

    # Filter out None values from the list
    id_list = [id_num for id_num in id_list if id_num is not None]

    if len(id_list) < 2:
        return None  # Not enough responses to perform the test

    # Check if all ID numbers are zero
    if all(id_num == 0 for id_num in id_list):
        return 'Z'

    # Check if the IP ID sequence ever increases by at least 20,000
    if test_type == 'CI':
        max_diff = max(id_list) - min(id_list)
        if max_diff >= 20000:
            return 'RD'

    # Check if all IP IDs are identical
    if len(set(id_list)) == 1:
        return hex(id_list[0])

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

def perform_ss_test(icmp_ids, tcp_ids, ii, ti):

    if ii in ['RI', 'BI', 'I'] and ii == ti:
        # Calculate avg based on the TCP IDs
        avg = (tcp_ids[-1] - tcp_ids[0]) // (len(tcp_ids) - 1)
        
        if icmp_ids[0] < (tcp_ids[-1] + 3 * avg):
            return 'S'
        else:
            return 'O'
    else:
        return

def calculate_ts_test(tsval_responses, time_elapsed=0.1):
    tsval_diffs = [tsval_responses[i] - tsval_responses[i-1] for i in range(1, len(tsval_responses)) if tsval_responses[i] is not None and tsval_responses[i - 1] is not None]
    time_intervals = [time_elapsed] * (len(tsval_responses) - 1)
    tsval_rates = [diff / time_interval for diff, time_interval in zip(tsval_diffs, time_intervals)]
    average_rate = sum(tsval_rates) / len(tsval_rates)
    
    if any(tsval == 0 for tsval in tsval_responses):
        ts_result = '0'
    elif any(math.isclose(average_rate, r, rel_tol=1e-2) for r in [2, 100, 200]):
        ts_result = '1' if math.isclose(average_rate, 2, rel_tol=1e-2) else '7' if math.isclose(average_rate, 100, rel_tol=1e-2) else '8'
    else:
        ts_result = str(round(math.log2(average_rate)))
    
    return ts_result

def generate_option_string(options):
    if options is None:
        return

    option_string = ""
    for option, argument in options:
        if option == 'EOL':
            option_string += 'L'
        elif option == 'NOP':
            option_string += 'N'
        elif option == 'MSS':
            option_string += 'M' + format(argument, 'X')
        elif option == 'WScale':
            option_string += 'W' + str(argument)
        elif option == 'Timestamp':
            tsval, tsecr = argument
            tsval_char = '1' if tsval != 0 else '0'
            tsecr_char = '1' if tsecr != 0 else '0'
            option_string += 'T' + tsval_char + tsecr_char
        elif option == 'SAckOK':
            option_string += 'S'
        else:
            raise
    return option_string

def perform_t_test(ttl, hops):
    return ttl + hops

def round_up_to_nearest(value, limit):
    next_power_of_2 = 2 ** math.ceil(math.log2(value))
    rounded_value = min(next_power_of_2, limit)
    return rounded_value

def perform_tg_test(ttl):
    return round_up_to_nearest(ttl, 255)

def main():
    
    responses = send_probes()
    sg_syn = extract_syn(responses["sg_responces"])
    sg_id = extract_ip_id(responses["sg_responces"])
    sg_ts = extract_time(responses["sg_responces"])
    sg_options = extract_tcp_options(responses["sg_responces"])
    sg_windows = extract_tcp_windows(responses["sg_responces"])
    u_ttl = extract_udp_response_ttl(responses["u_responses"])
    t_id = extract_ip_id(responses["t_responses"])
    t_closed_id = t_id[3:]
    ie_id = extract_ip_id(responses["ie_results"])


  
    gcd = gcd_test(sg_syn)
    isr = isr_test(sg_syn)
    sp = sp_test(sg_syn, gcd)
    
    ti = perform_id_sequence_test("TI", sg_id)
    ci = perform_id_sequence_test("CI", t_closed_id)
    ii = perform_id_sequence_test("II", ie_id)
    ss = perform_ss_test(ie_id, t_id, ii, ti)
    ts = calculate_ts_test(sg_ts)
    OPS = [generate_option_string(option) for option in sg_options]
    hops = u_ttl[0] - u_ttl[1] # number of hops away (ttl)
    print(gcd, isr, sp, "\n", ti, ci, ii, ss)
# Run the main function
if __name__ == "__main__":
    main()