from scapy.all import *
import math
import statistics
from tests import *
from send_probes import send_probes

dst_ip = '45.33.32.156'
open_port = 22
closed_port = 999




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


    seq = seq_test(responses)

    ops = ops_test([generate_option_string(option) for option in sg_options])
    hops = u_ttl[0] - u_ttl[1] # number of hops away (ttl)
    print(gcd, isr, sp, "\n", ti, ci, ii, ss)
# Run the main function
if __name__ == "__main__":
    main()