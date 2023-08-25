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

    seq = seq_test(responses)

    ops = ops_test(responses)
    win = win_test(responses)
    ecn = ecn_test(responses)
    hops = u_ttl[0] - u_ttl[1] # number of hops away (ttl)
    print(gcd, isr, sp, "\n", ti, ci, ii, ss)
# Run the main function
if __name__ == "__main__":
    main()