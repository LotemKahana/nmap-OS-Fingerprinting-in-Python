from scapy.all import *
import math
from tests import *
from send_probes import send_probes

dst_ip = '45.33.32.156'
open_port = 80
closed_port = 999



def main():
    
    responses = send_probes()

    seq = seq_test(responses)

    ops = ops_test(responses)
    win = win_test(responses)
    ecn = ecn_test(responses)
    t1 = t_1_test(responses)
    t2 = t_i_test(responses, 0)
    t3 = t_i_test(responses, 1)
    t4 = t_i_test(responses, 2)
    t5 = t_i_test(responses, 3)
    t6 = t_i_test(responses, 4)
    t7 = t_i_test(responses, 5)
    u1 = u1_test(responses)
    ie = ie_test(responses)
    pass
# Run the main function
if __name__ == "__main__":
    main()