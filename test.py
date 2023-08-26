from scapy.all import *
import math
from tests import *
from send_probes import send_probes

dst_ip = '45.33.32.156'
open_port = 22
closed_port = 999



def main():
    
    responses = send_probes()

    seq = seq_test(responses)

    ops = ops_test(responses)
    win = win_test(responses)
    ecn = ecn_test(responses)
    pass
    pass
# Run the main function
if __name__ == "__main__":
    main()