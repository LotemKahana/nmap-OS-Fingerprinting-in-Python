from os_detection.tests import *
import os_detection.send_probes as send_probes


def do_tests(responses):
    """run all tests on a dictionary of responces"""
    init_tests(responses)
    data_dict = dict()
    data_dict["SEQ"] = seq_test(responses)
    data_dict["OPS"] = ops_test(responses)
    data_dict["WIN"] = win_test(responses)
    data_dict["ECN"] = ecn_test(responses)
    data_dict["T1"] = t_1_test(responses)
    data_dict["T2"] = t_i_test(responses, 0)
    data_dict["T3"] = t_i_test(responses, 1)
    data_dict["T4"] = t_i_test(responses, 2)
    data_dict["T5"] = t_i_test(responses, 3)
    data_dict["T6"] = t_i_test(responses, 4)
    data_dict["T7"] = t_i_test(responses, 5)
    data_dict["U1"] = u1_test(responses)
    data_dict["IE"] = ie_test(responses)
    return data_dict

def get_os_info(dst_ip, open_port, closed_port):
    """get info on os, from destinaton ip, an open port and a closed one."""
    responses = send_probes.send_probes(dst_ip, open_port, closed_port)
    return do_tests(responses)
