from scapy.all import *
import sys
from pathlib import Path
base_dir = Path(__file__).parent.parent
sys.path.append(str(base_dir))

from os_detection.os_detect import do_tests

import os
import importlib.util

def load_data_module(data_directory, data_file):
    # Construct the full module name (e.g., "data_files.data1")
    module_name = f"{data_directory}.{data_file[:-3]}"  # Remove the ".py" extension

    # Use importlib to load the module
    spec = importlib.util.spec_from_file_location(module_name, os.path.join(data_directory, data_file))
    data_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(data_module)
    
    return data_module

def process_data_files(data_directory, operation):

    # Get a list of all .py files in the directory
    data_files = [file for file in os.listdir(data_directory) if file.endswith(".py")]

    # Iterate through each data file
    for data_file in data_files:
        data_module = load_data_module(data_directory, data_file)
        
        globals()["sg_raw_packets_recive"] = data_module.sg_raw_packets_recive
        globals()["sg_raw_packets_sent"] = data_module.sg_raw_packets_sent
        globals()["ie_raw_packet_recive"] = data_module.ie_raw_packet_recive
        globals()["ie_raw_packet_sent"] = data_module.ie_raw_packet_sent
        globals()["ecn_raw_packet_recive"] = data_module.ecn_raw_packet_recive
        globals()["ecn_raw_packet_sent"] = data_module.ecn_raw_packet_sent
        globals()["t_raw_packet_recive"] = data_module.t_raw_packet_recive
        globals()["t_raw_packet_sent"] = data_module.t_raw_packet_sent
        globals()["u_raw_packet_recive"] = data_module.u_raw_packet_recive
        globals()["u_raw_packet_sent"] = data_module.u_raw_packet_sent
        globals()["nmap_response"] = data_module.nmap_response
        globals()["test_name"] = data_file
        # Access and append the data from the imported module to the list
        operation()

def convert_from_raw(raw_packet_list):
    answer = []
    for raw_packet in raw_packet_list:
        if raw_packet is None:
            answer.append(None)
        else:
            answer.append(Ether(raw_packet)[IP])
    return answer

def build_response():
    response = \
    {
        "sg": (convert_from_raw(sg_raw_packets_recive), convert_from_raw(sg_raw_packets_sent)),
        "ie": (convert_from_raw(ie_raw_packet_recive), convert_from_raw(ie_raw_packet_sent)),
        "ecn": (convert_from_raw(ecn_raw_packet_recive), convert_from_raw(ecn_raw_packet_sent)),
        "t": (convert_from_raw(t_raw_packet_recive), convert_from_raw(t_raw_packet_sent)),
        "u": (convert_from_raw(u_raw_packet_recive)[0], convert_from_raw(u_raw_packet_sent)[0])
    }
    return response

def compare(nmap_response, abstract_results):
    for line_name in nmap_response.keys():
        for test_name in nmap_response[line_name].keys():
            if line_name not in abstract_results:
                print(f"could find test: {line_name}")
            elif test_name not in abstract_results[line_name]:
                print(f"missing test: {test_name} from testline: {line_name}")
            elif abstract_results[line_name][test_name] != nmap_response[line_name][test_name]:
                print(f"unmatching test answers. {test_name} from testline: {line_name}")
                print(f"got: {abstract_results[line_name][test_name]}, expected: {nmap_response[line_name][test_name]}")

def test():
    print(f"{test_name}:")
    response = build_response()
    abstract_results = do_tests(response)
    compare(nmap_response, abstract_results)
    if abstract_results == nmap_response:
        print("test succeeded")

def main():
    parent_dir = Path(os.path.dirname(os.path.realpath(__file__)))
    data_dir = os.path.join(str(parent_dir), "tests_data")
    process_data_files(data_dir, test)

if __name__ == "__main__":
    main()