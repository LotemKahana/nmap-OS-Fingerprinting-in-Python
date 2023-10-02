import os
from pathlib import Path

import pickle
import random
from constants import *
from scapy.all import *
import send_packets

def create_probes(dst_ip, ports):
    """create a list of basic syn probes from a givven list of ports"""
    probes = []
    for port in ports:
        probes.append(send_packets.build_ip(dst_ip)/send_packets.build_tcp(dest_port=port, flags=TCP_SYN_FLAG_CHAR, options=[]))
    return probes

def get_ports():
    """get a list of ports from a pre existing pkl file"""
    parent_dir = Path(os.path.dirname(os.path.realpath(__file__)))
    ports_path = os.path.join(str(parent_dir), PORT_LIST_FILE)
    ports_path = os.path.join(EXTERNAL_FILES_DICT, PORT_LIST_FILE)
    with open(ports_path, "rb") as p:
        ports = pickle.load(p)
    return ports

def get_oped_closed_ports(dst_ip):
    "scan target and choose a random open and random closed port"
    ports = get_ports()
    ansers = send_packets.send_packets(create_probes(dst_ip, ports), 0)
    open_ports = []
    closed_ports = []
    for ans in ansers:
        if ans is not None:
            if ans[TCP].flags == TCP_ACK_FLAG + TCP_SYN_FLAG:
                open_ports.append(ans[TCP].sport)
            if ans[TCP].flags == TCP_ACK_FLAG + TCP_RST_FLAG:
                closed_ports.append(ans[TCP].sport)
    open_port = None
    if len(open_ports):
        open_port = random.choice(open_ports)
    closed_port = None
    if len(closed_ports):
        closed_port = random.choice(closed_ports)
    return open_port, closed_port