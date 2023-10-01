from random import randint
from scapy.all import *
from send_packets import build_ip, build_tcp
import send_packets
from constants import *

def send_probes(dst_ip, open_port, closed_port):
    """send and recive answers for all probes required for the nmap tests,
send to dst_ip where sg packets, ecn packet and 3 t packets are destined to the open port
the rest are to the closed port, ie are icmp packets are have no port as destination"""
    sg_packets = [
        build_ip(dst_ip, id=1)/build_tcp(dest_port=open_port, window=1, flags="S", options=[('WScale', 10), ('NOP', 0), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(dst_ip, id=1)/build_tcp(dest_port=open_port, window=63, flags="S", options=[('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)]),
        build_ip(dst_ip, id=1)/build_tcp(dest_port=open_port, window=4, flags="S", options=[('Timestamp', (0xFFFFFFFF, 0)), ('NOP', 0), ('NOP', 0), ('WScale', 5), ('NOP', 0), ('MSS', 640)]),
        build_ip(dst_ip, id=1)/build_tcp(dest_port=open_port, window=4, flags="S", options=[('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
        build_ip(dst_ip, id=1)/build_tcp(dest_port=open_port, window=16, flags="S", options=[('MSS', 536), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
        build_ip(dst_ip, id=1)/build_tcp(dest_port=open_port, window=512, flags="S", options=[('MSS', 265), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0))])
    ]

    ie_id = RandShort()
    ie_p_id = RandShort()
    ie_packets = [
        build_ip(dst_ip, tos=0, df=True, id=ie_p_id)/ICMP(type='echo-request', code=9, id=ie_id, seq=295) / Raw(load=b'\x00' * 120),
        build_ip(dst_ip, tos=4, id=ie_p_id+1)/ICMP(type='echo-request', code=0, id=ie_id+1) / Raw(load=b'\x00' * 150)
    ]

    ecn_packets = [
        build_ip(dst_ip)/TCP(sport=RandShort(), dport=open_port, flags='SEC', window=3, ack=0, seq=randint(0, 2**32 - 1),
                                options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('NOP', None)],
                                urgptr=0xF7F5, reserved=1)
    ]

    t_packets = [
        build_ip(dst_ip, df=True)/build_tcp(dest_port=open_port, window=128, flags="", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(dst_ip)/build_tcp(dest_port=open_port, window=256, flags="FSUP", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(dst_ip, df=True)/build_tcp(dest_port=open_port, window=1024, flags="A", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(dst_ip)/build_tcp(dest_port=closed_port, window=31337, flags="S", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(dst_ip, df=True)/build_tcp(dest_port=closed_port, window=32768, flags="A", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(dst_ip)/build_tcp(dest_port=closed_port, window=65535, flags="FSUP", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')])
    ]

    u_packet = build_ip(dst_ip, id=0x1042)/UDP(sport=randint(1024, 49151), dport=closed_port)/(b'\x43' * 300)

    sg_responces = (send_packets.send_packets(sg_packets, SG_PROBE_SLEEP_TIME), sg_packets)
    ie_responces = (send_packets.send_packets(ie_packets, 0), ie_packets)
    ecn_response = (send_packets.send_packets(ecn_packets, 0), ecn_packets)
    t_responses = (send_packets.send_packets(t_packets, 0), t_packets)
    u_responses = (send_packets.send_recive_udp_packet(dst_ip, u_packet), u_packet)

    return {"sg":sg_responces, "ie":ie_responces, "ecn":ecn_response, "t":t_responses, "u":u_responses}