from random import randint
from scapy.all import *
import threading
import queue

dst_ip = '45.33.32.156'
open_port = 22
closed_port = 999

def build_ip(ttl=None, tos=None, df=None):
    probe = IP(dst=dst_ip)
    if tos is not None:
        probe.tos = tos
    if df is not None:
        probe.flags="DF"
    if ttl is not None:
        if type(ttl)==int:
            probe.ttl=ttl
        if ttl=='r':
            probe.ttl=randint(23,60)
    return probe

def send_receive_packet(packet, packet_num, response_queue):
    response = sr1(packet, timeout=4, verbose=False)
    response_queue.put((packet_num, response))

def send_recive_udp_packet(packet):
    send(packet, count=1)
    res = sniff(filter=f"icmp and host {dst_ip}", prn=handle_icmp_response, timeout=2)
    if len(res) != 0:
        return res.res[0]

def handle_icmp_response(packet):
    if packet and packet.haslayer(ICMP) and packet[ICMP].type == 3 and packet[ICMP].code == 3:
        print("Port is unreachable.")

def send_packet_thread(packets, sleep_time, response_queue):
    threads = []

    for i, packet in enumerate(packets):
        thread = threading.Thread(target=send_receive_packet, args=(packet, i, response_queue))
        thread.start()
        threads.append(thread)
        time.sleep(sleep_time)

    return threads

def send_packets(packets, sleep_time):
    response_queue = queue.Queue()
    threads = send_packet_thread(packets, sleep_time, response_queue)

    for thread in threads:
        thread.join()

    return get_threads_responces(packets, response_queue)

def get_threads_responces(packets, response_queue):
    results = [None] * len(packets)
    while not response_queue.empty():
        packet_num, response = response_queue.get()
        results[packet_num] = response
    return results

def send_probes(ttl='r'):
    sg_packets = [
        build_ip(ttl=ttl)/build_tcp(dest_port=open_port, window=1, flags="S", options=[('WScale', 10), ('NOP', 0), ('MSS', 1460), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(ttl=ttl)/build_tcp(dest_port=open_port, window=63, flags="S", options=[('MSS', 1400), ('WScale', 0), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('EOL', None)]),
        build_ip(ttl=ttl)/build_tcp(dest_port=open_port, window=4, flags="S", options=[('Timestamp', (0xFFFFFFFF, 0)), ('NOP', 0), ('NOP', 0), ('WScale', 5), ('NOP', 0), ('MSS', 640)]),
        build_ip(ttl=ttl)/build_tcp(dest_port=open_port, window=4, flags="S", options=[('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
        build_ip(ttl=ttl)/build_tcp(dest_port=open_port, window=16, flags="S", options=[('MSS', 536), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0)), ('WScale', 10), ('EOL', None)]),
        build_ip(ttl=ttl)/build_tcp(dest_port=open_port, window=512, flags="S", options=[('MSS', 265), ('SAckOK', ''), ('Timestamp', (0xFFFFFFFF, 0))])
    ]

    ie_packets = [
        build_ip(ttl=ttl)/ICMP(type='echo-request', code=9, id=RandShort()) / Raw(load=b'\x00' * 120),
        build_ip(tos=4, ttl=ttl)/ICMP(type='echo-request', code=0, id=RandShort()) / Raw(load=b'\x00' * 150)
    ]

    ecn_packets = [
        build_ip(ttl=ttl)/TCP(sport=RandShort(), dport=open_port, flags='SEC', window=3, ack=0, seq=randint(0, 2**32 - 1),
                                options=[('WScale', 10), ('NOP', None), ('MSS', 1460), ('SAckOK', ''), ('NOP', None), ('NOP', None)],
                                urgptr=0xF7F5, reserved=1)
    ]

    t_packets = [
        build_ip(ttl=ttl, df=True)/build_tcp(dest_port=open_port, window=128, flags="", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(ttl=ttl)/build_tcp(dest_port=open_port, window=256, flags="FSUP", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(ttl=ttl, df=True)/build_tcp(dest_port=open_port, window=1024, flags="A", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(ttl=ttl)/build_tcp(dest_port=closed_port, window=31337, flags="S", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(ttl=ttl, df=True)/build_tcp(dest_port=closed_port, window=32768, flags="A", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')]),
        build_ip(ttl=ttl)/build_tcp(dest_port=closed_port, window=65535, flags="FSUP", options=[('WScale', 10), ('NOP', None), ('MSS', 265), ('Timestamp', (0xFFFFFFFF, 0)), ('SAckOK', '')])
    ]

    u_packet = build_ip(ttl=ttl)/UDP(sport=randint(1024, 49151), dport=closed_port)/(b'\x43' * 300)

    sg_responces = send_packets(sg_packets, 0.1)
    ie_responces = send_packets(ie_packets, 0)
    ecn_response = send_packets(ecn_packets, 0)
    t_responses = send_packets(t_packets, 0)
    u_responses = send_recive_udp_packet(u_packet)

    return {"sg_responces":sg_responces, "ie_results":ie_responces, "ecn_response":ecn_response, "t_responses":t_responses, "u_responses":(u_responses, u_packet[IP].ttl)}

def build_tcp(dest_port, window, flags, options):
    sport = randint(1024, 49151)
    seq = randint(0, 2**32 - 1)
    ack = randint(0, 2**32 - 1)
    return TCP(dport=dest_port, seq=seq, ack=ack, sport=sport, window=window, flags=flags, options=options)