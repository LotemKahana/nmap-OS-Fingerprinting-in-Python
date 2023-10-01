import contextlib
import threading
import queue
from scapy.all import *
from constants import * 
from random import randint

def send_receive_packet(packet, packet_num, response_queue):
    """send and recive a packet using scapy, put result in queue"""
    try:
        response = sr1(packet, timeout=PROBE_TIMEOUT, verbose=False)
        response_queue.put((packet_num, response))
    except:
        return

def send_recive_udp_packet(dst_ip, packet):
    """send a udp packet and listen for icmp response"""
    try:
        send(packet, count=1, verbose=False)
        res = sniff(filter=f"icmp and host {dst_ip}", timeout=PROBE_TIMEOUT)
        if len(res) != 0:
            return res.res[0].payload
    except:
        return

def send_packet_thread(packets, sleep_time, response_queue):
    """send multiple packets in threads"""
    threads = []
    for i, packet in enumerate(packets):
        thread = threading.Thread(target=send_receive_packet, args=(packet, i, response_queue))
        thread.start()
        threads.append(thread)
        time.sleep(sleep_time)
    return threads

def send_packets(packets, sleep_time):
    """send packets in threads and get responces"""
    response_queue = queue.Queue()
    threads = send_packet_thread(packets, sleep_time, response_queue)
    for thread in threads:
        thread.join()
    return get_threads_responces(packets, response_queue)

def get_threads_responces(packets, response_queue):
    """extract all responces from a queue"""
    results = [None] * len(packets)
    while not response_queue.empty():
        packet_num, response = response_queue.get()
        results[packet_num] = response
    return results

def build_ip(dst_ip, tos=None, df=None, id=None):
    """build an ip packet"""
    probe = IP(dst=dst_ip)
    if tos is not None:
        probe.tos = tos
    if df is not None:
        probe.flags="DF"
    if id is not None:
        probe.id=id
    probe.ttl=randint(ttl_min, ttl_max)
    return probe

def build_tcp(dest_port, flags, options, window=None):
    """build a tcp packet"""
    sport = randint(MIN_SRC_PORT, MAX_SRC_PORT)
    seq = randint(0, 2**32 - 1)
    ack = randint(0, 2**32 - 1)
    if window is None:
        return TCP(dport=dest_port, seq=seq, ack=ack, sport=sport, flags=flags, options=options)
    return TCP(dport=dest_port, seq=seq, ack=ack, sport=sport, window=window, flags=flags, options=options)