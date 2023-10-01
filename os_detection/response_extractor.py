def extract_seq_num(packets):
    """extract the sequence number from each tcp packet"""
    results = []
    for result in packets:
        if result is not None:
            results.append(result.seq)
        else:
            results.append(None)
    return results

def extract_ip_id(packets):
    """extract the id from each ip packet"""
    results = []
    for result in packets:
        if result is not None:
            results.append(result.id)
        else:
            results.append(None)
    return results

def extract_time(packets):
    """get the timestamp from options of tcp packets"""
    results = []
    for result in extract_tcp_options(packets):
        if result is not None:
            for option in result:
                if option[0] == "Timestamp":
                    results.append(option[1][0])
        else:
            results.append(None)
    return results

def extract_tcp_options(packets):
    """get the optiona from a tcp packet"""
    results = []
    for result in packets:
        if result is not None:
            results.append(result.payload.options)
        else:
            results.append(None)
    return results

def extract_tcp_windows(packets):
    """extract windows size from tcp packets"""
    results = []
    for result in packets:
        if result is not None:
            results.append(result.window)
        else:
            results.append(None)
    return results

def extract_udp_response_ttl(packets):
    """extract ttl from a udp packet inside an icmp error packet"""
    if packets[0] is None:
        return
    icmp_ttl = packets[0].ttl
    got_ttl = packets[0].payload.payload.ttl
    return (icmp_ttl, got_ttl, packets[1])

def extract_seq(probes):
    """extract all data nessesary for seq tests"""
    probes = probes.copy()
    data = []
    for i, probe in enumerate(probes["sg"][0]):
        if probe is not None:
            data.append(probe)
        else:
            del probes["sg"][0][i]
    sg_seq = extract_seq_num(probes["sg"][0])
    sg_id = extract_ip_id(probes["sg"][0])
    sg_ts = extract_time(probes["sg"][0])
    sg_windows = extract_tcp_windows(probes["sg"][0])
    t_id = extract_ip_id(probes["t"][0])
    t_closed_id = t_id[3:]
    ie_id = extract_ip_id(probes["ie"][0])
    return {"sg_seq":sg_seq, "sg_id":sg_id, "sg_ts":sg_ts, "sg_windows":sg_windows,
            "t_id":t_id, "t_closed_id":t_closed_id,"ie_id":ie_id}

def extract_ops(probes):
    """extract all data nessesary for ops tests"""
    sg_options = extract_tcp_options(probes["sg"][0])
    return {"sg_options":sg_options}

def extract_win(probes):
    """extract all data nessesary for win tests"""
    seq_window_size = extract_tcp_windows(probes)
    return {"sg_windows": seq_window_size}