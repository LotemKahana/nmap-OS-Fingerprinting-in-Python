def extract_syn(packets):
    results = []
    for result in packets:
        if result is not None:
            results.append(result.seq)
        else:
            results.append(None)
    return results

def extract_ip_id(packets):
    results = []
    for result in packets:
        if result is not None:
            results.append(result.id)
        else:
            results.append(None)
    return results

def extract_time(packets):
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
    results = []
    for result in packets:
        if result is not None:
            results.append(result.payload.options)
        else:
            results.append(None)
    return results

def extract_tcp_windows(packets):
    results = []
    for result in packets:
        if result is not None:
            results.append(result.window)
        else:
            results.append(None)
    return results

def extract_udp_response_ttl(packets):
    if packets[0] is None:
        return
    icmp_ttl = packets[0].ttl
    got_ttl = packets[0].payload.payload.ttl
    return (icmp_ttl, got_ttl, packets[1])

def extract_seq(probes):
    sg_syn = extract_syn(probes["sg_responces"])
    sg_id = extract_ip_id(probes["sg_responces"])
    sg_ts = extract_time(probes["sg_responces"])
    sg_windows = extract_tcp_windows(probes["sg_responces"])
    t_id = extract_ip_id(probes["t_responses"])
    t_closed_id = t_id[3:]
    ie_id = extract_ip_id(probes["ie_results"])
    return {"sg_syn":sg_syn, "sg_id":sg_id, "sg_ts":sg_ts, "sg_windows":sg_windows,
            "t_id":t_id, "t_closed_id":t_closed_id,"ie_id":ie_id}

def extract_ops(probes):
    sg_options = extract_tcp_options(probes["sg_responces"])
    return {"sg_options":sg_options}

def extract_win(probes):
    seq_window_size = extract_tcp_windows(probes["sg_responces"])
    return {"sg_windows": seq_window_size}