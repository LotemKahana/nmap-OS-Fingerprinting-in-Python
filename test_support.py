def calculate_diffs(numbers):
    results = []
    for i in range(len(numbers) - 1):
        if all((numbers[i], numbers[i + 1])):
            results.append((numbers[i + 1] - numbers[i]) & 0xFFFFFFFF)
    return results

def calculate_rates(numbers, time):
    diffs = calculate_diffs(numbers)
    return [diff / time for diff in diffs]

def filter_none_probes(unfiltered_list):
    return [element for element in unfiltered_list if element is not None]

def sequence_test(id_list):
    if all(id_num == 0 for id_num in id_list):
        return 'Z'
    
    if len(set(id_list)) == 1:
        return hex(id_list[0])
    
    diffs = []
    for i in range(len(id_list) - 1):
        diffs.append((id_list[i+1] - id_list[i]) & 0xffff)
    
    if (max(diffs) > 20000 and len(diffs) > 2): # mistake in nmap documantation "https://github.com/nmap/nmap/blob/master/osscan2.cc#L285C10-L285C10"
        return "RD"
    
    # Check if any difference between two consecutive IDs exceeds 1,000 and is not evenly divisible by 256
    if any(abs(id_list[i] - id_list[i + 1]) > 1000 and (id_list[i] - id_list[i + 1]) % 256 != 0 for i in range(len(id_list) - 1)):
        return 'RI'

    # Check if all differences are divisible by 256 and no greater than 5,120
    if all(diff % 256 == 0 and diff <= 5120 for diff in (id_list[i] - id_list[i + 1] for i in range(len(id_list) - 1))):
        return 'BI'

    # Check if all differences are less than ten
    if all(abs(id_list[i] - id_list[i + 1]) < 10 for i in range(len(id_list) - 1)):
        return 'I'

    # If none of the previous steps identify the generation algorithm, the test is omitted from the fingerprint
    return None


def generate_option_string(options):
    if options is None:
        return

    option_string = ""
    for option, argument in options:
        if option == 'EOL':
            option_string += 'L'
        elif option == 'NOP':
            option_string += 'N'
        elif option == 'MSS':
            option_string += 'M' + format(argument, 'X')
        elif option == 'WScale':
            option_string += 'W' + str(argument)
        elif option == 'Timestamp':
            tsval, tsecr = argument
            tsval_char = '1' if tsval != 0 else '0'
            tsecr_char = '1' if tsecr != 0 else '0'
            option_string += 'T' + tsval_char + tsecr_char
        elif option == 'SAckOK':
            option_string += 'S'
        else:
            raise
    return option_string

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

def extract_gcd(probes):
    sg_syn = extract_syn(probes["sg_responces"])
    sg_id = extract_ip_id(probes["sg_responces"])
    sg_ts = extract_time(probes["sg_responces"])
    sg_options = extract_tcp_options(probes["sg_responces"])
    sg_windows = extract_tcp_windows(probes["sg_responces"])
    u_ttl = extract_udp_response_ttl(probes["u_responses"])
    t_id = extract_ip_id(probes["t_responses"])
    t_closed_id = t_id[3:]
    ie_id = extract_ip_id(probes["ie_results"])
    return {"sg_syn":sg_syn, "sg_id":sg_id, "sg_ts":sg_ts, "sg_options":sg_options,
        "sg_windows":sg_windows, "u_ttl":u_ttl, "t_id":t_id, "t_closed_id":t_closed_id,
        "ie_id":ie_id}