import math
import zlib
from statistics import stdev
import test_support
from constants import *

def gcd_test(sg_syn):
    """calculate the gcd test, the gcd from the differences in the list"""
    diffs = test_support.calculate_diffs(sg_syn)
    return math.gcd(*diffs)

def isr_test(sg_syn):
    """calculate the isr test, the rate the sequence number secound per minute"""
    seq_rates = test_support.calculate_rates(sg_syn, SG_PROBE_SLEEP_TIME)
    average_rate = sum(seq_rates) / len(seq_rates)
    if average_rate < 1:
        isr = 0
    else:
        isr = round(8 * math.log2(average_rate))
    return isr

def sp_test(sg_syn, gcd_result):
    """calculate the sp test using the gcd"""
    seq_rates = test_support.calculate_rates(sg_syn, SG_PROBE_SLEEP_TIME)
    if len(seq_rates) >= 4:
    # Divide seq_rates by GCD if GCD is greater than nine
        if gcd_result > 9:
            seq_rates = [rate / gcd_result for rate in seq_rates]

        # Calculate the standard deviation of the seq_rates array
        standard_deviation = stdev(seq_rates)

        # Calculate the TCP ISN Sequence Predictability Index (SP)
        if standard_deviation <= 1:
            sp = 0
        else:
            sp = round(8 * math.log2(standard_deviation))
    else:
        sp = None
    return sp

def ti_test(id_list):
    """calculate the ti test"""
    id_list = test_support.filter_none_probes(id_list)
    if len(id_list) < 3:
        return
    return test_support.sequence_test(id_list)

def ci_ii_test(id_list):
    """calculate the ci or ii tests"""
    id_list = test_support.filter_none_probes(id_list)
    if len(id_list) < 2:
        return
    return test_support.sequence_test(id_list)

def ss_test(icmp_ids, tcp_ids, ii, ti):
    """calculate the ss test"""
    if ii in ['RI', 'BI', 'I'] and ii == ti:
        # Calculate avg based on the TCP IDs
        avg = (tcp_ids[-1] - tcp_ids[0]) // (len(tcp_ids) - 1)
        
        if icmp_ids[0] < (tcp_ids[-1] + 3 * avg):
            return 'S'
        else:
            return 'O'
    else:
        return

def ts_test(tsval_responses, time_elapsed=0.1):
    """calculate the ts test, from the ts result in the tcp options"""
    if len(tsval_responses) == 0:
        return
    tsval_diffs = test_support.calculate_diffs(tsval_responses)# [tsval_responses[i] - tsval_responses[i-1] for i in range(1, len(tsval_responses)) if tsval_responses[i] is not None and tsval_responses[i - 1] is not None]
    time_intervals = [time_elapsed] * (len(tsval_responses) - 1)
    tsval_rates = [diff / time_interval for diff, time_interval in zip(tsval_diffs, time_intervals)]
    average_rate = sum(tsval_rates) / len(tsval_rates)
    if average_rate < 0:
        return
    if any(tsval == 0 for tsval in tsval_responses):
        ts_result = 0
    elif any(math.isclose(average_rate, r, rel_tol=1e-2) for r in [2, 100, 200]):
        ts_result = 1 if math.isclose(average_rate, 2, rel_tol=1e-2) else 7 if math.isclose(average_rate, 100, rel_tol=1e-2) else 8
    else:
        ts_result = math.ceil(math.log2(average_rate))
    
    return ts_result

def o_test(options):
    """Create a string to represent the tcp options field"""
    if options is None:
        return

    option_string = ""
    options_length = 0
    for option, argument in options:
        if option == 'EOL':
            option_string += 'L'
            options_length += 1
        elif option == 'NOP':
            option_string += 'N'
            options_length += 1
        elif option == 'MSS':
            option_string += 'M' + format(argument, 'X')
            options_length += 4
        elif option == 'WScale':
            option_string += 'W' + str(argument)
            options_length += 3
        elif option == 'Timestamp':
            tsval, tsecr = argument
            tsval_char = '1' if tsval != 0 else '0'
            tsecr_char = '1' if tsecr != 0 else '0'
            option_string += 'T' + tsval_char + tsecr_char
            options_length += 6
        elif option == 'SAckOK':
            option_string += 'S'
            options_length += 2
    if options_length % 2:
        option_string += 'L'
    return option_string

def round_up_to_nearest(value, limit=None):
    """round up to nearest power of 2 up to limit (optional)"""
    next_power_of_2 = 2 ** math.ceil(math.log2(value))
    if limit is not None:
        rounded_value = min(next_power_of_2, limit)
    return rounded_value

def r_test(packet):
    """Tests if a packet exists"""
    if packet is not None:
        return "Y"
    return "N"

def df_test(packet):
    """Test for existance of DF flag in a IP packet"""
    if packet.underlayer.flags.value & IP_DF_FLAG == IP_DF_FLAG:
        return "Y"
    return "N"

def dfi_test(probes):
    """Conduct the dfi test on testing for the DF flag on 2 packets"""
    first_flag = df_test(probes[0])
    secound_flag = df_test(probes[1])
    if first_flag == "N" and secound_flag == "N":
        return "N"
    if first_flag == "Y" and secound_flag == "Y":
        return "Y"
    if first_flag == "Y" and secound_flag == "N":
        return "S"
    return "O"

def init_t_test(udp_probes):
    """init the t_test function to use the number of hopes calculated from the icmp responce"""
    t_test(64, init=int(udp_probes[1].ttl - udp_probes[0].payload.ttl + 1))

def t_test(ttl, hops=[None], init=-1):
    "Conduct the t test, have to be initiated first to keep hops"
    if init != -1:
        hops[0] = init
        return
    if hops[0] is None:
        return
    return ttl + hops[0] - 1

def tg_test(ttl):
    """try and guess the ttl based on popular implementations"""
    return round_up_to_nearest(ttl, MAX_TTL)

def cc_test(probe):
    """conduct the cc test, looking at the probe's flags"""
    ece_flag = probe.payload.flags.value & TCP_ECE_FLAG
    cwr_flag = probe.payload.flags.value & TCP_CWR_FLAG
    if ece_flag and not cwr_flag:
        return "Y"
    if not ece_flag and not cwr_flag:
        return "N"
    if ece_flag and cwr_flag:
        return "S"
    return "O"

def q_test(probe):
    """conduct the q test looking at the urg pointer"""
    result = ""
    if probe.reserved:
        result += "R"
    if probe.payload.urgptr & TCP_URG_FLAG:
        result += "U"
    return result

def s_test(recive_probe, sent_probe):
    """conduct the s test based on seq and ack numbers"""
    seq = recive_probe.payload.seq
    ack = sent_probe.payload.ack
    if seq == 0:
        return "Z"
    if seq == ack:
        return "A"
    if seq == ack+1:
        return "A+"
    return "O"

def a_test(seq, probe):
    """conduct the a test"""
    ack = probe.payload.ack
    if ack == 0:
        return "Z"
    if seq == ack:
        return "S"
    if (seq + 1) == ack:
        return "S+"
    return "O"

def f_test(probe):
    """conduct the f flags based on the package tcp flags"""
    flags = probe.payload.flags.value
    result = ""
    if flags & TCP_ECE_FLAG:
        result += TCP_ECE_FLAG_CHAR
    if flags & TCP_URG_FLAG:
        result += TCP_URG_FLAG_CHAR
    if flags & TCP_ACK_FLAG:
        result += TCP_ACK_FLAG_CHAR
    if flags & TCP_PSH_FLAG:
        result += TCP_PSH_FLAG_CHAR
    if flags & TCP_RST_FLAG:
        result += TCP_RST_FLAG_CHAR
    if flags & TCP_SYN_FLAG:
        result += TCP_SYN_FLAG_CHAR
    if flags & TCP_FIN_FLAG:
        result += TCP_FIN_FLAG_CHAR
    return result

def w_test(probe):
    """the w test is the probe windows field"""
    return probe.window

def rd_test(probe):
    """calculate the rd test based on the tcp data"""
    if probe.flags.value & TCP_RST_FLAG:
        data = probe.payload.payload
        if not data:
            return zlib.crc32(data)
    return 0

def ipl_test(probe):
    """ipl test is the prob's length"""
    return probe.len

def un_test(probe):
    """un tests is the probes tcp reserved data"""
    return probe.payload.reserved

def ripl_test(probe):
    """calculate the ripl test by checking if the udp header has changed"""
    if probe.payload.len == BASIC_UDP_HEADER_LENGTH:
        return "G"
    return probe.payload.len

def rid_test(probe, id):
    """calculate the rid test by comparing the probe id"""
    try:
        if probe.payload.payload.id == id:
            return "G"
        return probe.payload.payload.id
    except:
        return

def ripck_test(probe, chksum):
    """calculate the ripck test, check if the checksum has changed"""
    if probe.chksum == 0:
        return "Z"
    if probe.chksum == chksum:
        return "I"
    return "G"
    
def ruck_test(probe, chksum):
    """calculate the ruck test, check if the udp checksum inside the icmp response has changed"""
    if probe.payload.payload.payload.chksum == chksum:
        return "G"
    return probe.payload.payload.payload.chksum

def rud_test(probe):
    """conduct the rud test, check if the udp responce's payload inside the icmp packet has changed"""
    payload = str(probe.payload.payload.payload.payload)
    if payload == "b" + '\'' + "C" * 300 + '\'' or len(payload) == 0:
        return "G"
    return "I"

def cd_test(ie_1, ie_2):
    """conduct the cd test"""
    if ie_1.code == 0 and ie_2.code == 0:
        return "Z"
    if ie_1.code == 9 and ie_2.code == 0:
        return "S"
    if ie_1.code == ie_2.code:
        return ie_1.code
    return "O"